<?php
// src/services/FileStore.php
// ─────────────────────────────────────────────────────────────────────
// Durable copies of runtime files in the database, for hosts whose
// filesystem is wiped on every restart/redeploy (Render free plan).
//
// Enabled only with CV_FILE_STORE=db (constant FILE_STORE). Otherwise
// every method returns immediately — no DB access, no filesystem access —
// so local XAMPP, docker-compose and the test suite are unaffected.
//
//   persist($abs)   after a file that must survive was written
//                   (certificate uploads + generated PDFs, QR PNGs, the
//                   key-pin file, transparency checkpoint files)
//   forget($abs)    after such a file was deleted
//   restoreAll()    at container start (scripts/render_boot.php): writes
//                   every stored row back to disk, skipping files that
//                   already exist with the same SHA-256
//
// Rows are keyed by the path RELATIVE to the repository root, so the copy
// is independent of where the app is mounted. Files outside the root are
// refused (logged). persist() uses the application's shared connection by
// default: inside an open transaction (issuance, supersede) the row is
// committed or rolled back together with the certificate row.
//
// Security note: with this mode the key-pin file and the transparency
// signing key live in the same database they are meant to be independent
// of. See docs/13_DEPLOY_RENDER.md ("Limitations").
// ─────────────────────────────────────────────────────────────────────

// Database.php is loaded lazily (only when the store is enabled), so
// including this class never pulls config.php into a caller that has not
// loaded it yet.

class FileStore
{
    private static ?PDO $pdo = null;
    private static ?bool $enabledOverride = null;

    /** True when CV_FILE_STORE=db (or a test override says so). */
    public static function enabled(): bool
    {
        if (self::$enabledOverride !== null) {
            return self::$enabledOverride;
        }
        return defined('FILE_STORE') && FILE_STORE === 'db';
    }

    /** Test/boot hook: force the mode (null = follow configuration). */
    public static function setEnabled(?bool $enabled): void
    {
        self::$enabledOverride = $enabled;
    }

    /** Test/boot hook: use this connection (null = Database::getInstance()). */
    public static function setConnection(?PDO $pdo): void
    {
        self::$pdo = $pdo;
    }

    private static function db(): PDO
    {
        if (self::$pdo !== null) {
            return self::$pdo;
        }
        require_once __DIR__ . '/../config/Database.php';
        return Database::getInstance();
    }

    /** Absolute repository root (no trailing slash, forward slashes). */
    public static function root(): string
    {
        $r = realpath(__DIR__ . '/../..');
        return rtrim(str_replace('\\', '/', $r !== false ? $r : __DIR__ . '/../..'), '/');
    }

    /**
     * Repository-relative key for $absPath, or null when the path lies
     * outside the repository root or is not a safe relative path.
     */
    public static function relativePath(string $absPath): ?string
    {
        $real = realpath($absPath);
        if ($real === false) {
            // Deleted files: resolve the directory instead.
            $dir = realpath(dirname($absPath));
            if ($dir === false) {
                return null;
            }
            $real = $dir . '/' . basename($absPath);
        }
        $real = str_replace('\\', '/', $real);
        $root = self::root() . '/';
        $cmpReal = PHP_OS_FAMILY === 'Windows' ? strtolower($real) : $real;
        $cmpRoot = PHP_OS_FAMILY === 'Windows' ? strtolower($root) : $root;
        if (strncmp($cmpReal, $cmpRoot, strlen($cmpRoot)) !== 0) {
            return null;
        }
        $rel = substr($real, strlen($root));
        return self::safeRelative($rel) ? $rel : null;
    }

    private static function safeRelative(string $rel): bool
    {
        return $rel !== '' && strlen($rel) <= 255
            && preg_match('#^[A-Za-z0-9._@/-]+$#', $rel)
            && !preg_match('#(^|/)\.\.?(/|$)#', $rel)
            && $rel[0] !== '/';
    }

    /**
     * Store the current content of $absPath. Returns true when stored (or
     * unchanged), false when disabled or the path is not storable.
     *
     * @throws RuntimeException when the database write fails (so callers
     *         inside a transaction roll back instead of losing the file)
     */
    public static function persist(string $absPath): bool
    {
        if (!self::enabled()) {
            return false;
        }
        $rel = self::relativePath($absPath);
        if ($rel === null) {
            error_log('[CertiVault] FileStore: not persisting a path outside the repository: ' . basename($absPath));
            return false;
        }
        $content = @file_get_contents($absPath);
        if ($content === false) {
            throw new RuntimeException('The file could not be read for durable storage.');
        }
        $sha = hash('sha256', $content);
        try {
            $db = self::db();
            $stmt = $db->prepare('SELECT sha256 FROM stored_files WHERE path = :p');
            $stmt->execute(['p' => $rel]);
            $existing = $stmt->fetchColumn();
            if ($existing !== false && hash_equals((string)$existing, $sha)) {
                return true;
            }
            $stmt = $db->prepare('REPLACE INTO stored_files (path, content, sha256, size, updated_at) VALUES (:p, :c, :s, :n, CURRENT_TIMESTAMP)');
            $stmt->bindValue(':p', $rel);
            $stmt->bindValue(':c', $content, PDO::PARAM_LOB);
            $stmt->bindValue(':s', $sha);
            $stmt->bindValue(':n', strlen($content), PDO::PARAM_INT);
            $stmt->execute();
        } catch (PDOException $e) {
            error_log('[CertiVault] FileStore: could not persist ' . $rel . ': ' . $e->getMessage());
            throw new RuntimeException('The file could not be saved to durable storage.');
        }
        return true;
    }

    /** persist() that never throws (logs instead). */
    public static function persistQuietly(string $absPath): bool
    {
        try {
            return self::persist($absPath);
        } catch (Throwable $e) {
            error_log('[CertiVault] FileStore: ' . $e->getMessage() . ' (' . basename($absPath) . ')');
            return false;
        }
    }

    /** Drop the stored copy of $absPath (after the file was deleted). Never throws. */
    public static function forget(string $absPath): bool
    {
        if (!self::enabled()) {
            return false;
        }
        $rel = self::relativePath($absPath);
        if ($rel === null) {
            return false;
        }
        try {
            self::db()->prepare('DELETE FROM stored_files WHERE path = :p')->execute(['p' => $rel]);
            return true;
        } catch (Throwable $e) {
            error_log('[CertiVault] FileStore: could not forget ' . $rel . ': ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Write every stored file back to disk. Files that already exist with
     * the same SHA-256 are skipped. Content is fetched row by row (low
     * memory) and written atomically (temp file + rename).
     *
     * @return array{restored:int, skipped:int, failed:int}
     * @throws PDOException when the table cannot be read
     */
    public static function restoreAll(): array
    {
        $stats = ['restored' => 0, 'skipped' => 0, 'failed' => 0];
        if (!self::enabled()) {
            return $stats;
        }
        $db = self::db();
        $rows = $db->query('SELECT path, sha256 FROM stored_files ORDER BY path')->fetchAll(PDO::FETCH_ASSOC);
        $root = self::root();
        $get = $db->prepare('SELECT content FROM stored_files WHERE path = :p');
        foreach ($rows as $row) {
            $rel = (string)$row['path'];
            if (!self::safeRelative($rel)) {
                error_log('[CertiVault] FileStore: refusing to restore unsafe path ' . $rel);
                $stats['failed']++;
                continue;
            }
            $abs = $root . '/' . $rel;
            if (is_file($abs) && hash_equals((string)$row['sha256'], (string)hash_file('sha256', $abs))) {
                $stats['skipped']++;
                continue;
            }
            $get->execute(['p' => $rel]);
            $content = $get->fetchColumn();
            $get->closeCursor();
            if (is_resource($content)) {
                $content = stream_get_contents($content);
            }
            if (!is_string($content) || !hash_equals((string)$row['sha256'], hash('sha256', $content))) {
                error_log('[CertiVault] FileStore: stored copy of ' . $rel . ' is missing or fails its hash check; not restored.');
                $stats['failed']++;
                continue;
            }
            $private = strncmp($rel, 'public/', 7) !== 0;
            $dir = dirname($abs);
            if (!is_dir($dir) && !@mkdir($dir, $private ? 0750 : 0755, true) && !is_dir($dir)) {
                $stats['failed']++;
                continue;
            }
            $tmp = $dir . '/.restore.' . bin2hex(random_bytes(6)) . '.tmp';
            $written = @file_put_contents($tmp, $content) !== false;
            if ($written && !@rename($tmp, $abs)) {
                // Windows cannot rename over an existing file.
                $written = (!is_file($abs) || @unlink($abs)) && @rename($tmp, $abs);
            }
            if (!$written) {
                @unlink($tmp);
                error_log('[CertiVault] FileStore: could not write ' . $rel);
                $stats['failed']++;
                continue;
            }
            @chmod($abs, $private ? 0640 : 0644);
            $stats['restored']++;
        }
        return $stats;
    }
}
