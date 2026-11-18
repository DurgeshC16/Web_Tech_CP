<?php
// src/services/SchemaInstaller.php
// ─────────────────────────────────────────────────────────────────────
// Import database/schema.sql into an EXISTING database over PDO, for hosts
// where nobody can run the mysql client (Render free plan; used by
// scripts/render_boot.php at container start).
//
//  - CREATE DATABASE / USE statements are skipped: the managed database
//    (e.g. Aiven's "defaultdb") already exists and is selected by the DSN.
//  - Statements are split by a small tokenizer that respects quotes,
//    backticks and comments, not by a naive explode(';').
//  - The import is idempotent so an interrupted first boot can resume:
//    CREATE TABLE gets IF NOT EXISTS, a duplicate index (1061) or a
//    duplicate seed row (1062) is ignored, and the seeded super_admin row is
//    not inserted again when one exists.
//  - Only CREATE TABLE IF NOT EXISTS migrations are applied automatically
//    (cheap, safe, repeatable). ALTER-based migrations stay manual.
// ─────────────────────────────────────────────────────────────────────

class SchemaInstaller
{
    /** Migrations that only contain CREATE TABLE IF NOT EXISTS. */
    public const SAFE_MIGRATIONS = ['017_guest_verify_quota.sql', '018_file_store.sql'];

    public static function schemaFile(): string
    {
        return __DIR__ . '/../../database/schema.sql';
    }

    /**
     * Split SQL text into statements. Comments (-- , #, /* *\/) are removed;
     * semicolons inside '…', "…" and `…` do not split.
     *
     * @return string[]
     */
    public static function splitStatements(string $sql): array
    {
        $out = [];
        $cur = '';
        $len = strlen($sql);
        $i = 0;
        while ($i < $len) {
            $c = $sql[$i];
            $n = $i + 1 < $len ? $sql[$i + 1] : '';
            if ($c === "'" || $c === '"' || $c === '`') {
                $j = $i + 1;
                while ($j < $len) {
                    if ($sql[$j] === '\\' && $c !== '`') {
                        $j += 2;
                        continue;
                    }
                    if ($sql[$j] === $c) {
                        if ($j + 1 < $len && $sql[$j + 1] === $c) { // doubled quote
                            $j += 2;
                            continue;
                        }
                        break;
                    }
                    $j++;
                }
                $cur .= substr($sql, $i, $j - $i + 1);
                $i = $j + 1;
                continue;
            }
            if (($c === '-' && $n === '-' && ($i + 2 >= $len || ctype_space($sql[$i + 2]))) || $c === '#') {
                $j = strpos($sql, "\n", $i);
                $i = $j === false ? $len : $j;
                continue;
            }
            if ($c === '/' && $n === '*') {
                $j = strpos($sql, '*/', $i + 2);
                $i = $j === false ? $len : $j + 2;
                $cur .= ' ';
                continue;
            }
            if ($c === ';') {
                if (trim($cur) !== '') {
                    $out[] = trim($cur);
                }
                $cur = '';
                $i++;
                continue;
            }
            $cur .= $c;
            $i++;
        }
        if (trim($cur) !== '') {
            $out[] = trim($cur);
        }
        return $out;
    }

    /** Table names created by schema.sql, in file order. */
    public static function schemaTables(?string $sql = null): array
    {
        $sql = implode(";\n", self::splitStatements($sql ?? (string)file_get_contents(self::schemaFile()))); // comments stripped
        preg_match_all('/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([A-Za-z0-9_]+)`?/i', $sql, $m);
        return array_values(array_unique($m[1]));
    }

    /** Tables (of $names) that exist in the connection's current database. */
    public static function existingTables(PDO $pdo, array $names): array
    {
        $rows = $pdo->query('SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE()')->fetchAll(PDO::FETCH_COLUMN);
        $have = array_map('strtolower', $rows);
        return array_values(array_filter($names, fn($t) => in_array(strtolower($t), $have, true)));
    }

    /**
     * 'fresh'      no users table → full import
     * 'incomplete' schema tables missing but at most one user → an
     *              interrupted first import → resume (idempotent)
     * 'existing'   a real installation → only SAFE_MIGRATIONS
     */
    public static function state(PDO $pdo): string
    {
        $tables = self::schemaTables();
        $have = self::existingTables($pdo, $tables);
        if (!in_array('users', array_map('strtolower', $have), true)) {
            return 'fresh';
        }
        if (count($have) < count($tables)) {
            $users = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
            if ($users <= 1) {
                return 'incomplete';
            }
        }
        return 'existing';
    }

    /**
     * Import schema.sql into the connection's current database.
     *
     * @return int number of statements executed
     * @throws PDOException on the first real error
     */
    public static function importSchema(PDO $pdo, ?string $file = null): int
    {
        $sql = (string)file_get_contents($file ?? self::schemaFile());
        // Match the collation schema.sql's CREATE DATABASE line asks for
        // (MySQL 8 defaults to utf8mb4_0900_ai_ci). Best effort.
        try {
            $pdo->exec('ALTER DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
        } catch (PDOException $e) {
            // Not fatal: every table declares its collation explicitly.
        }
        $count = 0;
        foreach (self::splitStatements($sql) as $stmt) {
            if (preg_match('/^(CREATE\s+(DATABASE|SCHEMA)|USE)\b/i', $stmt)) {
                continue;
            }
            $stmt = preg_replace('/^CREATE\s+TABLE\s+(?!IF\s+NOT\s+EXISTS)/i', 'CREATE TABLE IF NOT EXISTS ', $stmt);
            if (preg_match('/^INSERT\s+INTO\s+`?users`?\b/i', $stmt) && stripos($stmt, 'super_admin') !== false) {
                $has = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role = 'super_admin'")->fetchColumn();
                if ($has > 0) {
                    continue;
                }
            }
            try {
                $pdo->exec($stmt);
                $count++;
            } catch (PDOException $e) {
                $code = (int)($e->errorInfo[1] ?? 0);
                if ($code === 1061 || $code === 1062) { // duplicate index / seed row
                    continue;
                }
                throw $e;
            }
        }
        return $count;
    }

    /**
     * Apply the CREATE TABLE IF NOT EXISTS migrations (safe to repeat).
     *
     * @return string[] migration files applied
     */
    public static function applySafeMigrations(PDO $pdo): array
    {
        $done = [];
        foreach (self::SAFE_MIGRATIONS as $name) {
            $path = __DIR__ . '/../../database/migrations/' . $name;
            if (!is_file($path)) {
                continue;
            }
            foreach (self::splitStatements((string)file_get_contents($path)) as $stmt) {
                if (!preg_match('/^CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\b/i', $stmt)) {
                    continue; // never run anything but idempotent CREATEs here
                }
                $pdo->exec($stmt);
            }
            $done[] = $name;
        }
        return $done;
    }
}
