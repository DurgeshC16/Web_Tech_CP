<?php
// scripts/render_boot.php
// ─────────────────────────────────────────────────────────────────────
// Container start-up tasks (run by docker/entrypoint.sh before Apache).
// Written for hosts without shell access and with an ephemeral disk
// (Render free plan, docs/13_DEPLOY_RENDER.md), harmless everywhere else:
//
//   a) schema    empty database (no `users` table) → import
//                database/schema.sql (CREATE DATABASE/USE skipped);
//                otherwise only the cheap, repeatable CREATE TABLE IF NOT
//                EXISTS migrations (017 guest quota, 018 file store)
//   b) admin     CV_SUPER_ADMIN_EMAIL + CV_SUPER_ADMIN_PASSWORD set →
//                create/update the super admin exactly like
//                scripts/set_super_admin.php (password never printed)
//   c) files     CV_FILE_STORE=db → FileStore::restoreAll()
//
// Safe on every start. Never fails the container: if the database stays
// unreachable after a few retries it logs and exits 0 so Apache still
// starts (the health check then reports "db unavailable").
//
// Env: CV_BOOT_DB_RETRIES (default 5), CV_BOOT_DB_RETRY_DELAY (seconds,
//      default 3, grows linearly), CV_BOOT_SKIP_SCHEMA=1 (skip step a).
// ─────────────────────────────────────────────────────────────────────

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("CLI only.\n");
}

require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/services/SchemaInstaller.php';
require_once __DIR__ . '/../src/services/SuperAdminService.php';
require_once __DIR__ . '/../src/services/FileStore.php';

function boot_log(string $msg): void
{
    fwrite(STDERR, '[render_boot] ' . $msg . "\n");
}

/** Connect with retries; null when the server stays unreachable. */
function boot_connect(): ?PDO
{
    $tries = max(1, (int)(getenv('CV_BOOT_DB_RETRIES') ?: 5));
    $delay = max(0, (int)(getenv('CV_BOOT_DB_RETRY_DELAY') !== false && getenv('CV_BOOT_DB_RETRY_DELAY') !== '' ? getenv('CV_BOOT_DB_RETRY_DELAY') : 3));
    for ($i = 1; $i <= $tries; $i++) {
        try {
            return Database::connect(null, [PDO::ATTR_TIMEOUT => 10]);
        } catch (Throwable $e) {
            boot_log("database not reachable (attempt $i/$tries): " . preg_replace('/\s+/', ' ', $e->getMessage()));
            if ($i < $tries && $delay > 0) {
                sleep($delay * $i);
            }
        }
    }
    return null;
}

$started = microtime(true);
try {
    $tls = Database::sslCaFile() !== null ? ' (TLS)' : '';
} catch (Throwable $e) {
    $tls = ' (TLS CA file error: ' . $e->getMessage() . ')';
}
$target = DB_HOST . (defined('DB_PORT') && DB_PORT ? ':' . DB_PORT : '') . '/' . DB_NAME . $tls;
boot_log('starting; database ' . $target . '; file store ' . (FileStore::enabled() ? 'db' : 'off'));

$pdo = boot_connect();
if ($pdo === null) {
    boot_log('WARNING: giving up on the database for now; starting the web server anyway. '
        . 'Schema, super-admin and file restore steps were skipped — they run again on the next start.');
    exit(0);
}

// ── a) schema ───────────────────────────────────────────────────────
$schemaOk = true;
if ((getenv('CV_BOOT_SKIP_SCHEMA') ?: '0') !== '1') {
    try {
        $state = SchemaInstaller::state($pdo);
        if ($state === 'fresh' || $state === 'incomplete') {
            boot_log($state === 'fresh'
                ? 'empty database: importing database/schema.sql …'
                : 'incomplete schema from an interrupted import: resuming …');
            $n = SchemaInstaller::importSchema($pdo);
            boot_log("schema imported ($n statements).");
        }
        $applied = SchemaInstaller::applySafeMigrations($pdo);
        boot_log('ensured tables of ' . implode(', ', $applied) . '.');
        $missing = array_diff(SchemaInstaller::schemaTables(),
            SchemaInstaller::existingTables($pdo, SchemaInstaller::schemaTables()));
        if ($missing) {
            boot_log('WARNING: tables missing (run the migrations in database/migrations/ by hand): ' . implode(', ', $missing));
        }
    } catch (Throwable $e) {
        $schemaOk = false;
        boot_log('ERROR: schema step failed: ' . preg_replace('/\s+/', ' ', $e->getMessage()));
    }
}

// ── b) super admin from the environment ─────────────────────────────
$adminEmail = trim((string)(getenv('CV_SUPER_ADMIN_EMAIL') ?: ''));
$adminPass = (string)(getenv('CV_SUPER_ADMIN_PASSWORD') ?: '');
if ($adminEmail !== '' && $adminPass !== '') {
    if (!$schemaOk) {
        boot_log('super admin: skipped (schema step failed).');
    } else {
        try {
            $r = SuperAdminService::setCredentials($pdo, $adminEmail, $adminPass, true);
            boot_log('super admin ' . $adminEmail . ': ' . $r . '.');
        } catch (Throwable $e) {
            // Messages never contain the password.
            boot_log('ERROR: super admin not set from CV_SUPER_ADMIN_EMAIL/CV_SUPER_ADMIN_PASSWORD: ' . $e->getMessage());
        }
    }
} elseif ($adminEmail !== '' || $adminPass !== '') {
    boot_log('super admin: set BOTH CV_SUPER_ADMIN_EMAIL and CV_SUPER_ADMIN_PASSWORD (one is empty); nothing changed.');
} elseif ($schemaOk) {
    try {
        $locked = $pdo->query("SELECT COUNT(*) FROM users WHERE role = 'super_admin' AND password_hash LIKE '!locked%'")->fetchColumn();
        if ((int)$locked > 0) {
            boot_log('note: the super admin still has no password. Set CV_SUPER_ADMIN_EMAIL and CV_SUPER_ADMIN_PASSWORD '
                . '(or run php scripts/set_super_admin.php where a shell is available).');
        }
    } catch (Throwable $e) {
        // informational only
    }
}
unset($adminPass);

// ── c) restore durable files ────────────────────────────────────────
if (FileStore::enabled()) {
    try {
        FileStore::setConnection($pdo);
        $s = FileStore::restoreAll();
        boot_log(sprintf('file store: %d restored, %d already present, %d failed.', $s['restored'], $s['skipped'], $s['failed']));
    } catch (Throwable $e) {
        boot_log('ERROR: file restore failed: ' . preg_replace('/\s+/', ' ', $e->getMessage()));
    } finally {
        FileStore::setConnection(null);
    }
}

boot_log(sprintf('done in %.1fs.', microtime(true) - $started));
exit(0);
