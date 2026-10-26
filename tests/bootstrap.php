<?php
// tests/bootstrap.php
// Shared harness for the plain-PHP CLI suite (no framework).
// Each test file requires this, runs its cases with t_check(), and ends
// with t_summary(). Every file is runnable standalone AND via run_all.php.

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die('Test scripts must be run from the command line.');
}

// openssl_pkey_new() needs an openssl.cnf visible at PROCESS level on
// some Windows builds (a runtime putenv() is silently ignored and key
// generation fails). Relaunch once with a real variable when needed.
if (PHP_OS_FAMILY === 'Windows' && !getenv('OPENSSL_CONF')) {
    foreach (['C:\\xampp\\apache\\conf\\openssl.cnf', 'C:\\xampp\\php\\extras\\ssl\\openssl.cnf'] as $cnf) {
        if (is_file($cnf)) {
            $self = $_SERVER['argv'][0] ?? null;
            if ($self && realpath($self) && !getenv('CV_OSSL_RELAUNCHED')) {
                putenv('CV_OSSL_RELAUNCHED=1');
                $cmd = 'cmd /c "set OPENSSL_CONF=' . $cnf . ' && set CV_OSSL_RELAUNCHED=1 && '
                    . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(realpath($self));
                foreach (array_slice($_SERVER['argv'], 1) as $a) {
                    $cmd .= ' ' . escapeshellarg($a);
                }
                $cmd .= '"';
                passthru($cmd, $code);
                exit($code);
            }
            putenv('OPENSSL_CONF=' . $cnf); // best effort for the current process
            break;
        }
    }
}

$GLOBALS['__t_pass'] = 0;
$GLOBALS['__t_fail'] = 0;

function t_check($label, $cond) {
    if ($cond) {
        $GLOBALS['__t_pass']++;
        echo "PASS $label\n";
    } else {
        $GLOBALS['__t_fail']++;
        echo "FAIL $label\n";
    }
}

function t_summary($name) {
    $p = $GLOBALS['__t_pass'];
    $f = $GLOBALS['__t_fail'];
    echo "--- $name: $p passed, $f failed ---\n";
    return $f === 0;
}

/**
 * PDO handle to the isolated test database (default 'certivault_test',
 * override with CV_TEST_DB). Creates the database and imports
 * database/schema.sql on first use.
 */
function test_db() {
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    $host = getenv('CV_DB_HOST') ?: 'localhost';
    $user = getenv('CV_DB_USER') ?: 'root';
    $pass = getenv('CV_DB_PASS') ?: '';
    $db   = getenv('CV_TEST_DB') ?: 'certivault_test';

    $admin = new PDO("mysql:host=$host", $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $admin->exec('CREATE DATABASE IF NOT EXISTS `' . str_replace('`', '', $db) . '`');

    $pdo = new PDO(
        "mysql:host=$host;dbname=$db;charset=utf8mb4",
        $user, $pass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]
    );

    // Mirror Database.php: align the MySQL session zone with PHP so tests
    // see the same NOW()/time() relationship the application relies on.
    try {
        $pdo->exec("SET time_zone = '" . date('P') . "'");
    } catch (\PDOException $e) {
        // Non-fatal, as in Database.php.
    }

    // Import the canonical schema when the database is empty.
    $n = (int)$pdo->query("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = " . $pdo->quote($db))->fetchColumn();
    if ($n === 0) {
        $sql = file_get_contents(__DIR__ . '/../database/schema.sql');
        $lines = array_filter(
            explode("\n", $sql),
            fn($l) => !preg_match('/^\s*(--|USE\s)/i', $l)
        );
        foreach (explode(';', implode("\n", $lines)) as $stmt) {
            $stmt = trim($stmt);
            if ($stmt !== '') {
                $pdo->exec($stmt);
            }
        }
    }

    // Keep older isolated test databases compatible with migration 012 and
    // seed a v1 key record for test-created institutions. Production installs
    // receive these rows through the migration, not through this test helper.
    $pdo->exec("CREATE TABLE IF NOT EXISTS institution_keys (
        institution_id INT NOT NULL, key_id INT NOT NULL, public_key TEXT NOT NULL,
        encrypted_private_key TEXT NOT NULL, status ENUM('active','retired') NOT NULL DEFAULT 'active',
        valid_from DATETIME NOT NULL, valid_to DATETIME NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(institution_id,key_id), INDEX idx_institution_keys_status(institution_id,status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $hasKeyId = (int)$pdo->query("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='key_id'")->fetchColumn();
    if (!$hasKeyId) $pdo->exec('ALTER TABLE certificates ADD COLUMN key_id INT NOT NULL DEFAULT 1 AFTER institution_id');
    $hasOldPub = (int)$pdo->query("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='institutions' AND COLUMN_NAME='public_key'")->fetchColumn();
    $hasOldPriv = (int)$pdo->query("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='institutions' AND COLUMN_NAME='encrypted_private_key'")->fetchColumn();
    if ($hasOldPub && $hasOldPriv) {
        $pdo->exec("INSERT IGNORE INTO institution_keys (institution_id,key_id,public_key,encrypted_private_key,status,valid_from,valid_to)
            SELECT i.id,1,COALESCE(i.public_key,''),COALESCE(i.encrypted_private_key,''),IF(i.status='approved','active','retired'),NOW(),IF(i.status='approved',NULL,NOW()) FROM institutions i");
    }
    $pdo->exec("INSERT IGNORE INTO institution_keys (institution_id,key_id,public_key,encrypted_private_key,status,valid_from,valid_to)
        SELECT i.id,1,'','',IF(i.status='approved','active','retired'),NOW(),IF(i.status='approved',NULL,NOW()) FROM institutions i");
    $pdo->exec("CREATE TABLE IF NOT EXISTS tlog_entries (
        seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, certificate_id VARCHAR(64) NOT NULL,
        event_type ENUM('ISSUE','REVOKE','SUPERSEDE') NOT NULL, leaf_hash CHAR(64) NOT NULL, prev_root CHAR(64) NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, INDEX idx_tlog_certificate(certificate_id,seq)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $pdo->exec("CREATE TABLE IF NOT EXISTS tlog_checkpoints (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, tree_size BIGINT UNSIGNED NOT NULL UNIQUE,
        last_seq BIGINT UNSIGNED NOT NULL DEFAULT 0,
        root_hash CHAR(64) NOT NULL, signature TEXT NOT NULL, public_key_fingerprint CHAR(95) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $hasTlogLastSeq=(int)$pdo->query("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tlog_checkpoints' AND COLUMN_NAME='last_seq'")->fetchColumn();
    if (!$hasTlogLastSeq) $pdo->exec('ALTER TABLE tlog_checkpoints ADD COLUMN last_seq BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER tree_size');
    return $pdo;
}

/** Seed a version-1 key row for fixture-created institutions. */
function test_insert_institution_key($db, int $institutionId, string $publicKey, string $encryptedPrivateKey, string $status='active'): void {
    $stmt=$db->prepare('INSERT INTO institution_keys (institution_id,key_id,public_key,encrypted_private_key,status,valid_from) VALUES (:iid,1,:pub,:priv,:status,NOW()) ON DUPLICATE KEY UPDATE public_key=VALUES(public_key),encrypted_private_key=VALUES(encrypted_private_key),status=VALUES(status)');
    $stmt->execute(['iid'=>$institutionId,'pub'=>$publicKey,'priv'=>$encryptedPrivateKey,'status'=>$status]);
}
