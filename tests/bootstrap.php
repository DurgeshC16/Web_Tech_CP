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
    return $pdo;
}
