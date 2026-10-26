<?php
// tests/test_timezone.php
// Regression test for the PHP/MySQL timezone alignment fix.
//
// Several queries compare MySQL NOW()/CURRENT_TIMESTAMP against PHP
// time() (OTP resend cooldown, login-lockout remaining, remember-me
// expiry). If MySQL's session zone differs from PHP's date.timezone the
// comparison skews by the offset. Both Database.php and tests/bootstrap.php
// run "SET time_zone = <PHP offset>" on connect; this asserts the effect.

require_once __DIR__ . '/bootstrap.php';

echo "== DB timezone alignment ==\n";

// The meaningful check: MySQL renders its current wall clock as a string
// in the session zone; PHP then parses that string in its own zone. When
// the zones agree, strtotime(mysql NOW()) ~= time(). When they differ the
// deltas are hours apart. (UNIX_TIMESTAMP(NOW()) always equals the true
// epoch regardless of zone, so it cannot detect the mismatch.)
function tz_delta_seconds($pdo) {
    $mysqlNow = $pdo->query('SELECT NOW()')->fetchColumn();
    return strtotime((string)$mysqlNow) - time();
}

// 1. Test database connection (mirrors Database.php).
$db = test_db();
$delta = tz_delta_seconds($db);
t_check('test_db: strtotime(MySQL NOW()) matches PHP time() (<=2s)', abs($delta) <= 2);

// 2. The application's own Database singleton, if the dev DB is reachable.
require_once __DIR__ . '/../src/config/Database.php';
try {
    $app = Database::getInstance();
    $deltaApp = tz_delta_seconds($app);
    t_check('Database.php: strtotime(MySQL NOW()) matches PHP time() (<=2s)', abs($deltaApp) <= 2);
} catch (\Throwable $e) {
    // Dev DB not configured in this environment: the mirror test above
    // still guards the fix; report the skip explicitly.
    echo "SKIP Database.php check (dev DB unavailable): " . $e->getMessage() . "\n";
}

// 3. Control: an un-aliased connection reflects the raw server zone, so
//    when PHP and MySQL disagree its delta is large. Informational only.
$host = getenv('CV_DB_HOST') ?: 'localhost';
$user = getenv('CV_DB_USER') ?: 'root';
$pass = getenv('CV_DB_PASS') ?: '';
$plain = new PDO("mysql:host=$host", $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
echo 'info: raw (unset-session) delta = ' . tz_delta_seconds($plain) . "s\n";

exit(t_summary('test_timezone') ? 0 : 1);
