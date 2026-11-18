<?php
// public/health.php — liveness/readiness probe for the hosting platform
// (Render healthCheckPath) and uptime monitors (UptimeRobot).
//
// Deliberately minimal: no session, no helpers.php, no guest quota, no
// audit/verification log row, no error_log line per hit. It runs
// "SELECT 1" (which also keeps an idle external database awake) and
// answers 200 "ok" or 503 "db unavailable" — nothing else is revealed.

require_once __DIR__ . '/../src/config/Database.php';

header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

$ok = false;
$level = error_reporting(0); // a failing probe must not write a log line per hit
try {
    // Own short-timeout connection: a hung database must turn into a quick
    // 503, not a probe that times out.
    $ok = (string)Database::connect(null, [PDO::ATTR_TIMEOUT => 5])->query('SELECT 1')->fetchColumn() === '1';
} catch (Throwable $e) {
    $ok = false;
}
error_reporting($level);

http_response_code($ok ? 200 : 503);
echo $ok ? "ok\n" : "db unavailable\n";
