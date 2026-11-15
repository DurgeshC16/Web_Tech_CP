<?php
// tests/support/ui_db.php — tiny DB helper for tests/test_verify_ui.mjs.
//   php tests/support/ui_db.php reset-limiter   clear 127.0.0.1 limiter rows
//   php tests/support/ui_db.php last-log        latest 127.0.0.1 audit row (JSON)
// Always uses the isolated test database (tests/bootstrap.php).
require_once __DIR__ . '/../bootstrap.php';

$db = test_db();
$db->exec(file_get_contents(__DIR__ . '/../../database/migrations/014_verify_rate_limiter.sql'));

switch ($argv[1] ?? '') {
    case 'reset-limiter':
        $db->exec("DELETE FROM verify_rate WHERE ip = '127.0.0.1'");
        echo "ok\n";
        break;
    case 'last-log':
        $row = $db->query("SELECT query_type, query_value, result, detail FROM verification_logs
                           WHERE verifier_ip = '127.0.0.1' ORDER BY id DESC LIMIT 1")->fetch();
        echo json_encode($row ?: new stdClass());
        break;
    default:
        fwrite(STDERR, "usage: ui_db.php reset-limiter|last-log\n");
        exit(1);
}
