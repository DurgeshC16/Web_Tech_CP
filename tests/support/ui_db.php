<?php
// tests/support/ui_db.php — tiny DB helper for tests/test_verify_ui.mjs.
//   php tests/support/ui_db.php reset-limiter   clear 127.0.0.1 limiter rows
//   php tests/support/ui_db.php last-log        latest 127.0.0.1 audit row (JSON)
//   php tests/support/ui_db.php purge-browser-issued  remove certificates/files issued by browser tests
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
    case 'purge-browser-issued':
        // Files + rows created by the browser issuance tests (fixture
        // institution), plus pending users created by the bulk test.
        $rows = $db->query("SELECT c.certificate_id, c.file_path, c.qr_token FROM certificates c
                            JOIN institutions i ON i.id = c.institution_id WHERE i.name = 'Browser Fixture Uni'")->fetchAll();
        foreach ($rows as $r) {
            @unlink(__DIR__ . '/../../private_data/uploads/' . basename($r['file_path']));
            @unlink(__DIR__ . '/../../public/qrcodes/' . basename((string)$r['qr_token']) . '.png');
        }
        $delTlog = $db->prepare('DELETE FROM tlog_entries WHERE certificate_id = :c');
        foreach ($rows as $r) {
            $delTlog->execute(['c' => $r['certificate_id']]);
        }
        $ids = $db->query("SELECT id FROM users WHERE email LIKE 'bulk-ui-%@example.com'")->fetchAll(PDO::FETCH_COLUMN);
        foreach ($ids as $u) {
            $db->prepare('DELETE FROM otp_codes WHERE user_id = :u')->execute(['u' => $u]);
            $db->prepare('DELETE FROM students WHERE user_id = :u')->execute(['u' => $u]);
            $db->prepare('DELETE FROM users WHERE id = :u')->execute(['u' => $u]);
        }
        echo count($rows) . " certificate file(s) removed\n";
        break;
    default:
        fwrite(STDERR, "usage: ui_db.php reset-limiter|last-log\n");
        exit(1);
}
