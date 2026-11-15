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
        $db->exec("DELETE FROM verification_logs WHERE detail = 'analytics seed'");
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
    case 'seed-analytics':
        // 30 days of plausible verification activity for the browser
        // fixture certificate; prints the number of rows inserted.
        $cid = $db->query("SELECT c.certificate_id FROM certificates c JOIN institutions i ON i.id = c.institution_id
                           WHERE i.name = 'Browser Fixture Uni' ORDER BY c.id LIMIT 1")->fetchColumn();
        if (!$cid) { fwrite(STDERR, "no fixture certificate\n"); exit(1); }
        $ins = $db->prepare('INSERT INTO verification_logs (query_type, query_value, certificate_id_found, result, detail, verifier_ip, verified_at)
                             VALUES ("token", "analytics-seed", :c, :r, "analytics seed", :ip, :t)');
        mt_srand(42);
        $n = 0;
        for ($d = 29; $d >= 0; $d--) {
            $count = 2 + (int)round(4 + 3 * sin($d / 4)) + ($d % 7 === 0 ? 6 : 0);
            for ($k = 0; $k < $count; $k++) {
                $roll = mt_rand(1, 100);
                $res = $roll <= 82 ? 'VALID' : ($roll <= 90 ? 'EXPIRED' : ($roll <= 96 ? 'TAMPERED' : 'REVOKED'));
                $ins->execute(['c' => $cid, 'r' => $res, 'ip' => '198.51.100.' . mt_rand(1, 60),
                               't' => date('Y-m-d', strtotime("-$d days")) . sprintf(' %02d:%02d:00', mt_rand(0, 9), mt_rand(0, 59))]);
                $n++;
            }
        }
        echo $n . "\n";
        break;
    default:
        fwrite(STDERR, "usage: ui_db.php reset-limiter|last-log\n");
        exit(1);
}
