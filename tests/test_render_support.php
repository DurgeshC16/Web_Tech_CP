<?php
// tests/test_render_support.php
// Render free-plan support (docs/13_DEPLOY_RENDER.md), all OFF by default:
//   1. Brevo HTTP mail transport (mocked HTTP layer — no network)
//   2. production guard: 'brevo' needs CV_BREVO_API_KEY
//   3. FileStore (CV_FILE_STORE=db): persist / forget / restoreAll, binary
//      content, transaction rollback, no-op when disabled, QR hook
//   4. trusted proxy (CV_TRUST_PROXY=1): True-Client-IP / CF-Connecting-IP,
//      spoofed X-Forwarded-For ignored, invalid IPs ignored, HTTPS flag —
//      unit + over HTTP (php -S), including Secure cookie + HSTS
//   5. scripts/render_boot.php against a fresh temporary database
//      (schema import, idempotent re-run, resume after an interrupted
//      import, CV_SUPER_ADMIN_* bootstrap, file restore, DB unreachable)
//   6. public/health.php over php -S (200 ok / 503 db unavailable, no
//      session cookie, no log line, no guest quota)
//   + DB TLS option building (CA path / PEM normalisation)

// The Brevo transport is selected for THIS process only (constants win
// over config.php's getenv() fallbacks).
define('MAIL_TRANSPORT', 'brevo');
define('BREVO_API_KEY', 'xkeysib-unit-test-key-0123456789');
define('SMTP_USERNAME', '');
define('SMTP_PASSWORD', '');
define('SMTP_FROM_EMAIL', 'sender@certivault.test');
define('SMTP_FROM_NAME', 'CertiVault Test');

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/FileStore.php';
require_once __DIR__ . '/../src/services/QRService.php';
require_once __DIR__ . '/../src/services/SchemaInstaller.php';
require_once __DIR__ . '/../src/services/SuperAdminService.php';

$root = dirname(__DIR__);

// "Database unavailable" is simulated with a database name that does not
// exist (the server rejects the connection at once). A closed TCP port
// would be more literal, but on Windows a refused connect from a child
// process was observed to hang indefinitely, making the test flaky.
// These children are started before this process opens a connection.
$testDbName = getenv('CV_TEST_DB') ?: 'certivault_test';
$pA = rs_free_port((int)(getenv('CV_TEST_RENDER_PORT') ?: 8161));
$pB = rs_free_port($pA + 1);
$srvA = rs_server($pA, ['CV_TRUST_PROXY' => '1', 'CV_DB_NAME' => $testDbName, 'CV_MAIL_TRANSPORT' => 'file', 'CV_ENV' => 'development']);
$srvB = rs_server($pB, ['CV_TRUST_PROXY' => null, 'CV_DB_NAME' => 'certivault_no_such_db_rs', 'CV_MAIL_TRANSPORT' => 'file', 'CV_ENV' => 'development']);
$A = "http://127.0.0.1:$pA";
$B = "http://127.0.0.1:$pB";
[$unreachCode, $unreachOut] = rs_run(['scripts/render_boot.php'], ['CV_DB_NAME' => 'certivault_no_such_db_rs', 'CV_ENV' => null, 'CV_FILE_STORE' => null,
    'CV_BOOT_DB_RETRIES' => '2', 'CV_BOOT_DB_RETRY_DELAY' => '0']);

$db = test_db();

/** Run a PHP CLI process with env overrides; returns [exitCode, stdout+stderr]. */
function rs_run(array $args, array $overrides): array {
    $env = getenv();
    foreach ($overrides as $k => $v) {
        if ($v === null) { unset($env[$k]); } else { $env[$k] = $v; }
    }
    $desc = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open(array_merge([PHP_BINARY], $args), $desc, $pipes, dirname(__DIR__), $env);
    if (!is_resource($proc)) {
        return [-1, '__PROC_FAILED__'];
    }
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]) . stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    return [proc_close($proc), $out];
}

// ═════════════════════════════════════════════════════════════════════
echo "== 1. Brevo HTTP transport (mocked) ==\n";
$calls = [];
$reply = ['status' => 201, 'body' => '{"messageId":"<x@smtp-relay.mailin.fr>"}', 'error' => ''];
brevo_http_client(function ($url, array $headers, $body) use (&$calls, &$reply) {
    $calls[] = ['url' => $url, 'headers' => $headers, 'body' => $body];
    return $reply;
});

t_check('brevo transport selected', mail_brevo_transport_enabled() && !mail_file_transport_enabled());
t_check('brevo + key counts as configured', brevo_configured() && mail_delivery_configured());
t_check('smtp_configured() keeps its literal meaning', smtp_configured() === false);

$mail = create_smtp_mailer();
$mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
$mail->addAddress('student@example.org', 'Stu Dent');
$mail->addCC('cc@example.org');
$mail->addReplyTo('reply@example.org', 'Reply Desk');
$mail->Subject = 'Ünïcode subject ✓';
$mail->isHTML(true);
$mail->Body = '<p>Hello <b>world</b></p>';
$mail->AltBody = 'Hello world';
$p = brevo_build_payload($mail);
t_check('payload sender', $p['sender'] === ['email' => 'sender@certivault.test', 'name' => 'CertiVault Test']);
t_check('payload to (email + name)', $p['to'] === [['email' => 'student@example.org', 'name' => 'Stu Dent']]);
t_check('payload cc / replyTo', ($p['cc'] ?? null) === [['email' => 'cc@example.org']] && ($p['replyTo'] ?? null) === ['email' => 'reply@example.org', 'name' => 'Reply Desk']);
t_check('payload subject (UTF-8 kept)', $p['subject'] === 'Ünïcode subject ✓');
t_check('payload htmlContent + textContent', $p['htmlContent'] === '<p>Hello <b>world</b></p>' && $p['textContent'] === 'Hello world');

$plain = create_smtp_mailer();
$plain->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
$plain->addAddress('p@example.org');
$plain->Subject = 'plain';
$plain->Body = 'just text';
$pp = brevo_build_payload($plain);
t_check('plain-text message -> textContent only', ($pp['textContent'] ?? '') === 'just text' && !isset($pp['htmlContent']));

$calls = [];
t_check('deliver_mail() returns true on HTTP 201', deliver_mail($mail) === true);
$c = $calls[0] ?? ['url' => '', 'headers' => [], 'body' => '{}'];
$sent = json_decode($c['body'], true);
t_check('POST goes to the Brevo endpoint', $c['url'] === 'https://api.brevo.com/v3/smtp/email');
t_check('api-key header carries the key', in_array('api-key: ' . BREVO_API_KEY, $c['headers'], true));
t_check('JSON content type', in_array('content-type: application/json', $c['headers'], true));
t_check('request body == built payload', $sent == $p);

// Failure semantics = SMTP failure: deliver_mail throws, ErrorInfo set.
$reply = ['status' => 401, 'body' => '{"code":"unauthorized","message":"Key not found ' . BREVO_API_KEY . '"}', 'error' => ''];
$threw = null;
try { deliver_mail($mail); } catch (Throwable $e) { $threw = $e; }
t_check('HTTP 401 -> deliver_mail throws', $threw instanceof RuntimeException);
t_check('error names the API error, never the key', $threw && str_contains($threw->getMessage(), 'unauthorized')
    && !str_contains($threw->getMessage(), BREVO_API_KEY) && !str_contains((string)$mail->ErrorInfo, BREVO_API_KEY));
t_check('otp_mail_error_reason() classifies Brevo', str_contains(otp_mail_error_reason($mail, $threw), 'Brevo'));
$reply = ['status' => 0, 'body' => '', 'error' => 'Could not resolve host'];
$threw = null;
try { deliver_mail($mail); } catch (Throwable $e) { $threw = $e; }
t_check('network error -> deliver_mail throws', $threw instanceof RuntimeException);
brevo_http_client(function () { throw new RuntimeException('boom'); });
$threw = null;
try { deliver_mail($mail); } catch (Throwable $e) { $threw = $e; }
t_check('client exception -> deliver_mail throws RuntimeException', $threw instanceof RuntimeException);
brevo_http_client(function ($url, array $headers, $body) use (&$calls, &$reply) {
    $calls[] = ['url' => $url, 'headers' => $headers, 'body' => $body];
    return $reply;
});

// Existing callers, unchanged: notification + OTP.
$reply = ['status' => 201, 'body' => '{}', 'error' => ''];
$calls = [];
t_check('send_notification_email() true via Brevo', send_notification_email('note@example.org', 'Subj', 'Heading', 'Body text') === true);
$n = json_decode($calls[0]['body'] ?? '{}', true);
t_check('notification payload (to/subject/html/text)', ($n['to'][0]['email'] ?? '') === 'note@example.org'
    && ($n['subject'] ?? '') === 'Subj' && str_contains($n['htmlContent'] ?? '', 'Heading') && str_contains($n['textContent'] ?? '', 'Body text'));
$reply = ['status' => 400, 'body' => '{"code":"invalid_parameter","message":"sender is invalid"}', 'error' => ''];
t_check('send_notification_email() false on API error', send_notification_email('note@example.org', 'Subj', 'Heading', 'Body') === false);

$otpEmail = 'rs.otp.' . bin2hex(random_bytes(3)) . '@example.org';
$db->prepare('INSERT INTO users (email, password_hash, role) VALUES (:e, :h, "student")')->execute(['e' => $otpEmail, 'h' => password_hash('x', PASSWORD_BCRYPT)]);
$otpUid = (int)$db->lastInsertId();
$reply = ['status' => 500, 'body' => '{"code":"internal","message":"down"}', 'error' => ''];
$r = create_otp($db, $otpUid, 'activation');
$left = (int)$db->query('SELECT COUNT(*) FROM otp_codes WHERE user_id = ' . $otpUid)->fetchColumn();
t_check('create_otp(): API failure -> mail_failed, row rolled back', $r === 'mail_failed' && $left === 0);
$reply = ['status' => 201, 'body' => '{}', 'error' => ''];
$calls = [];
$r = create_otp($db, $otpUid, 'activation', 'https://app.example/activate_account.php?user_id=' . $otpUid);
$o = json_decode($calls[0]['body'] ?? '{}', true);
$hasCode = preg_match('/code is: (\d{6})/', $o['textContent'] ?? '', $m) === 1;
$stored = $db->query('SELECT otp_code FROM otp_codes WHERE user_id = ' . $otpUid . ' AND used = 0 ORDER BY id DESC LIMIT 1')->fetchColumn();
t_check('create_otp(): sent via Brevo, code in the mail matches the stored hash', $r === 'sent' && $hasCode && hash_equals((string)$stored, hash_otp($m[1])));
$db->prepare('DELETE FROM users WHERE id = :id')->execute(['id' => $otpUid]);
brevo_http_client(null, true);
t_check('brevo_http_client(null, true) restores the real client', brevo_http_client() === 'brevo_http_post');

// brevo without a key (separate process: constants are per process).
[, $o] = rs_run(['-r', 'require "src/config/config.php"; require "src/utils/helpers.php"; echo mail_delivery_configured() ? "CONFIGURED" : "NOT_CONFIGURED";'],
    ['CV_MAIL_TRANSPORT' => 'brevo', 'CV_BREVO_API_KEY' => null, 'CV_ENV' => null]);
t_check('brevo without key -> mail_delivery_configured() false', str_contains($o, 'NOT_CONFIGURED'));

// ═════════════════════════════════════════════════════════════════════
echo "== 2. production guard ==\n";
$probe = __DIR__ . '/fixtures/config_probe.php';
$strong = [
    'CV_ENV' => 'production',
    'CV_ENCRYPTION_KEY' => 'k9O1Ff0hQ3l1+3Yt5bT0a8m7jx2c1bq0v5n4m3l2k1o=', // Render generateValue shape
    'CV_SHARE_SECRET'   => 'Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4cXV1eHF1dXg=',
    'CV_OTP_PEPPER'     => 'cGVwcGVycGVwcGVycGVwcGVycGVwcGVycGVwcGVyMTI=',
];
[, $o] = rs_run([$probe], $strong + ['CV_MAIL_TRANSPORT' => 'brevo', 'CV_BREVO_API_KEY' => 'xkeysib-abc']);
t_check('production + brevo + key => loads', str_contains($o, 'CV_CONFIG_LOADED'));
[, $o] = rs_run([$probe], $strong + ['CV_MAIL_TRANSPORT' => 'brevo', 'CV_BREVO_API_KEY' => null]);
t_check('production + brevo without key => refused', !str_contains($o, 'CV_CONFIG_LOADED'));
[, $o] = rs_run([$probe], $strong + ['CV_MAIL_TRANSPORT' => 'brevo', 'CV_BREVO_API_KEY' => '   ']);
t_check('production + brevo with blank key => refused', !str_contains($o, 'CV_CONFIG_LOADED'));
[, $o] = rs_run([$probe], $strong + ['CV_MAIL_TRANSPORT' => 'smtp']);
t_check('production + smtp still loads', str_contains($o, 'CV_CONFIG_LOADED'));
[, $o] = rs_run([$probe], $strong + ['CV_MAIL_TRANSPORT' => 'file', 'CV_BREVO_API_KEY' => 'xkeysib-abc']);
t_check('production + file still refused (even with a Brevo key)', !str_contains($o, 'CV_CONFIG_LOADED'));

// ═════════════════════════════════════════════════════════════════════
echo "== 3. FileStore ==\n";
FileStore::setConnection($db);
$tag = 'cv_filestore_test_' . bin2hex(random_bytes(4));
$db->exec("DELETE FROM stored_files WHERE path LIKE '%cv_filestore_test_%'");
$rowCount = fn($rel) => (int)$db->query('SELECT COUNT(*) FROM stored_files WHERE path = ' . $db->quote($rel))->fetchColumn();
$upload = $root . '/private_data/uploads/' . $tag . '.bin';
$rel = 'private_data/uploads/' . $tag . '.bin';
$binary = "\x00\x01\xFF\xFE%PDF\r\n" . random_bytes(70000) . "\x00end";
file_put_contents($upload, $binary);

FileStore::setEnabled(false);
t_check('disabled: persist() is a no-op', FileStore::persist($upload) === false && $rowCount($rel) === 0);
t_check('disabled: forget() / restoreAll() are no-ops', FileStore::forget($upload) === false && FileStore::restoreAll() === ['restored' => 0, 'skipped' => 0, 'failed' => 0]);
FileStore::setEnabled(null);
t_check('default configuration is OFF', FileStore::enabled() === false && FILE_STORE === '');

FileStore::setEnabled(true);
t_check('relative path key', FileStore::relativePath($upload) === $rel);
t_check('persist() stores the file', FileStore::persist($upload) === true && $rowCount($rel) === 1);
$row = $db->query('SELECT content, sha256, size FROM stored_files WHERE path = ' . $db->quote($rel))->fetch();
t_check('stored bytes identical (binary-safe)', $row && $row['content'] === $binary);
t_check('stored sha256 + size', $row && $row['sha256'] === hash('sha256', $binary) && (int)$row['size'] === strlen($binary));
t_check('persist() unchanged file again -> ok', FileStore::persist($upload) === true && $rowCount($rel) === 1);
$binary2 = $binary . 'v2';
file_put_contents($upload, $binary2);
FileStore::persist($upload);
t_check('persist() after change updates the copy', $db->query('SELECT sha256 FROM stored_files WHERE path = ' . $db->quote($rel))->fetchColumn() === hash('sha256', $binary2));

unlink($upload);
$s = FileStore::restoreAll();
t_check('restoreAll() recreates a deleted file', $s['restored'] >= 1 && is_file($upload) && file_get_contents($upload) === $binary2);
$s = FileStore::restoreAll();
t_check('restoreAll() skips files with the same hash', $s['restored'] === 0 && $s['skipped'] >= 1);
file_put_contents($upload, 'locally modified');
FileStore::restoreAll();
t_check('restoreAll() replaces a file whose hash differs', file_get_contents($upload) === $binary2);

// QR hook: QRService persists the PNG it writes.
$qr = $root . '/public/qrcodes/' . $tag . '.png';
QRService::generateQRCode('https://example.org/verify.php?token=abc', $qr);
$qrRel = 'public/qrcodes/' . $tag . '.png';
t_check('QRService::generateQRCode() persists the PNG', is_file($qr) && $rowCount($qrRel) === 1);

// Inside a transaction the copy is rolled back with the certificate row.
$tx = $root . '/private_data/uploads/' . $tag . '_tx.bin';
file_put_contents($tx, 'tx');
$db->beginTransaction();
FileStore::persist($tx);
$db->rollBack();
t_check('persist() inside a rolled-back transaction leaves no row', $rowCount('private_data/uploads/' . $tag . '_tx.bin') === 0);
@unlink($tx);

// Paths outside the repository are refused.
$outside = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $tag . '.bin';
file_put_contents($outside, 'x');
t_check('path outside the repository is not stored', FileStore::persist($outside) === false && FileStore::relativePath($outside) === null);
@unlink($outside);

// forget() drops the copy; restoreAll() then leaves the file deleted.
unlink($upload);
t_check('forget() removes the stored copy', FileStore::forget($upload) === true && $rowCount($rel) === 0);
FileStore::restoreAll();
t_check('forgotten file is not restored', !is_file($upload));

// A tampered/unsafe row is never written outside the tree.
$db->prepare('INSERT INTO stored_files (path, content, sha256, size) VALUES (:p, :c, :s, 1)')
   ->execute(['p' => '../' . $tag . '_evil.txt', 'c' => 'x', 's' => hash('sha256', 'x')]);
$db->prepare('INSERT INTO stored_files (path, content, sha256, size) VALUES (:p, :c, :s, 1)')
   ->execute(['p' => 'private_data/uploads/' . $tag . '_badhash.bin', 'c' => 'x', 's' => str_repeat('0', 64)]);
$s = FileStore::restoreAll();
t_check('unsafe path and bad-hash rows are refused', $s['failed'] >= 2 && !is_file(dirname($root) . '/' . $tag . '_evil.txt')
    && !is_file($root . '/private_data/uploads/' . $tag . '_badhash.bin'));

@unlink($qr);
$db->exec("DELETE FROM stored_files WHERE path LIKE '%cv_filestore_test_%'");
FileStore::setEnabled(null);
FileStore::setConnection(null);

// ═════════════════════════════════════════════════════════════════════
echo "== 4. trusted proxy (unit) ==\n";
$base = ['REMOTE_ADDR' => '10.0.0.5'];
$hdrs = 'True-Client-IP,CF-Connecting-IP';
$s = certivault_apply_trusted_proxy($base + ['HTTP_X_FORWARDED_FOR' => '6.6.6.6, 10.0.0.5'], $hdrs);
t_check('X-Forwarded-For alone is ignored (spoofable)', $s['REMOTE_ADDR'] === '10.0.0.5');
$s = certivault_apply_trusted_proxy($base + ['HTTP_TRUE_CLIENT_IP' => '203.0.113.7', 'HTTP_X_FORWARDED_FOR' => '6.6.6.6'], $hdrs);
t_check('True-Client-IP wins over a spoofed X-Forwarded-For', $s['REMOTE_ADDR'] === '203.0.113.7' && $s['CV_PROXY_REMOTE_ADDR'] === '10.0.0.5');
$s = certivault_apply_trusted_proxy($base + ['HTTP_TRUE_CLIENT_IP' => '1.2.3.4<script>', 'HTTP_CF_CONNECTING_IP' => '2001:db8::1'], $hdrs);
t_check('invalid True-Client-IP ignored, CF-Connecting-IP (IPv6) used', $s['REMOTE_ADDR'] === '2001:db8::1');
$s = certivault_apply_trusted_proxy($base + ['HTTP_TRUE_CLIENT_IP' => '999.1.1.1', 'HTTP_CF_CONNECTING_IP' => 'unknown'], $hdrs);
t_check('all headers invalid -> REMOTE_ADDR unchanged', $s['REMOTE_ADDR'] === '10.0.0.5');
$s = certivault_apply_trusted_proxy($base + ['HTTP_X_FORWARDED_PROTO' => 'https'], $hdrs);
t_check('X-Forwarded-Proto https -> HTTPS=on', ($s['HTTPS'] ?? null) === 'on');
$s = certivault_apply_trusted_proxy($base + ['HTTP_X_FORWARDED_PROTO' => 'http'], $hdrs);
t_check('X-Forwarded-Proto http -> HTTPS not set', !isset($s['HTTPS']));
t_check('CV_TRUST_PROXY is OFF by default', TRUST_PROXY === false);

// ═════════════════════════════════════════════════════════════════════
echo "== DB TLS options ==\n";
$pemBody = base64_encode(random_bytes(300));
$pemGood = "-----BEGIN CERTIFICATE-----\n" . rtrim(chunk_split($pemBody, 64, "\n")) . "\n-----END CERTIFICATE-----\n";
t_check('PEM with literal \\n normalised', Database::normalizePem(str_replace("\n", '\n', $pemGood)) === $pemGood);
t_check('PEM collapsed onto one line normalised', Database::normalizePem(str_replace("\n", ' ', $pemGood)) === $pemGood);
t_check('PEM with CRLF normalised', Database::normalizePem(str_replace("\n", "\r\n", $pemGood)) === $pemGood);
t_check('default: no TLS options, no port in DSN', Database::sslCaFile() === null && !isset(Database::options()[PDO::MYSQL_ATTR_SSL_CA])
    && !str_contains(Database::dsn(), 'port='));
[, $o] = rs_run(['-r', 'require "src/config/Database.php"; $o = Database::options(); $f = $o[PDO::MYSQL_ATTR_SSL_CA] ?? ""; '
    . 'echo Database::dsn(), "|", (is_file($f) && str_contains(file_get_contents($f), "BEGIN CERTIFICATE")) ? "CAFILE" : "NOCA", "|", '
    . '($o[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] ?? false) ? "VERIFY" : "NOVERIFY";'],
    ['CV_DB_PORT' => '24123', 'CV_DB_SSL_CA_PEM' => str_replace("\n", '\n', $pemGood)]);
t_check('CV_DB_PORT + CV_DB_SSL_CA_PEM -> port in DSN, CA file, verification on',
    str_contains($o, 'port=24123') && str_contains($o, '|CAFILE|VERIFY'));

// ═════════════════════════════════════════════════════════════════════
echo "== 5. render_boot.php (fresh temporary database) ==\n";
$split = SchemaInstaller::splitStatements("-- c;1\nCREATE TABLE a (x VARCHAR(5) DEFAULT 'a;b'); /* ; */ INSERT INTO a VALUES ('it''s;'); # x;y\nSELECT `we;ird`");
t_check('statement splitter respects quotes and comments', count($split) === 3 && str_contains($split[0], "'a;b'") && str_contains($split[1], "'it''s;'"));

$host = getenv('CV_DB_HOST') ?: 'localhost';
$user = getenv('CV_DB_USER') ?: 'root';
$pass = getenv('CV_DB_PASS') ?: '';
$bootDb = 'certivault_boot_test';
$admin = new PDO("mysql:host=$host", $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$admin->exec("DROP DATABASE IF EXISTS `$bootDb`");
$admin->exec("CREATE DATABASE `$bootDb`");
$bootEnv = [
    'CV_DB_NAME' => $bootDb, 'CV_ENV' => null, 'CV_FILE_STORE' => null, 'CV_BOOT_DB_RETRIES' => '1',
    'CV_SUPER_ADMIN_EMAIL' => 'boot.admin@example.org', 'CV_SUPER_ADMIN_PASSWORD' => 'Boot#Admin2026x',
];
[$code, $o] = rs_run(['scripts/render_boot.php'], $bootEnv);
$bdb = new PDO("mysql:host=$host;dbname=$bootDb;charset=utf8mb4", $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
$tables = SchemaInstaller::schemaTables();
$have = SchemaInstaller::existingTables($bdb, $tables);
t_check('boot: exit 0 and schema imported', $code === 0 && str_contains($o, 'schema imported'));
t_check('boot: every schema.sql table exists (' . count($tables) . ')', count($have) === count($tables) && count($tables) >= 17);
t_check('boot: 017 + 018 tables exist', in_array('guest_verify_quota', $have, true) && in_array('stored_files', $have, true));
$sa = $bdb->query("SELECT email, password_hash, is_verified FROM users WHERE role = 'super_admin'")->fetchAll();
t_check('boot: exactly one super admin, from env', count($sa) === 1 && $sa[0]['email'] === 'boot.admin@example.org'
    && password_verify('Boot#Admin2026x', $sa[0]['password_hash']) && (int)$sa[0]['is_verified'] === 1);
t_check('boot: password never printed', !str_contains($o, 'Boot#Admin2026x'));

[$code, $o] = rs_run(['scripts/render_boot.php'], $bootEnv);
t_check('boot re-run: no import, super admin unchanged', $code === 0 && !str_contains($o, 'schema imported') && str_contains($o, ': unchanged.'));
$hashBefore = $bdb->query("SELECT password_hash FROM users WHERE role = 'super_admin'")->fetchColumn();
[$code, $o] = rs_run(['scripts/render_boot.php'], ['CV_SUPER_ADMIN_PASSWORD' => 'weakpass'] + $bootEnv);
t_check('boot: weak password rejected, not printed, nothing changed', $code === 0 && str_contains($o, 'ERROR: super admin')
    && !str_contains($o, 'weakpass') && $bdb->query("SELECT password_hash FROM users WHERE role = 'super_admin'")->fetchColumn() === $hashBefore);
[$code, $o] = rs_run(['scripts/render_boot.php'], ['CV_SUPER_ADMIN_PASSWORD' => 'Rotated#Pass2027', 'CV_SUPER_ADMIN_EMAIL' => 'new.admin@example.org'] + $bootEnv);
$sa = $bdb->query("SELECT email, password_hash FROM users WHERE role = 'super_admin'")->fetchAll();
t_check('boot: env change rotates the super admin', count($sa) === 1 && $sa[0]['email'] === 'new.admin@example.org' && password_verify('Rotated#Pass2027', $sa[0]['password_hash']));

// Interrupted first import (tables missing, only the seeded user) resumes.
$bdb->exec('DROP TABLE tlog_checkpoints');
$bdb->exec('DROP TABLE stored_files');
[$code, $o] = rs_run(['scripts/render_boot.php'], $bootEnv);
$have = SchemaInstaller::existingTables($bdb, $tables);
t_check('boot: interrupted import is resumed', $code === 0 && str_contains($o, 'resuming') && count($have) === count($tables));
t_check('boot: resume did not add a second super admin', (int)$bdb->query("SELECT COUNT(*) FROM users WHERE role = 'super_admin'")->fetchColumn() === 1);

// File restore at start (CV_FILE_STORE=db).
$restoreRel = 'private_data/uploads/cv_filestore_test_boot.bin';
$restoreBytes = "\x00boot\xFF" . random_bytes(1000);
$ins = $bdb->prepare('INSERT INTO stored_files (path, content, sha256, size) VALUES (:p, :c, :s, :n)');
$ins->bindValue(':p', $restoreRel);
$ins->bindValue(':c', $restoreBytes, PDO::PARAM_LOB);
$ins->bindValue(':s', hash('sha256', $restoreBytes));
$ins->bindValue(':n', strlen($restoreBytes), PDO::PARAM_INT);
$ins->execute();
@unlink($root . '/' . $restoreRel);
[$code, $o] = rs_run(['scripts/render_boot.php'], ['CV_FILE_STORE' => 'db'] + $bootEnv);
t_check('boot: CV_FILE_STORE=db restores stored files', $code === 0 && str_contains($o, '1 restored')
    && is_file($root . '/' . $restoreRel) && file_get_contents($root . '/' . $restoreRel) === $restoreBytes);
@unlink($root . '/' . $restoreRel);

// Database unreachable: logs, retries, never fails the container.
// (run at the top of this file, before any DB connection was opened)
[$code, $o] = [$unreachCode, $unreachOut];
t_check('boot: unreachable DB -> retries, exit 0, starts anyway', $code === 0 && substr_count($o, 'not reachable') === 2 && str_contains($o, 'starting the web server anyway'));

// SuperAdminService direct rules (shared with scripts/set_super_admin.php).
$bdb->exec("INSERT INTO users (email, password_hash, role) VALUES ('taken@example.org', 'x', 'student')");
$err = null;
try { SuperAdminService::setCredentials($bdb, 'taken@example.org', 'Strong#Pass2026'); } catch (InvalidArgumentException $e) { $err = $e; }
t_check('super admin: email of another account refused', $err !== null);
$err = null;
try { SuperAdminService::setCredentials($bdb, 'not-an-email', 'Strong#Pass2026'); } catch (InvalidArgumentException $e) { $err = $e; }
t_check('super admin: invalid email refused', $err !== null);
$bdb->exec("DELETE FROM users WHERE role = 'super_admin'");
$err = null;
try { SuperAdminService::setCredentials($bdb, 'a@example.org', 'Strong#Pass2026'); } catch (RuntimeException $e) { $err = $e; }
t_check('super admin: CLI mode keeps the "no row" error', $err !== null && !($err instanceof InvalidArgumentException));
t_check('super admin: boot mode creates the row', SuperAdminService::setCredentials($bdb, 'a@example.org', 'Strong#Pass2026', true) === 'created');
$bdb = null;
$admin->exec("DROP DATABASE IF EXISTS `$bootDb`");
t_check('temporary boot database dropped', (int)$admin->query("SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '$bootDb'")->fetchColumn() === 0);

// ═════════════════════════════════════════════════════════════════════
echo "== 4b/6. trusted proxy + health.php over HTTP (php -S) ==\n";
function rs_free_port(int $port): int {
    for ($i = 0; $i < 20; $i++, $port++) {
        $sock = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.3);
        if (!$sock) {
            return $port;
        }
        fclose($sock);
    }
    return $port;
}
function rs_server(int $port, array $env) {
    $log = sys_get_temp_dir() . '/cv_render_support_http.log';
    $desc = [0 => ['pipe', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']];
    $full = getenv();
    foreach ($env as $k => $v) {
        if ($v === null) { unset($full[$k]); } else { $full[$k] = $v; }
    }
    $root = dirname(__DIR__);
    return proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', $root . '/public', $root . '/tests/fixtures/proxy_probe.php'],
        $desc, $pipes, $root, $full);
}
/** @return array{code:int, headers:string, body:string}|null */
function rs_http(string $url, array $headers = []) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_TIMEOUT => 20, CURLOPT_HTTPHEADER => $headers]);
    $raw = curl_exec($ch);
    if ($raw === false) { curl_close($ch); return null; }
    $hs = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return ['code' => $code, 'headers' => substr($raw, 0, $hs), 'body' => substr($raw, $hs)];
}
function rs_wait(string $base): bool {
    for ($i = 0; $i < 60; $i++) {
        usleep(200000);
        if (rs_http($base . '/__proxy_probe') !== null) { return true; }
    }
    return false;
}

// (servers $srvA / $srvB were started at the top of this file)
if (!is_resource($srvA) || !is_resource($srvB) || !rs_wait($A) || !rs_wait($B)) {
    t_check('built-in servers started', false);
} else {
    $spoof = ['X-Forwarded-For: 6.6.6.6', 'True-Client-IP: 198.51.100.23', 'X-Forwarded-Proto: https'];
    $j = json_decode(rs_http("$A/__proxy_probe", $spoof)['body'] ?? '{}', true);
    t_check('HTTP trusted: REMOTE_ADDR from True-Client-IP, not X-Forwarded-For', ($j['remote_addr'] ?? '') === '198.51.100.23');
    t_check('HTTP trusted: HTTPS=on from X-Forwarded-Proto', ($j['https'] ?? '') === 'on');
    $j = json_decode(rs_http("$A/__proxy_probe", ['X-Forwarded-For: 6.6.6.6', 'True-Client-IP: not-an-ip'])['body'] ?? '{}', true);
    t_check('HTTP trusted: invalid header + XFF -> real peer kept', ($j['remote_addr'] ?? '') === '127.0.0.1' && ($j['https'] ?? null) === null);
    $j = json_decode(rs_http("$B/__proxy_probe", $spoof)['body'] ?? '{}', true);
    t_check('HTTP default (proxy trust OFF): headers ignored', ($j['remote_addr'] ?? '') === '127.0.0.1' && ($j['https'] ?? null) === null && ($j['trust_proxy'] ?? true) === false);

    $login = rs_http("$A/login.php", $spoof);
    t_check('HTTP trusted https: session cookie Secure + HSTS', $login !== null
        && preg_match('/^Set-Cookie: PHPSESSID=[^\r\n]*;\s*secure/mi', $login['headers']) === 1
        && stripos($login['headers'], 'Strict-Transport-Security:') !== false);
    $loginPlain = rs_http("$B/login.php", $spoof);
    t_check('HTTP default: no Secure flag / HSTS from forged headers', $loginPlain !== null
        && preg_match('/^Set-Cookie: PHPSESSID=[^\r\n]*;\s*secure/mi', $loginPlain['headers']) === 0
        && stripos($loginPlain['headers'], 'Strict-Transport-Security:') === false);

    $logFile = $root . '/private_data/php_errors.log';
    clearstatcache();
    $logBefore = is_file($logFile) ? filesize($logFile) : 0;
    $quotaBefore = (int)$db->query('SELECT COUNT(*) FROM guest_verify_quota')->fetchColumn();
    $h = rs_http("$A/health.php");
    t_check('health.php: 200 "ok" with a working DB', $h && $h['code'] === 200 && trim($h['body']) === 'ok');
    t_check('health.php: no session cookie, not cacheable', $h && stripos($h['headers'], 'Set-Cookie') === false && stripos($h['headers'], 'Cache-Control: no-store') !== false);
    for ($i = 0; $i < 3; $i++) { rs_http("$A/health.php"); }
    $h = rs_http("$B/health.php");
    t_check('health.php: 503 "db unavailable" when the DB is down', $h && $h['code'] === 503 && trim($h['body']) === 'db unavailable');
    t_check('health.php: no internals in the body', $h && !preg_match('/SQLSTATE|PDO|127\.0\.0\.1|password/i', $h['body']));
    rs_http("$B/health.php");
    clearstatcache();
    t_check('health.php: no log line per hit', (is_file($logFile) ? filesize($logFile) : 0) === $logBefore);
    t_check('health.php: does not consume guest quota', (int)$db->query('SELECT COUNT(*) FROM guest_verify_quota')->fetchColumn() === $quotaBefore);
}
foreach ([$srvA, $srvB] as $srv) {
    if (is_resource($srv)) { proc_terminate($srv); proc_close($srv); }
}

exit(t_summary('test_render_support') ? 0 : 1);
