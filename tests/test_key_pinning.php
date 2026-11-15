<?php
// tests/test_key_pinning.php
// Key fingerprint pinning (KeyPinService) against the paper's attack S6:
// an attacker with database write access replaces the institution's public
// key, edits the certificate and re-signs it with their own key.

require_once __DIR__ . '/bootstrap.php';

// Isolated pin file for this run (config.php honours a pre-defined constant).
$pinFile = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cv_pins_' . getmypid() . '.json';
define('KEY_PINS_FILE', $pinFile);

require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/KeyPinService.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/TrustScoreService.php';

$db = test_db();
$tag = bin2hex(random_bytes(4));
$file = __DIR__ . '/../private_data/uploads/pin-fixture-' . $tag . '.pdf';
@unlink($pinFile);

$db->beginTransaction();
try {
    // ── Fixture: institution with key A, one certificate signed by A ──
    $db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "admin", 1)')->execute(['e' => "pin-admin-$tag@example.com"]);
    $adminUid = (int)$db->lastInsertId();
    $db->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:u, "Pin Uni", "approved")')->execute(['u' => $adminUid]);
    $instId = (int)$db->lastInsertId();
    $keyA = CryptoService::generateRSAKeyPair();
    test_insert_institution_key($db, $instId, $keyA['public_key'], CryptoService::encryptPrivateKey($keyA['private_key']));
    $db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "student", 1)')->execute(['e' => "pin-stu-$tag@example.com"]);
    $stuUid = (int)$db->lastInsertId();
    $db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "Pin Student")')->execute(['u' => $stuUid]);
    $stuId = (int)$db->lastInsertId();

    file_put_contents($file, "%PDF-1.4 pin fixture $tag\n" . str_repeat('P', 200));
    $cid = 'PIN-' . strtoupper($tag);
    $fields = ['certificate_id' => $cid, 'institution_id' => $instId, 'student_id' => $stuId,
               'title' => 'Pinned Course', 'issue_date' => '2025-01-01', 'expiry_date' => null];
    $h = CryptoService::computeCertificateHash($fields, $file);
    $db->prepare('INSERT INTO certificates (certificate_id, institution_id, key_id, student_id, title, issue_date, file_path, status, sha256_hash, digital_signature)
                  VALUES (:c, :i, 1, :s, "Pinned Course", "2025-01-01", :f, "active", :h, :sig)')
       ->execute(['c' => $cid, 'i' => $instId, 's' => $stuId, 'f' => basename($file), 'h' => $h,
                  'sig' => CryptoService::signCertificateHash($h, $keyA['private_key'])]);
    $load = fn() => VerificationService::findByCertificateId($db, $cid);

    // ── Unpinned (non-strict): verifies normally ──────────────────────
    t_check('unpinned key: check() = unpinned', KeyPinService::check($instId, 1, $keyA['public_key']) === 'unpinned');
    t_check('unpinned key (non-strict): VALID', VerificationService::verify($db, $load())['verdict'] === 'VALID');

    // ── Pin key A ─────────────────────────────────────────────────────
    t_check('pin() new key -> pinned', KeyPinService::pin($instId, 1, $keyA['public_key'], 'test') === 'pinned');
    t_check('pin() same key again -> exists', KeyPinService::pin($instId, 1, $keyA['public_key'], 'test') === 'exists');
    t_check('pinned key: check() = match', KeyPinService::check($instId, 1, $keyA['public_key']) === 'match');
    t_check('pinned genuine certificate: VALID', VerificationService::verify($db, $load())['verdict'] === 'VALID');

    // ── Attack S6: swap the public key, edit the title, re-sign ───────
    $keyB = CryptoService::generateRSAKeyPair();
    $db->prepare('UPDATE institution_keys SET public_key = :p WHERE institution_id = :i AND key_id = 1')
       ->execute(['p' => $keyB['public_key'], 'i' => $instId]);
    $forged = $fields; $forged['title'] = 'Forged Advanced Course';
    $h2 = CryptoService::computeCertificateHash($forged, $file);
    $db->prepare('UPDATE certificates SET title = :t, sha256_hash = :h, digital_signature = :s WHERE certificate_id = :c')
       ->execute(['t' => $forged['title'], 'h' => $h2, 's' => CryptoService::signCertificateHash($h2, $keyB['private_key']), 'c' => $cid]);

    $res = VerificationService::verify($db, $load());
    t_check('S6 forgery with pinned key: TAMPERED', $res['verdict'] === 'TAMPERED');
    t_check('S6 detail names the key pin', str_contains($res['detail'], 'pinned key fingerprint'));
    $score = TrustScoreService::compute($db, $load());
    $sig = array_values(array_filter($score['checks'], fn($c) => $c['id'] === 'signature'))[0] ?? null;
    t_check('S6 trust score: signature check fails', $sig !== null && $sig['pass'] === false);
    t_check('S6 trust score: capped at 40 (cannot contradict verdict)', $score['score'] <= 40);

    // Without the pin the same forgery would pass — proves the pin is what stops it.
    $saved = file_get_contents($pinFile);
    unlink($pinFile); KeyPinService::reset();
    t_check('control: same forgery WITHOUT pins is accepted (the gap pinning closes)', VerificationService::verify($db, $load())['verdict'] === 'VALID');
    file_put_contents($pinFile, $saved); KeyPinService::reset();

    // ── Pins are append-only ──────────────────────────────────────────
    $before = file_get_contents($pinFile);
    t_check('re-pin with a different key -> conflict', KeyPinService::pin($instId, 1, $keyB['public_key'], 'attacker') === 'conflict');
    t_check('conflict leaves the pin file unchanged', file_get_contents($pinFile) === $before);

    // ── Corrupt store fails closed ────────────────────────────────────
    file_put_contents($pinFile, '{not json');
    KeyPinService::reset();
    t_check('corrupt pin file: check() fails closed (mismatch)', KeyPinService::check($instId, 1, $keyA['public_key']) === 'mismatch');
    file_put_contents($pinFile, $before);
    KeyPinService::reset();
} finally {
    $db->rollBack();
    @unlink($file);
}

// ── Strict mode (separate process: the constant is fixed per process) ─
$probe = __DIR__ . '/fixtures/pin_strict_probe.php';
$out = shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($probe) . ' 2>&1');
t_check('strict mode: unpinned key is NOT acceptable', is_string($out) && str_contains($out, 'unpinned:reject'));
t_check('strict mode: pinned matching key is acceptable', is_string($out) && str_contains($out, 'match:accept'));

// ── Operator script --verify reports a mismatch ───────────────────────
$db2 = test_db();
$t2 = bin2hex(random_bytes(3));
$db2->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "admin", 1)')->execute(['e' => "pin-cli-$t2@example.com"]);
$u2 = (int)$db2->lastInsertId();
$db2->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:u, "Pin CLI Uni", "approved")')->execute(['u' => $u2]);
$i2 = (int)$db2->lastInsertId();
$k2 = CryptoService::generateRSAKeyPair();
test_insert_institution_key($db2, $i2, $k2['public_key'], CryptoService::encryptPrivateKey($k2['private_key']));
$cliPins = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cv_pins_cli_' . getmypid() . '.json';
@unlink($cliPins);
$env = 'set CV_DB_NAME=' . (getenv('CV_TEST_DB') ?: 'certivault_test') . '&& set CV_KEY_PINS_FILE=' . $cliPins . '&& ';
$run = function (string $args) use ($env, $cliPins) {
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/../scripts/pin_institution_keys.php') . ' ' . $args;
    if (PHP_OS_FAMILY === 'Windows') {
        return shell_exec('cmd /c "' . $env . $cmd . '" 2>&1');
    }
    return shell_exec('CV_DB_NAME=' . escapeshellarg(getenv('CV_TEST_DB') ?: 'certivault_test') . ' CV_KEY_PINS_FILE=' . escapeshellarg($cliPins) . ' ' . $cmd . ' 2>&1');
};
$boot = (string)$run('');
t_check('script bootstrap pins existing keys', str_contains($boot, 'new pins:') && is_file($cliPins));
t_check('script --verify: all match after bootstrap', str_contains((string)$run('--verify'), 'All keys match their pins.'));
$db2->prepare('UPDATE institution_keys SET public_key = :p WHERE institution_id = :i')->execute(['p' => CryptoService::generateRSAKeyPair()['public_key'], 'i' => $i2]);
$v = (string)$run('--verify');
t_check('script --verify flags the swapped key', str_contains($v, 'MISMATCH') && str_contains($v, 'Pin CLI Uni'));
t_check('script --export prints the pin set', str_contains((string)$run('--export'), '"' . $i2 . ':1"'));
$db2->prepare('DELETE FROM institutions WHERE id = :i')->execute(['i' => $i2]);
$db2->prepare('DELETE FROM users WHERE id = :u')->execute(['u' => $u2]);
@unlink($cliPins); @unlink($cliPins . '.lock');
@unlink($pinFile); @unlink($pinFile . '.lock');

exit(t_summary('test_key_pinning') ? 0 : 1);
