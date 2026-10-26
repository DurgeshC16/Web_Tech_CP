<?php
// tests/test_otp.php
// Unit tests for the OTP lifecycle (create/verify) using the FILE mail
// transport, so they are deterministic and need no SMTP server or network.
//
// Scope: OTP generation, hashing, storage, rate limits, expiry, attempt
// lockout, and single-use semantics. Actual SMTP hand-off is covered
// separately by tests/test_smtp_live.php (opt-in, needs a real server).

require_once __DIR__ . '/bootstrap.php';

// Force the dev file transport and provide the constants helpers.php
// expects. SMTP_* are only consumed while building the message object;
// the file transport ignores their values.
define('MAIL_TRANSPORT', 'file');
define('MAIL_FILE_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cv_otp_mail_' . getmypid());
define('SMTP_HOST', 'localhost');
define('SMTP_PORT', 25);
define('SMTP_USERNAME', '');
define('SMTP_PASSWORD', '');
define('SMTP_ENCRYPTION', '');
define('SMTP_FROM_EMAIL', 'no-reply@certivault.test');
define('SMTP_FROM_NAME', 'CertiVault Test');
define('OTP_PEPPER', 'test-pepper');

require_once __DIR__ . '/../src/utils/helpers.php';

$db = test_db();

function otp_make_user($db, $email) {
    $db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "student", 1)')
       ->execute(['e' => $email]);
    return (int)$db->lastInsertId();
}
function otp_cleanup_user($db, $uid) {
    $db->prepare('DELETE FROM otp_codes WHERE user_id = :u')->execute(['u' => $uid]);
    $db->prepare('DELETE FROM users WHERE id = :u')->execute(['u' => $uid]);
}
function otp_clear_spool() {
    foreach (glob(MAIL_FILE_DIR . '/*.eml') ?: [] as $f) {
        @unlink($f);
    }
}
/** Extract the 6-digit code from the most recent spooled message. */
function otp_last_code() {
    $files = glob(MAIL_FILE_DIR . '/*.eml') ?: [];
    if (!$files) {
        return null;
    }
    usort($files, fn($a, $b) => filemtime($b) <=> filemtime($a));
    $body = file_get_contents($files[0]);
    if (preg_match('/>(\d{6})</', $body, $m)) {
        return $m[1];
    }
    if (preg_match('/code is:\s*(\d{6})/', $body, $m)) {
        return $m[1];
    }
    return null;
}

echo "== OTP lifecycle (file transport) ==\n";

// ── 1. create_otp delivers via the file transport and returns 'sent' ──
otp_clear_spool();
$u1 = otp_make_user($db, 'otp1@test.local');
t_check('create_otp returns sent', create_otp($db, $u1, 'activation') === 'sent');
t_check('spool wrote exactly one .eml', count(glob(MAIL_FILE_DIR . '/*.eml') ?: []) === 1);
$code1 = otp_last_code();
t_check('spool contains a 6-digit code', is_string($code1) && preg_match('/^\d{6}$/', $code1) === 1);

// ── 2. Stored value is the HMAC, never the plaintext ─────────────────
$stored = $db->prepare('SELECT otp_code FROM otp_codes WHERE user_id = :u ORDER BY id DESC LIMIT 1');
$stored->execute(['u' => $u1]);
$storedHash = $stored->fetchColumn();
t_check('stored code is not the plaintext', $storedHash !== $code1);
t_check('stored code equals hash_otp(plaintext)', $storedHash === hash_otp($code1));

// ── 3. Correct code verifies, and is single-use ──────────────────────
t_check('verify correct code => ok', verify_otp($db, $u1, 'activation', $code1) === 'ok');
t_check('verify reused code => none', verify_otp($db, $u1, 'activation', $code1) === 'none');

// ── 4. Resend cooldown (60s) ─────────────────────────────────────────
t_check('immediate second create => cooldown', create_otp($db, $u1, 'activation') === 'cooldown');

// ── 5. Non-numeric / short code rejected before any lookup ───────────
$u2 = otp_make_user($db, 'otp2@test.local');
t_check('non-numeric code => invalid', verify_otp($db, $u2, 'activation', 'abcdef') === 'invalid');
otp_clear_spool();
create_otp($db, $u2, 'activation');
$code2 = otp_last_code();

// ── 6. Wrong code increments attempts, then locks at 5 ───────────────
$wrong = ($code2 === '000000') ? '111111' : '000000';
$results = [];
for ($i = 1; $i <= 5; $i++) {
    $results[] = verify_otp($db, $u2, 'activation', $wrong);
}
t_check('1st..4th wrong => invalid', $results === ['invalid', 'invalid', 'invalid', 'invalid', 'locked']);
t_check('5th wrong => locked', end($results) === 'locked');
t_check('locked code no longer usable', verify_otp($db, $u2, 'activation', $code2) === 'none');

// ── 7. Expiry ───────────────────────────────────────────────────────
$u3 = otp_make_user($db, 'otp3@test.local');
otp_clear_spool();
create_otp($db, $u3, 'activation');
$code3 = otp_last_code();
$db->prepare('UPDATE otp_codes SET expires_at = DATE_SUB(NOW(), INTERVAL 1 MINUTE) WHERE user_id = :u')
   ->execute(['u' => $u3]);
t_check('expired code => expired', verify_otp($db, $u3, 'activation', $code3) === 'expired');

// ── 8. Max 5 codes per user per hour ─────────────────────────────────
$u4 = otp_make_user($db, 'otp4@test.local');
$ins = $db->prepare('INSERT INTO otp_codes (user_id, otp_code, purpose, expires_at, created_at)
                     VALUES (:u, :c, "activation", DATE_ADD(NOW(), INTERVAL 10 MINUTE), DATE_SUB(NOW(), INTERVAL 120 SECOND))');
for ($i = 0; $i < 5; $i++) {
    $ins->execute(['u' => $u4, 'c' => hash_otp('111111')]);
}
t_check('6th code in an hour => limit', create_otp($db, $u4, 'activation') === 'limit');

// ── 9. A fresh unused code supersedes older unused codes ─────────────
$u5 = otp_make_user($db, 'otp5@test.local');
otp_clear_spool();
create_otp($db, $u5, 'activation');
$first = otp_last_code();
$db->prepare('UPDATE otp_codes SET created_at = DATE_SUB(NOW(), INTERVAL 90 SECOND) WHERE user_id = :u')
   ->execute(['u' => $u5]); // lift cooldown
otp_clear_spool();
create_otp($db, $u5, 'activation');
$second = otp_last_code();
$unused = $db->prepare('SELECT COUNT(*) FROM otp_codes WHERE user_id = :u AND used = 0');
$unused->execute(['u' => $u5]);
t_check('only one unused code remains after resend', (int)$unused->fetchColumn() === 1);
t_check('old code rejected after resend', verify_otp($db, $u5, 'activation', $first) === 'invalid');
t_check('new code verifies', verify_otp($db, $u5, 'activation', $second) === 'ok');

// Cleanup.
foreach ([$u1, $u2, $u3, $u4, $u5] as $u) {
    otp_cleanup_user($db, $u);
}
otp_clear_spool();
@rmdir(MAIL_FILE_DIR);

exit(t_summary('test_otp') ? 0 : 1);
