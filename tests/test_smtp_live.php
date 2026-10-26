<?php
// tests/test_smtp_live.php
// OPT-IN end-to-end SMTP delivery test. Unlike tests/test_otp.php (which
// uses the file transport), this one performs a real SMTP handshake and
// asserts a message is actually delivered and its OTP activates a user.
//
// It is NOT part of run_all.php because it needs a reachable SMTP server
// and network I/O. To run it, start a throwaway server and opt in:
//
//   1) python tests/support/smtp_capture_server.py 2525 <capture-dir>
//   2) set CV_SMTP_LIVE=1 CV_SMTP_HOST=127.0.0.1 CV_SMTP_PORT=2525 \
//          CV_SMTP_USER=test CV_SMTP_PASS=test CV_SMTP_ENCRYPTION= \
//          CV_SMTP_CAPTURE_DIR=<capture-dir>
//   3) php tests/test_smtp_live.php
//
// Any real SMTP account works too (set the CV_SMTP_* values to it).

require_once __DIR__ . '/bootstrap.php';

if (getenv('CV_SMTP_LIVE') !== '1') {
    echo "SKIP live SMTP test (set CV_SMTP_LIVE=1 to run).\n";
    exit(0);
}

$captureDir = getenv('CV_SMTP_CAPTURE_DIR') ?: sys_get_temp_dir();

define('MAIL_TRANSPORT', 'smtp');
define('SMTP_HOST', getenv('CV_SMTP_HOST') ?: '127.0.0.1');
define('SMTP_PORT', (int)(getenv('CV_SMTP_PORT') ?: 2525));
define('SMTP_USERNAME', getenv('CV_SMTP_USER') ?: '');
define('SMTP_PASSWORD', getenv('CV_SMTP_PASS') ?: '');
define('SMTP_ENCRYPTION', getenv('CV_SMTP_ENCRYPTION') ?: '');
define('SMTP_FROM_EMAIL', 'no-reply@certivault.test');
define('SMTP_FROM_NAME', 'CertiVault Test');
define('OTP_PEPPER', getenv('CV_OTP_PEPPER') ?: 'test-pepper');

require_once __DIR__ . '/../src/utils/helpers.php';

$db = test_db();

function live_mail_files($dir) {
    return array_values(array_filter(glob($dir . '/*.eml') ?: [], 'is_file'));
}

echo "== live SMTP delivery ==\n";
echo 'server: ' . SMTP_HOST . ':' . SMTP_PORT . ' (transport=' . MAIL_TRANSPORT . ")\n";

// 1. A plain message is accepted by the SMTP server.
$before = count(live_mail_files($captureDir));
try {
    $mail = create_smtp_mailer();
    $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
    $mail->addAddress('delivery-check@certivault.test');
    $mail->Subject = 'CertiVault SMTP live test';
    $mail->isHTML(false);
    $mail->Body = 'live delivery probe';
    deliver_mail($mail);
    t_check('SMTP handshake + delivery accepted', true);
} catch (\Throwable $e) {
    t_check('SMTP handshake + delivery accepted (' . $e->getMessage() . ')', false);
}
$after = count(live_mail_files($captureDir));
t_check('capture server received the message', $after > $before);

// 2. The full OTP path delivers a real code that activates the account.
$email = 'livetest+' . bin2hex(random_bytes(4)) . '@certivault.test';
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "student", 0)')
   ->execute(['e' => $email]);
$uid = (int)$db->lastInsertId();

$beforeOtp = count(live_mail_files($captureDir));
$result = create_otp($db, $uid, 'activation');
t_check("create_otp over SMTP => sent (got $result)", $result === 'sent');

$new = array_slice(live_mail_files($captureDir), $beforeOtp);
$code = null;
foreach ($new as $file) {
    if (preg_match('/>(\d{6})</', (string)file_get_contents($file), $m)) {
        $code = $m[1];
        break;
    }
}
t_check('delivered email contains a 6-digit code', is_string($code));
if ($code !== null) {
    t_check('delivered code activates the user', verify_otp($db, $uid, 'activation', $code) === 'ok');
}

// Cleanup.
$db->prepare('DELETE FROM otp_codes WHERE user_id = :u')->execute(['u' => $uid]);
$db->prepare('DELETE FROM users WHERE id = :u')->execute(['u' => $uid]);

exit(t_summary('test_smtp_live') ? 0 : 1);
