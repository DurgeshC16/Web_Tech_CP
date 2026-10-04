<?php
// scripts/test_smtp.php
// ─────────────────────────────────────────────────────────────────────
// Quick CLI smoke-test for SMTP credentials.
//
// Usage:  php scripts/test_smtp.php someone@example.com
//
// Loads the same config and uses the same create_smtp_mailer() helper
// that create_otp() does, so a pass here guarantees the real OTP email
// flow will also work.
// ─────────────────────────────────────────────────────────────────────

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die('This script must be run from the command line.');
}

if ($argc < 2 || !filter_var($argv[1], FILTER_VALIDATE_EMAIL)) {
    fwrite(STDERR, "Usage: php scripts/test_smtp.php <recipient-email>\n");
    exit(1);
}

$recipient = $argv[1];

// ── Bootstrap config (same path the web app uses) ───────────────────
require_once __DIR__ . '/../src/config/config.php';

// ── Load the shared mailer helper ───────────────────────────────────
require_once __DIR__ . '/../src/utils/helpers.php';

// ── Attempt to send a test email ────────────────────────────────────
try {
    $mail = create_smtp_mailer();

    $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
    $mail->addAddress($recipient);
    $mail->Subject = 'CertiVault SMTP Test';
    $mail->Body    = "This is a test email from CertiVault.\nIf you can read this, SMTP is configured correctly.";
    $mail->isHTML(false);

    $mail->send();

    echo "SMTP OK — test email sent to $recipient\n";
    exit(0);
} catch (\Throwable $e) {
    fwrite(STDERR, "SMTP FAILED — " . $e->getMessage() . "\n");
    exit(2);
}
