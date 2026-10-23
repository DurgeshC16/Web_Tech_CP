<?php
// scripts/smtp_diagnostic.php
// ─────────────────────────────────────────────────────────────────────
// CLI SMTP diagnostic that prints PASS/FAIL for every step of the real
// OTP email path, so "users don't receive activation emails" can be
// narrowed to the exact failing stage:
//
//   1. configuration present      SMTP_HOST/PORT/USERNAME/PASSWORD set
//   2. OpenSSL extension          loaded (required for TLS/SSL)
//   3. connection to host:port    raw TCP/SSL reachability
//   4. STARTTLS + authentication  the same handshake create_otp() does
//   5. test send                  a real email delivered end-to-end
//
// Usage:  php scripts/smtp_diagnostic.php someone@example.com
//
// Loads the same config and uses the same create_smtp_mailer() helper
// that create_otp() does, so a pass here guarantees the real OTP email
// flow will also work. Exit codes: 0 = all passed, 1 = a precondition
// failed, 2 = the final test send failed.
// ─────────────────────────────────────────────────────────────────────

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die('This script must be run from the command line.');
}

if ($argc < 2 || !filter_var($argv[1], FILTER_VALIDATE_EMAIL)) {
    fwrite(STDERR, "Usage: php scripts/smtp_diagnostic.php <recipient-email>\n");
    exit(1);
}

$recipient = $argv[1];

// ── Bootstrap config (same path the web app uses) ───────────────────
require_once __DIR__ . '/../src/config/config.php';

// ── Load the shared mailer helper ───────────────────────────────────
require_once __DIR__ . '/../src/utils/helpers.php';

$failures = 0;
$stage_ok = function ($label, $ok, $detail = '') use (&$failures) {
    echo sprintf('%-46s %s%s', $label, $ok ? 'PASS' : 'FAIL', $detail !== '' ? ' — ' . $detail : '') . PHP_EOL;
    if (!$ok) {
        $failures++;
    }
    return $ok;
};

// ── 1. Configuration present ────────────────────────────────────────
echo "CertiVault SMTP diagnostic\n==========================\n";

// Where each SMTP value came from — the local override file wins over
// environment variables, which win over config.php defaults. The
// password itself is NEVER printed, only its source and set/empty state.
function smtp_config_source(string $const, string $local_src): string
{
    if ($local_src !== ''
        && preg_match('/^\s*define\(\s*[\'"]' . preg_quote($const, '/') . '[\'"]\s*,/mi', $local_src)) {
        return 'local file (config.local.php)';
    }
    $env = getenv($const);
    if ($env !== false && trim((string)$env) !== '') {
        return "env var $const";
    }
    return 'default (config.php fallback)';
}
$sv_local_raw = '';
$sv_local_path = __DIR__ . '/../src/config/config.local.php';
if (is_file($sv_local_path)) {
    $sv_local_raw = (string)file_get_contents($sv_local_path);
}
echo "Value sources:" . PHP_EOL;
foreach (['SMTP_HOST', 'SMTP_PORT', 'SMTP_USERNAME', 'SMTP_PASSWORD', 'SMTP_ENCRYPTION', 'SMTP_FROM_EMAIL', 'SMTP_FROM_NAME'] as $sv_c) {
    $sv_hidden = $sv_c === 'SMTP_PASSWORD';
    $sv_val = constant($sv_c);
    $sv_shown = $sv_hidden
        ? (trim((string)$sv_val) !== '' ? '(set — hidden)' : '(empty)')
        : (trim((string)$sv_val) === '' ? '(empty)' : $sv_val);
    echo sprintf(
        '  %-16s %-28s <- %s',
        $sv_c, (string)$sv_shown, smtp_config_source($sv_c, $sv_local_raw)
    ) . PHP_EOL;
}
if (!is_file($sv_local_path)) {
    echo '  NOTE: src/config/config.local.php does not exist — copy '
        . 'config.local.php.example there and fill in SMTP_USERNAME / '
        . 'SMTP_PASSWORD (Gmail App Password).' . PHP_EOL;
}

$stage_ok(
    '1. configuration present',
    smtp_configured(),
    "[host=" . SMTP_HOST . " port=" . SMTP_PORT . " encryption=" . SMTP_ENCRYPTION
        . " user=" . (SMTP_USERNAME !== '' ? SMTP_USERNAME : '(empty)') . " password="
        . (SMTP_PASSWORD !== '' ? '(set)' : '(empty)') . ']'
);

// ── 2. OpenSSL extension ────────────────────────────────────────────
$ext_ok = extension_loaded('openssl');
$stage_ok('2. openssl extension loaded', $ext_ok, $ext_ok ? '' : 'enable extension=openssl in php.ini');

// ── 3. Connection to host:port ──────────────────────────────────────
if ($ext_ok) {
    $transport = strtolower((string)SMTP_ENCRYPTION) === 'ssl' ? 'ssl' : 'tcp';
    $target = $transport . '://' . SMTP_HOST . ':' . SMTP_PORT;
    $errno = 0; $errstr = '';
    $sock = @stream_socket_client($target, $errno, $errstr, 10);
    if ($sock !== false) {
        $stage_ok('3. connection to ' . SMTP_HOST . ':' . SMTP_PORT, true);
        fclose($sock);
    } else {
        $stage_ok('3. connection to ' . SMTP_HOST . ':' . SMTP_PORT, false,
            "$errstr (errno $errno) — wrong host/port, firewall, or Gmail not reachable from this server");
    }
} else {
    echo sprintf('%-46s %s', '3. connection to ' . SMTP_HOST . ':' . SMTP_PORT, 'SKIPPED') . PHP_EOL;
}

// ── 4. STARTTLS + authentication (same handshake as create_otp()) ───
$auth_ok = false;
if ($ext_ok) {
    try {
        $mail = create_smtp_mailer();
        $mail->smtpConnect([
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'allow_self_signed' => false],
        ]);
        $mail->smtpClose();
        $auth_ok = true;
        $stage_ok('4. TLS handshake + authentication', true);
    } catch (\Throwable $e) {
        $reason = function_exists('otp_mail_error_reason') ? otp_mail_error_reason($mail, $e) : 'SMTP error';
        $stage_ok('4. TLS handshake + authentication', false, $reason . ' | ' . ($mail->ErrorInfo ?? $e->getMessage()));
    }
} else {
    echo sprintf('%-46s %s', '4. TLS handshake + authentication', 'SKIPPED') . PHP_EOL;
}

// ── 5. Test send (real message through the full pipeline) ───────────
if ($auth_ok) {
    try {
        $mail = create_smtp_mailer();
        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        $mail->addAddress($recipient, 'CertiVault SMTP Test');
        $mail->Subject = 'CertiVault SMTP Test';
        $mail->Body    = "This is a test email from CertiVault.\nIf you can read this, SMTP is configured correctly.";
        $mail->isHTML(false);
        $mail->send();
        $stage_ok('5. test send to ' . $recipient, true);
    } catch (\Throwable $e) {
        $reason = function_exists('otp_mail_error_reason') ? otp_mail_error_reason($mail, $e) : 'SMTP send failed';
        $stage_ok('5. test send to ' . $recipient, false, $reason . ' | ' . ($mail->ErrorInfo ?? $e->getMessage()));
    }
} else {
    echo sprintf('%-46s %s', '5. test send to ' . $recipient, 'SKIPPED') . PHP_EOL;
}

// ── Summary ─────────────────────────────────────────────────────────
echo '--------------------------' . PHP_EOL;
if ($failures === 0) {
    echo 'ALL SMTP CHECKS PASSED — the OTP email path should work.' . PHP_EOL;
    exit(0);
}
echo "$failures check(s) failed. Fix the failing stage(s) above, then retry." . PHP_EOL;
echo 'Gmail reminder: SMTP_PASSWORD must be a 16-character App Password '
    . '(myaccount.google.com/apppasswords), not the normal account password.' . PHP_EOL;
exit($auth_ok ? 2 : 1);
