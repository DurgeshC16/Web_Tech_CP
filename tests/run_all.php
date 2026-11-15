<?php
// tests/run_all.php — run the whole CLI suite against the isolated test
// database and print a pass/fail summary.
// Usage:  php tests/run_all.php
// Env:    CV_DB_HOST / CV_DB_USER / CV_DB_PASS (default localhost/root/'')
//         CV_TEST_DB (default 'certivault_test') — never touches the dev DB.

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die('Test scripts must be run from the command line.');
}

$files = [
    // NOTE: test_validators.php, test_certflow.php and the combined
    // test_upload_validation.php were deleted by the local sandbox filter
    // driver (filename holds); the content now lives in
    // test_upload_suite.php (validators, flexible certificate-ID lookup,
    // verification cascade, Smart Verify either/or).
    'test_upload_suite.php',
    'test_crypto.php',
    'test_attested_credentials.php',
    'test_transparency_log.php',
    'test_rate_limit.php',
    'test_timezone.php',
    'test_workflow.php',
    'test_upload_http.php',   // spawns `php -S` on a local port
    'test_otp.php',           // OTP lifecycle via the dev file mail transport
    'test_config_guard.php',  // production secret / mail-transport guard
    'test_verify_http.php',   // verify.php over real HTTP (php -S)
    'test_key_pinning.php',   // key fingerprint pins vs the S6 key-swap attack
    // Browser suite (needs Chrome/Edge + Node >= 21): node tests/test_verify_ui.mjs
    // test_smtp_live.php needs a real SMTP account; run it by hand.
];

$failed = [];
foreach ($files as $f) {
    echo "\n===== $f =====\n";
    $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . DIRECTORY_SEPARATOR . $f);
    passthru($cmd, $code);
    if ($code !== 0) {
        $failed[] = $f;
    }
}

echo "\n===== SUMMARY =====\n";
if (empty($failed)) {
    echo 'ALL SUITES PASSED (' . count($files) . '/' . count($files) . ")\n";
    exit(0);
}
echo 'FAILURES in: ' . implode(', ', $failed) . "\n";
exit(1);
