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
    'test_validators.php',
    'test_crypto.php',
    'test_upload_validation.php',
    'test_certflow.php',
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
