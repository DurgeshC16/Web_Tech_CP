<?php
// tests/test_config_guard.php
// Regression tests for config.php's production guards:
//   - committed default secrets are refused when CV_ENV=production
//   - MAIL_TRANSPORT != 'smtp' is refused when CV_ENV=production
//   - the file transport is allowed outside production
//
// Each case boots a fresh PHP process (tests/fixtures/config_probe.php)
// with a controlled environment and checks whether config.php let it past.

require_once __DIR__ . '/bootstrap.php';

$probe = __DIR__ . '/fixtures/config_probe.php';
$marker = 'CV_CONFIG_LOADED';

/** Run the probe under $overrides (merged over the current env). */
function run_probe($probe, $overrides) {
    $env = getenv(); // full current environment
    foreach ($overrides as $k => $v) {
        if ($v === null) {
            unset($env[$k]);
        } else {
            $env[$k] = $v;
        }
    }
    $desc = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open([PHP_BINARY, $probe], $desc, $pipes, null, $env);
    if (!is_resource($proc)) {
        return "__PROC_FAILED__";
    }
    $out = stream_get_contents($pipes[1]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($proc);
    return $out . $err;
}

// Strong, non-default secrets so only the mail guard can be the reason
// a production boot is refused.
$strong = [
    'CV_ENCRYPTION_KEY' => 'unit-test-encryption-key-0123456789',
    'CV_SHARE_SECRET'   => 'unit-test-share-secret-0123456789',
    'CV_OTP_PEPPER'     => 'unit-test-otp-pepper-0123456789',
];

echo "== config production guards ==\n";

// 1. Dev (no CV_ENV) + file transport => allowed.
$o = run_probe($probe, array_merge($strong, ['CV_ENV' => null, 'CV_MAIL_TRANSPORT' => 'file']));
t_check('dev + file transport => loads', str_contains($o, $marker));

// 2. Production + smtp + strong secrets => allowed.
$o = run_probe($probe, array_merge($strong, ['CV_ENV' => 'production', 'CV_MAIL_TRANSPORT' => 'smtp']));
t_check('production + smtp => loads', str_contains($o, $marker));

// 3. Production + file transport => refused (mail guard).
$o = run_probe($probe, array_merge($strong, ['CV_ENV' => 'production', 'CV_MAIL_TRANSPORT' => 'file']));
t_check('production + file transport => refused', !str_contains($o, $marker));

// 4. Production + default secrets => refused (secret guard).
$o = run_probe($probe, [
    'CV_ENV' => 'production',
    'CV_MAIL_TRANSPORT' => 'smtp',
    'CV_ENCRYPTION_KEY' => null,
    'CV_SHARE_SECRET'   => null,
    'CV_OTP_PEPPER'     => null,
]);
t_check('production + default secrets => refused', !str_contains($o, $marker));

// 5. Sanity: the probe itself loads fine in dev with defaults.
$o = run_probe($probe, ['CV_ENV' => null, 'CV_MAIL_TRANSPORT' => null]);
t_check('dev + defaults => loads', str_contains($o, $marker));

exit(t_summary('test_config_guard') ? 0 : 1);
