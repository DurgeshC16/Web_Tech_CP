<?php
// tests/fixtures/pin_strict_probe.php — used by tests/test_key_pinning.php.
// Runs KeyPinService with KEY_PINNING_STRICT=true in its own process (the
// constant is fixed per process) and prints "<check>:<accept|reject>".
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit;
}
$pins = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cv_pins_strict_' . getmypid() . '.json';
define('KEY_PINS_FILE', $pins);
define('KEY_PINNING_STRICT', true);
require_once __DIR__ . '/../../src/services/KeyPinService.php';

$k = CryptoService::generateRSAKeyPair();
$state = fn() => KeyPinService::check(7, 1, $k['public_key']) . ':' . (KeyPinService::acceptable(7, 1, $k['public_key']) ? 'accept' : 'reject');
echo $state(), "\n";                       // unpinned:reject
KeyPinService::pin(7, 1, $k['public_key'], 'probe');
echo $state(), "\n";                       // match:accept
@unlink($pins);
@unlink($pins . '.lock');
