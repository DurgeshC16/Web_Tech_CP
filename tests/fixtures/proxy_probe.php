<?php
// tests/fixtures/proxy_probe.php
// Router script for `php -S … -t public tests/fixtures/proxy_probe.php`
// (test_render_support.php). /__proxy_probe loads config.php and reports
// what the application sees after the trusted-proxy rewrite; every other
// path is served normally from public/.
if (parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) !== '/__proxy_probe') {
    return false;
}
require __DIR__ . '/../../src/config/config.php';
header('Content-Type: application/json');
echo json_encode([
    'remote_addr' => $_SERVER['REMOTE_ADDR'] ?? null,
    'https'       => $_SERVER['HTTPS'] ?? null,
    'trust_proxy' => TRUST_PROXY,
]);
