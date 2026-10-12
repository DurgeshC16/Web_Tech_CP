<?php
// src/utils/qrdecoder/autoload.php
// Minimal PSR-4 autoloader for the vendored QR decoder (no Composer).
// Library: khanamiryan/qrcode-detector-decoder v2.0.3 (MIT + Apache-2.0,
// see LICENSE-ORIGINAL-MIT), source: lib/ (namespace Zxing\).
spl_autoload_register(function ($class) {
    if (strpos($class, 'Zxing\\') !== 0) {
        return;
    }
    $file = __DIR__ . '/lib/' . str_replace('\\', '/', substr($class, strlen('Zxing\\'))) . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});
require_once __DIR__ . '/lib/Common/customFunctions.php';
