<?php
// tests/fixtures/upload_probe.php
// Minimal endpoint that runs the real v_upload() validator against a real
// multipart upload (so is_uploaded_file() is true) and echoes the result.
// Used only by tests/test_upload_http.php via PHP's built-in server.
require __DIR__ . '/../../src/utils/validators.php';

$result = v_upload($_FILES['f'] ?? null);
header('Content-Type: text/plain');
echo $result === true ? 'true' : $result;
