<?php
// tests/test_upload_http.php
// Boundary tests for v_upload() over REAL multipart uploads. The pure-CLI
// suite (test_upload_validation.php) cannot reach the extension/MIME/size
// branches because is_uploaded_file() is always false off an HTTP request.
// Here we boot PHP's built-in server, POST genuine multipart bodies, and
// assert the validator verdict.
//
// Self-contained: starts/stops its own server on an ephemeral-ish port.
// Skips (exit 0) if curl or a bind fails, so it never masks other suites.

require_once __DIR__ . '/bootstrap.php';

if (!function_exists('curl_init')) {
    echo "SKIP upload-http: curl extension unavailable.\n";
    exit(0);
}

$port = (int)(getenv('CV_TEST_HTTP_PORT') ?: 8137);
$root = __DIR__ . '/fixtures';
$base = "http://127.0.0.1:$port";
$tmp  = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cv_upload_' . getmypid();
@mkdir($tmp, 0777, true);

// ── Starter fixtures ──────────────────────────────────────────────────
$pdfOk   = $tmp . '/valid.pdf';
file_put_contents($pdfOk, "%PDF-1.4\n1 0 obj<</>>endobj\n" . str_repeat('A', 300));

$tiny    = $tmp . '/tiny.pdf';
file_put_contents($tiny, "%PDF-1.4 small"); // < 100 bytes

$wrong   = $tmp . '/evil.exe';
file_put_contents($wrong, "MZ" . str_repeat("\x00", 300)); // executable name

$mismatch = $tmp . '/fake.png';
file_put_contents($mismatch, "%PDF-1.4 not really a png\n" . str_repeat('B', 300));

$big = $tmp . '/big.pdf';
file_put_contents($big, "%PDF-1.4\n" . str_repeat('C', 6 * 1024 * 1024)); // > 5 MB

// Real images via GD (content sniffing must succeed).
$pngOk = $tmp . '/valid.png';
$jpgOk = $tmp . '/valid.jpg';
$hasGd = function_exists('imagecreatetruecolor');
if ($hasGd) {
    $im = imagecreatetruecolor(40, 40);
    imagefilledrectangle($im, 0, 0, 39, 39, imagecolorallocate($im, 10, 120, 200));
    imagepng($im, $pngOk);
    imagejpeg($im, $jpgOk, 90);
    imagedestroy($im);
}

/** Start PHP's built-in server; returns the process resource or null. */
function start_server($port, $root) {
    $desc = [0 => ['pipe', 'r'], 1 => ['file', sys_get_temp_dir() . '/cv_http_srv.log', 'a'], 2 => ['file', sys_get_temp_dir() . '/cv_http_srv.log', 'a']];
    $proc = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', $root], $desc, $pipes);
    return is_resource($proc) ? $proc : null;
}

/** POST one file to the probe endpoint; returns the response body. */
function post_file($url, $path, $postName) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => ['f' => new CURLFile($path, 'application/octet-stream', $postName)],
        CURLOPT_TIMEOUT        => 30,
    ]);
    $body = curl_exec($ch);
    $err  = curl_error($ch);
    curl_close($ch);
    return $body === false ? "__CURL_ERROR__:$err" : $body;
}

$proc = start_server($port, $root);
if ($proc === null) {
    echo "SKIP upload-http: could not start built-in server.\n";
    exit(0);
}

// Poll until the server answers (or give up -> skip).
$ready = false;
for ($i = 0; $i < 50; $i++) {
    usleep(200000);
    $ch = curl_init($base . '/upload_probe.php');
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 2]);
    $r = curl_exec($ch);
    curl_close($ch);
    if ($r !== false) { $ready = true; break; }
}
if (!$ready) {
    proc_terminate($proc);
    echo "SKIP upload-http: server did not become ready.\n";
    exit(0);
}

$url = $base . '/upload_probe.php';
echo "== v_upload over real multipart (php -S :$port) ==\n";

t_check('valid PDF accepted', post_file($url, $pdfOk, 'cert.pdf') === 'true');
if ($hasGd) {
    t_check('valid PNG accepted', post_file($url, $pngOk, 'cert.png') === 'true');
    t_check('valid JPG accepted', post_file($url, $jpgOk, 'cert.jpg') === 'true');
}

$r = post_file($url, $wrong, 'evil.exe');
t_check('disallowed extension rejected', $r !== 'true' && str_contains($r, 'Only PDF, PNG, and JPG'));

$r = post_file($url, $mismatch, 'fake.png');
t_check('extension/content mismatch rejected', $r !== 'true' && str_contains($r, 'does not match'));

$r = post_file($url, $tiny, 'tiny.pdf');
t_check('too-small file rejected', $r !== 'true' && str_contains($r, 'minimum 100 bytes'));

$r = post_file($url, $big, 'big.pdf');
t_check('oversized file rejected', $r !== 'true' && (str_contains($r, '5MB') || str_contains($r, '5 MB') || str_contains($r, 'upload limit')));

proc_terminate($proc);
proc_close($proc);

// Cleanup temp fixtures.
foreach ([$pdfOk, $tiny, $wrong, $mismatch, $big, $pngOk, $jpgOk] as $f) {
    @unlink($f);
}
@rmdir($tmp);

exit(t_summary('test_upload_http') ? 0 : 1);
