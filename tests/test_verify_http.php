<?php
// tests/test_verify_http.php
// Verdict + URL-parameter coverage for the public verifier over REAL HTTP.
//
// The browser suite (test_verify_ui.mjs) proves the four input methods feed
// the same backend; this suite proves the backend itself (verify.php) is
// correct for every verdict through both supported entry points — ?token=
// and ?certificate_id= — plus the CSRF-protected POST, the browser-decoded
// QR fallback and the landing page's external-script-only wiring. It boots PHP's built-in
// server against the isolated test DB, seeds one certificate per verdict,
// and asserts the rendered verdict seal.
//
// Self-contained: starts/stops its own server and cleans up its rows/files.
// Skips (exit 0) if curl or the server is unavailable.

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/utils/validators.php';

if (!function_exists('curl_init')) {
    echo "SKIP verify-http: curl extension unavailable.\n";
    exit(0);
}

$port = (int)(getenv('CV_TEST_VERIFY_PORT') ?: 8139);
$base = "http://127.0.0.1:$port";
$appRoot = realpath(__DIR__ . '/../public');
$uploadDir = __DIR__ . '/../private_data/uploads';

$db = test_db();

// Never let repeated runs accumulate distinct lookups against the limiter.
$db->exec(file_get_contents(__DIR__ . '/../database/migrations/014_verify_rate_limiter.sql'));
$db->prepare("DELETE FROM verification_logs WHERE verifier_ip = '127.0.0.1'")->execute();
$db->prepare("DELETE FROM verify_rate WHERE ip = '127.0.0.1'")->execute();

// ── Seed one certificate per verdict ──────────────────────────────────
$instName = 'Verify HTTP Fixture Uni';
// Order matters for FK constraints: certificates → students/institutions → users.
$st = $db->prepare('SELECT id FROM institutions WHERE name = :n');
$st->execute(['n' => $instName]);
foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $oldIid) {
    $db->prepare('UPDATE certificates SET superseded_by_id = NULL WHERE institution_id = :i')->execute(['i' => $oldIid]);
    $db->prepare('DELETE FROM certificates WHERE institution_id = :i')->execute(['i' => $oldIid]);
}
$db->prepare('DELETE FROM students WHERE full_name = "Verify HTTP Student"')->execute();
$db->prepare('DELETE FROM institutions WHERE name = :n')->execute(['n' => $instName]);
$db->prepare('DELETE FROM users WHERE email IN ("verifyhttp.admin@example.com","verifyhttp.student@example.com")')->execute();

$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES ("verifyhttp.admin@example.com", "x", "admin", 1)')->execute();
$adminUid = (int)$db->lastInsertId();
$keys = CryptoService::generateRSAKeyPair();
$db->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:u, :n, "approved")')
   ->execute(['u' => $adminUid, 'n' => $instName]);
$instId = (int)$db->lastInsertId();
test_insert_institution_key($db, $instId, $keys['public_key'], CryptoService::encryptPrivateKey($keys['private_key']));

$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES ("verifyhttp.student@example.com", "x", "student", 1)')->execute();
$studentUid = (int)$db->lastInsertId();
$db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "Verify HTTP Student")')->execute(['u' => $studentUid]);
$studentId = (int)$db->lastInsertId();

function vh_token() { return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='); }

$createdFiles = [];
function vh_cert($db, $instId, $studentId, $keys, $certId, $token, $status, $expiry, &$createdFiles) {
    $filename = 'verifyhttp-' . $token . '.pdf';
    $path = __DIR__ . '/../private_data/uploads/' . $filename;
    file_put_contents($path, "%PDF-1.4 fixture $token\n" . str_repeat('V', 240));
    $createdFiles[] = $path;
    $data = [
        'certificate_id' => $certId, 'institution_id' => $instId, 'student_id' => $studentId,
        'title' => 'HTTP Fixture', 'issue_date' => '2024-01-01', 'expiry_date' => $expiry,
    ];
    $hash = CryptoService::computeCertificateHash($data, $path);
    $sig  = CryptoService::signCertificateHash($hash, $keys['private_key']);
    $db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, expiry_date, file_path, status, version, qr_token, sha256_hash, digital_signature)
                  VALUES (:cid, :iid, :sid, "HTTP Fixture", "2024-01-01", :exp, :fp, :st, 1, :qr, :h, :s)')
       ->execute(['cid' => $certId, 'iid' => $instId, 'sid' => $studentId, 'exp' => $expiry, 'fp' => $filename, 'st' => $status, 'qr' => $token, 'h' => $hash, 's' => $sig]);
    return ['dbId' => (int)$db->lastInsertId(), 'token' => $token, 'certId' => $certId, 'path' => $path];
}

$valid      = vh_cert($db, $instId, $studentId, $keys, 'CV-2026-770001', vh_token(), 'active', '2099-01-01', $createdFiles);
$expired    = vh_cert($db, $instId, $studentId, $keys, 'CV-2026-770002', vh_token(), 'active', '2020-01-01', $createdFiles);
$revoked    = vh_cert($db, $instId, $studentId, $keys, 'CV-2026-770003', vh_token(), 'revoked', '2099-01-01', $createdFiles);
$newer      = vh_cert($db, $instId, $studentId, $keys, 'CV-2026-770004', vh_token(), 'active', '2099-01-01', $createdFiles);
$superseded = vh_cert($db, $instId, $studentId, $keys, 'CV-2026-770005', vh_token(), 'superseded', '2099-01-01', $createdFiles);
$db->prepare('UPDATE certificates SET superseded_by_id = :n WHERE id = :id')->execute(['n' => $newer['dbId'], 'id' => $superseded['dbId']]);
$tampered   = vh_cert($db, $instId, $studentId, $keys, 'CV-2026-770006', vh_token(), 'active', '2099-01-01', $createdFiles);
file_put_contents($tampered['path'], "TAMPERED\n" . str_repeat('X', 240)); // hash no longer matches
$unknownToken = vh_token();

// ── Start the built-in server ─────────────────────────────────────────
$env = getenv();
$env['CV_DB_NAME'] = getenv('CV_TEST_DB') ?: 'certivault_test';
$env['CV_MAIL_TRANSPORT'] = 'file';
$env['CV_ENV'] = 'development';

$desc = [0 => ['pipe', 'r'], 1 => ['file', sys_get_temp_dir() . '/cv_verify_http.log', 'a'], 2 => ['file', sys_get_temp_dir() . '/cv_verify_http.log', 'a']];
$proc = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', $appRoot], $desc, $pipes, dirname($appRoot), $env);
if (!is_resource($proc)) {
    echo "SKIP verify-http: could not start built-in server.\n";
    exit(0);
}

function h_get($url) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_FOLLOWLOCATION => false]);
    $body = curl_exec($ch);
    curl_close($ch);
    return $body === false ? null : $body;
}

$ready = false;
for ($i = 0; $i < 60; $i++) {
    usleep(200000);
    if (h_get($base . '/verify.php') !== null) { $ready = true; break; }
}
if (!$ready) {
    proc_terminate($proc); proc_close($proc);
    echo "SKIP verify-http: server did not become ready.\n";
    exit(0);
}

/** True when the response rendered the given verdict seal. */
function vh_verdict($html, $verdict) {
    return $html !== null && preg_match('/verdict-seal-' . strtolower($verdict) . '"/', $html) === 1;
}

echo "== verify.php verdicts over real HTTP (php -S :$port) ==\n";

// ── Token entry point (what every QR/upload method produces) ──────────
t_check('token VALID',      vh_verdict(h_get("$base/verify.php?token={$valid['token']}"), 'VALID'));
t_check('token EXPIRED',    vh_verdict(h_get("$base/verify.php?token={$expired['token']}"), 'EXPIRED'));
t_check('token REVOKED',    vh_verdict(h_get("$base/verify.php?token={$revoked['token']}"), 'REVOKED'));
t_check('token SUPERSEDED', vh_verdict(h_get("$base/verify.php?token={$superseded['token']}"), 'SUPERSEDED'));
t_check('token TAMPERED',   vh_verdict(h_get("$base/verify.php?token={$tampered['token']}"), 'TAMPERED'));
t_check('unknown token INVALID', vh_verdict(h_get("$base/verify.php?token=$unknownToken"), 'INVALID'));
t_check('malformed token INVALID', vh_verdict(h_get("$base/verify.php?token=tooshort"), 'INVALID'));

// ── Shareable direct link by certificate ID (GET) ────────────────────
t_check('id VALID (GET)',        vh_verdict(h_get("$base/verify.php?certificate_id={$valid['certId']}"), 'VALID'));
t_check('id REVOKED (GET)',      vh_verdict(h_get("$base/verify.php?certificate_id={$revoked['certId']}"), 'REVOKED'));
t_check('id EXPIRED (GET)',      vh_verdict(h_get("$base/verify.php?certificate_id={$expired['certId']}"), 'EXPIRED'));
t_check('id alias ?id= VALID',   vh_verdict(h_get("$base/verify.php?id=" . strtolower($valid['certId'])), 'VALID'));
t_check('unknown id INVALID',    vh_verdict(h_get("$base/verify.php?certificate_id=CV-2026-999999"), 'INVALID'));
$mal = h_get("$base/verify.php?certificate_id=" . rawurlencode('<script>x</script>'));
t_check('malformed id INVALID',  vh_verdict($mal, 'INVALID'));
t_check('malformed id not reflected raw', $mal !== null && !str_contains($mal, '<script>x</script>'));

// ── POST needs a CSRF token (session cookie + token from the form) ────
$jar = tempnam(sys_get_temp_dir(), 'cvjar');
function h_session($url, $jar, $post = null) {
    $ch = curl_init($url);
    $opts = [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 30, CURLOPT_COOKIEJAR => $jar, CURLOPT_COOKIEFILE => $jar];
    if ($post !== null) { $opts[CURLOPT_POST] = true; $opts[CURLOPT_POSTFIELDS] = $post; }
    curl_setopt_array($ch, $opts);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return [$code, $body === false ? null : $body];
}
[, $land] = h_session("$base/verify.php", $jar);
preg_match('/name="csrf_token" value="([^"]+)"/', (string)$land, $m);
$csrf = $m[1] ?? '';
t_check('landing renders a CSRF token', $csrf !== '');
[, $post] = h_session("$base/verify.php", $jar, ['csrf_token' => $csrf, 'certificate_id' => $valid['certId']]);
t_check('POST certificate_id with CSRF VALID', vh_verdict($post, 'VALID'));
[$noCsrfCode, $noCsrf] = h_session("$base/verify.php", $jar, ['csrf_token' => 'forged', 'smart_id' => $valid['certId']]);
t_check('POST with a forged CSRF token refused (403)', $noCsrfCode === 403 && !vh_verdict($noCsrf, 'VALID'));

// ── Browser-decoded QR fallback (privacy mode: hash + QR text only) ──
$qrText = "$base/verify.php?token={$valid['token']}";
[, $qr] = h_session("$base/verify.php", $jar, ['csrf_token' => $csrf, 'smart_hash' => str_repeat('0', 64), 'smart_qr_text' => $qrText]);
t_check('privacy hash miss + browser QR -> VALID', vh_verdict($qr, 'VALID'));
t_check('browser-QR result says the file is not byte-exact', $qr !== null && str_contains($qr, 'not a byte-exact copy'));
[, $qrNone] = h_session("$base/verify.php", $jar, ['csrf_token' => $csrf, 'smart_hash' => str_repeat('1', 64), 'smart_qr_text' => 'https://evil.example/not-ours']);
t_check('privacy hash miss + foreign QR -> INVALID', vh_verdict($qrNone, 'INVALID'));
@unlink($jar);

// ── Landing page: Smart Verify panel + external scripts only ─────────
foreach (['id="smartVerifyForm"', 'id="smart_id"', 'id="smart_file"', 'id="scanQrBtn"', 'id="privacyHashToggle"',
          'assets/js/smart-verify.js', 'assets/js/html5-qrcode.min.js', 'data-pdf-worker="assets/js/vendor/pdf.worker.min.js"'] as $needle) {
    t_check("landing exposes $needle", $land !== null && str_contains($land, $needle));
}
t_check('landing has no inline <script> blocks', $land !== null && preg_match('/<script\b(?![^>]*\bsrc\s*=)[^>]*>/i', $land) === 0);
foreach (['assets/js/smart-verify.js', 'assets/js/vendor/pdf.min.js', 'assets/js/vendor/pdf.worker.min.js'] as $asset) {
    [$code] = h_session("$base/$asset", $jar);
    t_check("asset served: $asset", $code === 200);
}

// ── Cleanup ───────────────────────────────────────────────────────────
proc_terminate($proc);
proc_close($proc);

$db->prepare('UPDATE certificates SET superseded_by_id = NULL WHERE institution_id = :i')->execute(['i' => $instId]);
$db->prepare('DELETE FROM certificates WHERE institution_id = :i')->execute(['i' => $instId]);
$db->prepare('DELETE FROM institutions WHERE id = :i')->execute(['i' => $instId]);
$db->prepare('DELETE FROM students WHERE id = :i')->execute(['i' => $studentId]);
$db->prepare('DELETE FROM users WHERE id IN (:a, :s)')->execute(['a' => $adminUid, 's' => $studentUid]);
$db->prepare("DELETE FROM verify_rate WHERE ip = '127.0.0.1'")->execute();
foreach ($createdFiles as $f) { @unlink($f); }

exit(t_summary('test_verify_http') ? 0 : 1);
