<?php
// tests/fixtures/make_verify_fixtures.php
// Builds everything the browser/HTTP verification tests need, in the
// isolated test database only:
//   - certificates with known QR tokens for each verdict
//   - QR PNG images (valid, bare token, foreign-origin, malformed, no-QR,
//     garbage) and certificate PDFs (single page, multi page, no QR, broken)
//   - a JSON manifest of tokens + absolute file paths
//
// Usage:
//   php tests/fixtures/make_verify_fixtures.php [--clean] [--base=http://127.0.0.1:8151]
//
// The QR payload origin MUST match the origin the browser test uses, so the
// client-side same-origin check can be exercised both ways.

if (php_sapi_name() !== 'cli') { http_response_code(403); die("CLI only.\n"); }

require_once __DIR__ . '/../bootstrap.php';
require_once __DIR__ . '/../../src/services/CryptoService.php';
require_once __DIR__ . '/../../src/services/QRService.php';
require_once __DIR__ . '/pdf_builder.php';

$opts = getopt('', ['clean', 'base::']);
$base = $opts['base'] ?? 'http://127.0.0.1:8151';
$base = rtrim($base, '/');
$outDir = __DIR__ . '/out';
$manifestPath = $outDir . '/manifest.json';

$db = test_db();
$instName = 'Verify UI Fixture Uni';
$adminEmail = 'verifyui.admin@example.com';

function vf_cleanup($db, $instName, $adminEmail) {
    $st = $db->prepare('SELECT id FROM institutions WHERE name = :n');
    $st->execute(['n' => $instName]);
    foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $iid) {
        $db->prepare('UPDATE certificates SET superseded_by_id = NULL, previous_version_id = NULL WHERE institution_id = :i')->execute(['i' => $iid]);
        $db->prepare('DELETE FROM certificates WHERE institution_id = :i')->execute(['i' => $iid]);
    }
    $db->prepare('DELETE FROM students WHERE full_name = "Verify UI Student"')->execute();
    $db->prepare('DELETE FROM institutions WHERE name = :n')->execute(['n' => $instName]);
    $db->prepare('DELETE FROM users WHERE email IN (:a, :s)')->execute(['a' => $adminEmail, 's' => 'verifyui.student@example.com']);
}

vf_cleanup($db, $instName, $adminEmail);

if (isset($opts['clean'])) {
    if (is_dir($outDir)) { array_map('unlink', glob($outDir . '/*') ?: []); }
    echo "verify fixtures removed\n";
    exit(0);
}

if (!is_dir($outDir)) { mkdir($outDir, 0777, true); }

// Clear this client's verification log rows so repeated test runs can never
// accumulate >30 distinct lookups and trip the (correct) rate limiter.
$db->prepare("DELETE FROM verification_logs WHERE verifier_ip = '127.0.0.1'")->execute();

function vf_token() { return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='); }

// ── Seed institution + student ────────────────────────────────────────
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "admin", 1)')->execute(['e' => $adminEmail]);
$adminUid = (int)$db->lastInsertId();
$keys = CryptoService::generateRSAKeyPair();
$db->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:u, :n, "approved")')
   ->execute(['u' => $adminUid, 'n' => $instName]);
$instId = (int)$db->lastInsertId();
test_insert_institution_key($db, $instId, $keys['public_key'], CryptoService::encryptPrivateKey($keys['private_key']));

$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "student", 1)')->execute(['e' => 'verifyui.student@example.com']);
$studentUid = (int)$db->lastInsertId();
$db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "Verify UI Student")')->execute(['u' => $studentUid]);
$studentId = (int)$db->lastInsertId();

// Insert a certificate row + real file; returns [dbId, token, certId, file].
function vf_cert($db, $instId, $studentId, $keys, $certId, $token, $status, $expiry, $title) {
    $filename = 'verifyui-' . $token . '.pdf';
    $path = __DIR__ . '/../../private_data/uploads/' . $filename;
    file_put_contents($path, "%PDF-1.4 fixture $token\n" . str_repeat('V', 240));
    $data = [
        'certificate_id' => $certId, 'institution_id' => $instId, 'student_id' => $studentId,
        'title' => $title, 'issue_date' => '2024-01-01', 'expiry_date' => $expiry,
    ];
    $hash = CryptoService::computeCertificateHash($data, $path);
    $sig  = CryptoService::signCertificateHash($hash, $keys['private_key']);
    $db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, expiry_date, file_path, status, version, qr_token, sha256_hash, digital_signature)
                  VALUES (:cid, :iid, :sid, :t, "2024-01-01", :exp, :fp, :st, 1, :qr, :h, :s)')
       ->execute(['cid' => $certId, 'iid' => $instId, 'sid' => $studentId, 't' => $title, 'exp' => $expiry, 'fp' => $filename, 'st' => $status, 'qr' => $token, 'h' => $hash, 's' => $sig]);
    return ['dbId' => (int)$db->lastInsertId(), 'token' => $token, 'certId' => $certId, 'file' => $filename];
}

$valid      = vf_cert($db, $instId, $studentId, $keys, 'CV-2026-880001', vf_token(), 'active', '2099-01-01', 'Valid Fixture Degree');
$expired    = vf_cert($db, $instId, $studentId, $keys, 'CV-2026-880002', vf_token(), 'active', '2020-01-01', 'Expired Fixture Degree');
$revoked    = vf_cert($db, $instId, $studentId, $keys, 'CV-2026-880003', vf_token(), 'revoked', '2099-01-01', 'Revoked Fixture Degree');
$newer      = vf_cert($db, $instId, $studentId, $keys, 'CV-2026-880004', vf_token(), 'active', '2099-01-01', 'Superseding Fixture Degree');
$superseded = vf_cert($db, $instId, $studentId, $keys, 'CV-2026-880005', vf_token(), 'superseded', '2099-01-01', 'Superseded Fixture Degree');
$db->prepare('UPDATE certificates SET superseded_by_id = :n WHERE id = :id')->execute(['n' => $newer['dbId'], 'id' => $superseded['dbId']]);
$tampered   = vf_cert($db, $instId, $studentId, $keys, 'CV-2026-880006', vf_token(), 'active', '2099-01-01', 'Tampered Fixture Degree');
// Alter the file AFTER hashing so the stored hash no longer matches.
file_put_contents(__DIR__ . '/../../private_data/uploads/' . $tampered['file'], "TAMPERED CONTENT\n" . str_repeat('X', 240));
$unknownToken = vf_token();

// ── QR images ─────────────────────────────────────────────────────────
function vf_qr($payload, $path) { QRService::generateQRCode($payload, $path); }

$qrValid    = "$outDir/qr_valid.png";
$qrBare     = "$outDir/qr_bare.png";
$qrForeign  = "$outDir/qr_foreign.png";
$qrMalformed = "$outDir/qr_malformed.png";
$qrNoQr     = "$outDir/qr_noqr.png";
$qrGarbage  = "$outDir/qr_garbage.png";

vf_qr($base . '/verify.php?token=' . $valid['token'], $qrValid);
vf_qr($valid['token'], $qrBare);
vf_qr('https://evil.example/verify.php?token=' . $valid['token'], $qrForeign);
vf_qr($base . '/verify.php?token=tooshort', $qrMalformed);

// A valid PNG image that contains no QR code.
$im = imagecreatetruecolor(240, 240);
imagefilledrectangle($im, 0, 0, 239, 239, imagecolorallocate($im, 240, 240, 240));
imagepng($im, $qrNoQr);
imagedestroy($im);

// A .png-named file that is not an image at all.
file_put_contents($qrGarbage, random_bytes(4096));

// ── PDFs ──────────────────────────────────────────────────────────────
$pdfOne   = "$outDir/cert_one.pdf";
$pdfMulti = "$outDir/cert_multi.pdf";
$pdfNoQr  = "$outDir/cert_noqr.pdf";
$pdfBroken = "$outDir/cert_broken.pdf";

file_put_contents($pdfOne,   cv_build_pdf([['png' => $qrValid]]));
file_put_contents($pdfMulti, cv_build_pdf([null, null, ['png' => $qrValid]])); // QR on page 3
file_put_contents($pdfNoQr,  cv_build_pdf([null, null]));
file_put_contents($pdfBroken, random_bytes(8192));

// ── Manifest ──────────────────────────────────────────────────────────
$manifest = [
    'base' => $base,
    'tokens' => [
        'valid' => $valid['token'], 'expired' => $expired['token'], 'revoked' => $revoked['token'],
        'superseded' => $superseded['token'], 'tampered' => $tampered['token'], 'unknown' => $unknownToken,
    ],
    'cert_ids' => [
        'valid' => $valid['certId'], 'expired' => $expired['certId'], 'revoked' => $revoked['certId'],
        'superseded' => $superseded['certId'], 'tampered' => $tampered['certId'],
        'malformed' => 'CV-2026-123', // wrong format
        'unknown' => 'CV-2026-999999',
    ],
    'qr' => [
        'valid' => $qrValid, 'bare' => $qrBare, 'foreign' => $qrForeign,
        'malformed' => $qrMalformed, 'noqr' => $qrNoQr, 'garbage' => $qrGarbage,
    ],
    'pdf' => ['one' => $pdfOne, 'multi' => $pdfMulti, 'noqr' => $pdfNoQr, 'broken' => $pdfBroken],
];
file_put_contents($manifestPath, json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

echo "verify fixtures written\n";
echo "manifest=$manifestPath\n";
echo "valid_token={$valid['token']}\n";
