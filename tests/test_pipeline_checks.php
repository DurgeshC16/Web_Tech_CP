<?php
// tests/test_pipeline_checks.php — end-to-end verification pipeline
// against the isolated test database: issue a certificate, then assert
// each verdict (VALID -> TAMPERED -> REVOKED, plus EXPIRED and INVALID).
// Run: php tests/test_pipeline_checks.php
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/services/VerificationService.php';

$db = test_db();

// -- Fixtures (unique per run) ----------------------------------------
$tag = bin2hex(random_bytes(4));
$admin_email = "tv-admin-$tag@example.com";
$student_email = "tv-student-$tag@example.com";
$cid = 'CV-2026-900001';
$qr = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

$db->beginTransaction();
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, :h, "admin", 1)')
   ->execute(['e' => $admin_email, 'h' => password_hash('x', PASSWORD_BCRYPT)]);
$admin_uid = $db->lastInsertId();

$keys = CryptoService::generateRSAKeyPair();
$db->prepare('INSERT INTO institutions (user_id, name, status, public_key, encrypted_private_key) VALUES (:u, "TV Uni", "approved", :pub, :priv)')
   ->execute(['u' => $admin_uid, 'pub' => $keys['public_key'], 'priv' => CryptoService::encryptPrivateKey($keys['private_key'])]);
$inst_id = $db->lastInsertId();

$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, :h, "student", 1)')
   ->execute(['e' => $student_email, 'h' => password_hash('x', PASSWORD_BCRYPT)]);
$student_uid = $db->lastInsertId();
$db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "TV Student")')
   ->execute(['u' => $student_uid]);
$student_id = $db->lastInsertId();

// Stored file must live where VerificationService looks for it.
$filename = "tv-$tag.pdf";
$filepath = __DIR__ . '/../private_data/uploads/' . $filename;
$original = "%PDF-1.4\n1 0 obj<</>>endobj test $tag\n" . str_repeat('T', 200);
file_put_contents($filepath, $original);

$certData = [
    'certificate_id' => $cid,
    'institution_id' => $inst_id,
    'student_id'     => $student_id,
    'title'          => 'TV Degree',
    'issue_date'     => '2024-05-01',
    'expiry_date'    => '2030-05-01',
];
$hash = CryptoService::computeCertificateHash($certData, $filepath);
$sig = CryptoService::signCertificateHash($hash, $keys['private_key']);
$db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, expiry_date, file_path, status, version, qr_token, sha256_hash, digital_signature)
              VALUES (:cid, :iid, :sid, "TV Degree", "2024-05-01", "2030-05-01", :fp, "active", 1, :qr, :hash, :sig)')
   ->execute(['cid' => $cid, 'iid' => $inst_id, 'sid' => $student_id, 'fp' => $filename, 'qr' => $qr, 'hash' => $hash, 'sig' => $sig]);
$db->commit();

$check = function ($label, $token, $want) use ($db) {
    $cert = VerificationService::findByToken($db, $token);
    if (!$cert) {
        t_check("$label => INVALID", $want === 'INVALID');
        return;
    }
    $r = VerificationService::verify($db, $cert);
    t_check("$label => $want (got {$r['verdict']})", $r['verdict'] === $want);
};

// -- Verdict cascade --------------------------------------------------
$check('fresh certificate', $qr, 'VALID');

file_put_contents($filepath, $original . 'TAMPERED');
$check('altered file', $qr, 'TAMPERED');

file_put_contents($filepath, $original); // restore bytes
$db->prepare('UPDATE certificates SET status = "revoked" WHERE certificate_id = :c')->execute(['c' => $cid]);
$check('revoked (bytes intact)', $qr, 'REVOKED');

file_put_contents($filepath, $original . 'TAMPERED'); // tamper again: revoked still wins
$check('revoked + tampered', $qr, 'REVOKED');

file_put_contents($filepath, $original); // restore bytes FIRST — the hash covers file content
$pastData = $certData;
$pastData['expiry_date'] = '2020-01-01';
$pastHash = CryptoService::computeCertificateHash($pastData, $filepath);
$pastSig = CryptoService::signCertificateHash($pastHash, $keys['private_key']);
$db->prepare('UPDATE certificates SET status = "active", expiry_date = "2020-01-01", sha256_hash = :h, digital_signature = :s WHERE certificate_id = :c')
   ->execute(['h' => $pastHash, 's' => $pastSig, 'c' => $cid]);
$check('past expiry', $qr, 'EXPIRED');

$check('unknown token', 'no-such-token-aaaaaaaaaaaaaaaaaaaaaaaaaaa', 'INVALID');

// -- Cleanup (certificates first: their FKs have no cascade) ----------
@unlink($filepath);
$db->prepare('DELETE FROM certificates WHERE certificate_id = :c')->execute(['c' => $cid]);
$db->prepare('DELETE FROM users WHERE email IN (:a, :s)')->execute(['a' => $admin_email, 's' => $student_email]);
t_check('fixture file removed', !file_exists($filepath));

exit(t_summary('test_pipeline_checks') ? 0 : 1);