<?php
// tests/seed_browser_fixtures.php
// Creates (or removes with --clean) a stable set of fixtures in the test
// database so the browser responsive checker can load authenticated pages:
//   - an approved institution admin  (Browser Fixture Uni)
//   - a verified student
//   - one active certificate with a valid QR token + file + hash + signature
// Prints the values the checker needs (certificate id, QR token, db id).
//
// Only ever touches the CV_TEST_DB database, never production data.

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die("CLI only.\n");
}

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/services/CryptoService.php';

$db = test_db();
$clean = in_array('--clean', $argv, true);

$adminEmail = 'browser.admin@example.com';
$studentEmail = 'browser.student@example.com';
$password = 'Password1!';
$instName = 'Browser Fixture Uni';

/** Remove the fixture set (children first). */
function seed_cleanup($db, $adminEmail, $studentEmail, $instName) {
    $st = $db->prepare('SELECT id FROM institutions WHERE name = :n');
    $st->execute(['n' => $instName]);
    $instIds = $st->fetchAll(PDO::FETCH_COLUMN);
    foreach ($instIds as $iid) {
        $db->prepare('UPDATE certificates SET superseded_by_id = NULL, previous_version_id = NULL WHERE institution_id = :i')->execute(['i' => $iid]);
        $db->prepare('DELETE FROM certificates WHERE institution_id = :i')->execute(['i' => $iid]);
    }
    $db->prepare('DELETE FROM students WHERE full_name = "Browser Student"')->execute();
    $db->prepare('DELETE FROM institutions WHERE name = :n')->execute(['n' => $instName]);
    $db->prepare('DELETE FROM users WHERE email IN (:a, :s)')->execute(['a' => $adminEmail, 's' => $studentEmail]);
}

seed_cleanup($db, $adminEmail, $studentEmail, $instName);
if ($clean) {
    echo "browser fixtures removed\n";
    exit(0);
}

$hash = password_hash($password, PASSWORD_BCRYPT);

// Admin + approved institution with a signing key pair.
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, :h, "admin", 1)')
   ->execute(['e' => $adminEmail, 'h' => $hash]);
$adminUid = (int)$db->lastInsertId();
$keys = CryptoService::generateRSAKeyPair();
$db->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:u, :n, "approved")')
   ->execute(['u' => $adminUid, 'n' => $instName]);
$instId = (int)$db->lastInsertId();
test_insert_institution_key($db, $instId, $keys['public_key'], CryptoService::encryptPrivateKey($keys['private_key']));

// Verified student.
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, :h, "student", 1)')
   ->execute(['e' => $studentEmail, 'h' => $hash]);
$studentUid = (int)$db->lastInsertId();
$db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "Browser Student")')->execute(['u' => $studentUid]);
$studentId = (int)$db->lastInsertId();

// A valid certificate so the result/detail pages render fully.
$cid = 'CV-2026-700001';
$qr = rtrim(strtr(base64_encode(hash('sha256', 'browser-fixture', true)), '+/', '-_'), '=');
$filename = 'browser-fixture.pdf';
$path = __DIR__ . '/../private_data/uploads/' . $filename;
file_put_contents($path, "%PDF-1.4\nbrowser fixture\n" . str_repeat('B', 300));
$certData = [
    'certificate_id' => $cid,
    'institution_id' => $instId,
    'student_id'     => $studentId,
    'title'          => 'Browser Fixture Degree',
    'issue_date'     => '2024-01-01',
    'expiry_date'    => '2099-01-01',
];
$certHash = CryptoService::computeCertificateHash($certData, $path);
$certSig = CryptoService::signCertificateHash($certHash, $keys['private_key']);
$db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, expiry_date, file_path, status, version, qr_token, sha256_hash, digital_signature)
              VALUES (:cid, :iid, :sid, "Browser Fixture Degree", "2024-01-01", "2099-01-01", :fp, "active", 1, :qr, :h, :s)')
   ->execute(['cid' => $cid, 'iid' => $instId, 'sid' => $studentId, 'fp' => $filename, 'qr' => $qr, 'h' => $certHash, 's' => $certSig]);
$certDbId = (int)$db->lastInsertId();

echo "ADMIN_EMAIL=$adminEmail\n";
echo "STUDENT_EMAIL=$studentEmail\n";
echo "PASSWORD=$password\n";
echo "CERT_DB_ID=$certDbId\n";
echo "CERT_ID=$cid\n";
echo "QR_TOKEN=$qr\n";
