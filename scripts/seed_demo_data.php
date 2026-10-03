<?php
// scripts/seed_demo_data.php
// -------------------------------------------------------------------------
// Seeds realistic demo data for a live demo. Uses the EXACT same pipeline as
// the real issuance flow (CryptoService + QRService) so every certificate's
// hash, signature and QR code are real and will verify correctly.
//
// Idempotent: safe to run repeatedly; existing rows (matched by fixed
// email/name/title) are reused, not duplicated.
//
// Usage:  php scripts/seed_demo_data.php
// -------------------------------------------------------------------------

if (!getenv('OPENSSL_CONF') && file_exists('C:\\xampp\\php\\extras\\openssl\\openssl.cnf')) {
    // CLI on Windows often lacks the OpenSSL config path that Apache has;
    // without it openssl_pkey_new() (CryptoService key generation) fails.
    putenv('OPENSSL_CONF=C:\\xampp\\php\\extras\\openssl\\openssl.cnf');
}

require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/QRService.php';

const DEMO_INST_EMAIL = 'demo.institution@certivault.test';
const DEMO_INST_PASSWORD = 'DemoInst@2026';
const DEMO_STUDENT_EMAIL = 'demo.student@certivault.test';
const DEMO_STUDENT_PASSWORD = 'DemoStudent@2026';

$db = Database::getInstance();
$root = dirname(__DIR__);
$uploads_dir = $root . '/private_data/uploads';
$qr_dir = $root . '/public/qrcodes';
@mkdir($uploads_dir, 0777, true);
@mkdir($qr_dir, 0777, true);

// ── 1. Demo institution ─────────────────────────────────────────────
$stmt = $db->prepare('SELECT id FROM users WHERE email = :email');
$stmt->execute(['email' => DEMO_INST_EMAIL]);
$inst_user_id = $stmt->fetchColumn();

if (!$inst_user_id) {
    $hash = password_hash(DEMO_INST_PASSWORD, PASSWORD_BCRYPT);
    $stmt = $db->prepare("INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, :h, 'admin', 1)");
    $stmt->execute(['e' => DEMO_INST_EMAIL, 'h' => $hash]);
    $inst_user_id = $db->lastInsertId();

    // Same key generation/encryption as super_admin.php's approval flow.
    $keys = CryptoService::generateRSAKeyPair();
    $encryptedPriv = CryptoService::encryptPrivateKey($keys['private_key']);
    $stmt = $db->prepare("INSERT INTO institutions (user_id, name, status, public_key, encrypted_private_key) VALUES (:uid, :name, 'approved', :pub, :priv)");
    $stmt->execute(['uid' => $inst_user_id, 'name' => 'Demo Institute of Technology', 'pub' => $keys['public_key'], 'priv' => $encryptedPriv]);
    echo "[+] Created demo institution (user id $inst_user_id)\n";
} else {
    echo "[=] Demo institution already exists (user id $inst_user_id)\n";
}

$stmt = $db->prepare('SELECT id FROM institutions WHERE user_id = :uid LIMIT 1');
$stmt->execute(['uid' => $inst_user_id]);
$institution_id = $stmt->fetchColumn();
if (!$institution_id) {
    // User existed but no institution row (e.g. a previously interrupted run)
    // — finish the same "approval" provisioning here.
    $keys = CryptoService::generateRSAKeyPair();
    $encryptedPriv = CryptoService::encryptPrivateKey($keys['private_key']);
    $stmt = $db->prepare("INSERT INTO institutions (user_id, name, status, public_key, encrypted_private_key) VALUES (:uid, :name, 'approved', :pub, :priv)");
    $stmt->execute(['uid' => $inst_user_id, 'name' => 'Demo Institute of Technology', 'pub' => $keys['public_key'], 'priv' => $encryptedPriv]);
    $institution_id = $db->lastInsertId();
    echo "[+] Created missing institution row for existing user\n";
} else {
    $institution_id = (int)$institution_id;
}

// ── 2. Demo student ─────────────────────────────────────────────────
$stmt = $db->prepare('SELECT id FROM users WHERE email = :email');
$stmt->execute(['email' => DEMO_STUDENT_EMAIL]);
$student_user_id = $stmt->fetchColumn();

if (!$student_user_id) {
    $hash = password_hash(DEMO_STUDENT_PASSWORD, PASSWORD_BCRYPT);
    $stmt = $db->prepare("INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, :h, 'student', 1)");
    $stmt->execute(['e' => DEMO_STUDENT_EMAIL, 'h' => $hash]);
    $student_user_id = $db->lastInsertId();
    $stmt = $db->prepare("INSERT INTO students (user_id, full_name, enrollment_number) VALUES (:uid, 'Demo Student', 'DEMO-2026-001')");
    $stmt->execute(['uid' => $student_user_id]);
    echo "[+] Created demo student (user id $student_user_id)\n";
} else {
    echo "[=] Demo student already exists (user id $student_user_id)\n";
}

$stmt = $db->prepare('SELECT id FROM students WHERE user_id = :uid LIMIT 1');
$stmt->execute(['uid' => $student_user_id]);
$student_id = $stmt->fetchColumn();
if (!$student_id) {
    $stmt = $db->prepare("INSERT INTO students (user_id, full_name, enrollment_number) VALUES (:uid, 'Demo Student', 'DEMO-2026-001')");
    $stmt->execute(['uid' => $student_user_id]);
    $student_id = $db->lastInsertId();
    echo "[+] Created missing students row for existing user\n";
} else {
    $student_id = (int)$student_id;
}

// ── 3. Dummy certificate file ───────────────────────────────────────
$dummy_file = $uploads_dir . '/demo_placeholder.pdf';
if (!file_exists($dummy_file)) {
    file_put_contents($dummy_file, "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\nDemo placeholder certificate for CertiVault seed data.\n");
    echo "[+] Created dummy certificate file\n";
}

// ── Helpers mirroring the real issuance flow ────────────────────────
function next_cert_id($db) {
    $year = date('Y');
    $stmt = $db->prepare("SELECT certificate_id FROM certificates WHERE certificate_id LIKE :prefix ORDER BY id DESC LIMIT 1");
    $stmt->execute(['prefix' => "CV-$year-%"]);
    $lastId = $stmt->fetchColumn();
    $num = 1;
    if ($lastId) {
        $parts = explode('-', $lastId);
        $num = (int)end($parts) + 1;
    }
    return sprintf("CV-%s-%06d", $year, $num);
}

// Issues a certificate through the exact pipeline from issue_certificate.php.
// Returns the certificates row as an array.
function issue_cert($db, $institution_id, $student_id, $title, $issue_date, $expiry_date, $uploads_dir, $qr_dir) {
    $cert_id = next_cert_id($db);

    $filename = $cert_id . '_' . time() . '_' . bin2hex(random_bytes(3)) . '.pdf';
    $destination = $uploads_dir . '/' . $filename;
    copy($uploads_dir . '/demo_placeholder.pdf', $destination);

    $qr_token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $verify_url = BASE_URL . "/verify.php?token=" . $qr_token;
    QRService::generateQRCode($verify_url, $qr_dir . '/' . $qr_token . '.png');

    $certData = [
        'certificate_id' => $cert_id,
        'institution_id' => $institution_id,
        'student_id' => $student_id,
        'title' => $title,
        'issue_date' => $issue_date,
        'expiry_date' => $expiry_date ?: null,
    ];
    $sha256_hash = CryptoService::computeCertificateHash($certData, $destination);

    $stmt = $db->prepare('SELECT encrypted_private_key FROM institutions WHERE id = :id');
    $stmt->execute(['id' => $institution_id]);
    $privateKey = CryptoService::decryptPrivateKey($stmt->fetchColumn());
    $digital_signature = CryptoService::signCertificateHash($sha256_hash, $privateKey);

    $stmt = $db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, expiry_date, file_path, status, version, qr_token, sha256_hash, digital_signature) VALUES (:cid, :iid, :sid, :title, :issue, :expiry, :path, "active", 1, :qr, :hash, :sig)');
    $stmt->execute([
        'cid' => $cert_id, 'iid' => $institution_id, 'sid' => $student_id,
        'title' => $title, 'issue' => $issue_date, 'expiry' => $expiry_date ?: null,
        'path' => $filename, 'qr' => $qr_token, 'hash' => $sha256_hash, 'sig' => $digital_signature,
    ]);

    return ['id' => (int)$db->lastInsertId(), 'certificate_id' => $cert_id, 'qr_token' => $qr_token, 'version' => 1];
}

function find_cert_by_title($db, $title, $student_id, $institution_id, $version = null) {
    $sql = 'SELECT * FROM certificates WHERE title = :t AND student_id = :s AND institution_id = :i';
    if ($version !== null) $sql .= ' AND version = ' . (int)$version;
    $stmt = $db->prepare($sql . ' LIMIT 1');
    $stmt->execute(['t' => $title, 's' => $student_id, 'i' => $institution_id]);
    return $stmt->fetch() ?: null;
}

$seeded = [];

// ── 4a. Active, no expiry → VALID ───────────────────────────────────
$title = 'B.Sc. Computer Science';
$found = find_cert_by_title($db, $title, $student_id, $institution_id, 1);
if (!$found) {
    $found = issue_cert($db, $institution_id, $student_id, $title, date('Y-m-d', strtotime('-6 months')), null, $uploads_dir, $qr_dir);
    echo "[+] Seeded: $title\n";
} else { echo "[=] $title already present\n"; }
$seeded[] = ['cert' => $found, 'expected' => 'VALID'];

// ── 4b. Expired → EXPIRED ───────────────────────────────────────────
$title = 'AWS Cloud Practitioner';
$found = find_cert_by_title($db, $title, $student_id, $institution_id, 1);
if (!$found) {
    $found = issue_cert($db, $institution_id, $student_id, $title, date('Y-m-d', strtotime('-2 years')), date('Y-m-d', strtotime('-3 months')), $uploads_dir, $qr_dir);
    echo "[+] Seeded: $title\n";
} else { echo "[=] $title already present\n"; }
$seeded[] = ['cert' => $found, 'expected' => 'EXPIRED'];

// ── 4c. Revoked → REVOKED ───────────────────────────────────────────
$title = 'Internship Completion Certificate';
$found = find_cert_by_title($db, $title, $student_id, $institution_id, 1);
if (!$found) {
    $found = issue_cert($db, $institution_id, $student_id, $title, date('Y-m-d', strtotime('-3 months')), null, $uploads_dir, $qr_dir);
    echo "[+] Seeded: $title\n";
} else { echo "[=] $title already present\n"; }
$stmt = $db->prepare('SELECT status FROM certificates WHERE id = :id');
$stmt->execute(['id' => $found['id']]);
$status = $stmt->fetchColumn();
if ($status !== 'revoked') {
    $stmt = $db->prepare('UPDATE certificates SET status = "revoked", revocation_reason = :r WHERE id = :id');
    $stmt->execute(['r' => 'Seeded demo data — revoked for testing.', 'id' => $found['id']]);
    echo "[+] Revoked: $title\n";
}
$seeded[] = ['cert' => $found, 'expected' => 'REVOKED'];

// ── 4d. Version chain: v1 superseded, v2 active → SUPERSEDED / VALID ─
$title = 'Web Development Bootcamp';
$v1 = find_cert_by_title($db, $title, $student_id, $institution_id, 1);
if (!$v1) {
    $v1 = issue_cert($db, $institution_id, $student_id, $title, date('Y-m-d', strtotime('-8 months')), null, $uploads_dir, $qr_dir);
    echo "[+] Seeded v1: $title\n";
} else { echo "[=] $title v1 already present\n"; }

$v2 = find_cert_by_title($db, $title, $student_id, $institution_id, 2);
if (!$v2) {
    // Same supersede pipeline as supersede_certificate.php:
    $new_cert_id = next_cert_id($db);
    $new_version = 2;
    $filename = $new_cert_id . '_' . time() . '_' . bin2hex(random_bytes(3)) . '.pdf';
    $destination = $uploads_dir . '/' . $filename;
    copy($uploads_dir . '/demo_placeholder.pdf', $destination);

    $qr_token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $verify_url = BASE_URL . "/verify.php?token=" . $qr_token;
    QRService::generateQRCode($verify_url, $qr_dir . '/' . $qr_token . '.png');

    $issue_date = date('Y-m-d', strtotime('-2 months'));
    $certData = [
        'certificate_id' => $new_cert_id,
        'institution_id' => $institution_id,
        'student_id' => $student_id,
        'title' => $title,
        'issue_date' => $issue_date,
        'expiry_date' => null,
    ];
    $sha256_hash = CryptoService::computeCertificateHash($certData, $destination);
    $stmt = $db->prepare('SELECT encrypted_private_key FROM institutions WHERE id = :id');
    $stmt->execute(['id' => $institution_id]);
    $privateKey = CryptoService::decryptPrivateKey($stmt->fetchColumn());
    $digital_signature = CryptoService::signCertificateHash($sha256_hash, $privateKey);

    $stmt = $db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, expiry_date, file_path, status, version, previous_version_id, qr_token, sha256_hash, digital_signature) VALUES (:cid, :iid, :sid, :title, :issue, NULL, :path, "active", :ver, :prev, :qr, :hash, :sig)');
    $stmt->execute([
        'cid' => $new_cert_id, 'iid' => $institution_id, 'sid' => $student_id,
        'title' => $title, 'issue' => $issue_date, 'path' => $filename,
        'ver' => $new_version, 'prev' => $v1['id'], 'qr' => $qr_token,
        'hash' => $sha256_hash, 'sig' => $digital_signature,
    ]);
    $new_db_id = $db->lastInsertId();

    $stmt = $db->prepare('UPDATE certificates SET status = "superseded", superseded_by_id = :new WHERE id = :old');
    $stmt->execute(['new' => $new_db_id, 'old' => $v1['id']]);

    $v2 = ['id' => (int)$new_db_id, 'certificate_id' => $new_cert_id, 'qr_token' => $qr_token, 'version' => 2];
    echo "[+] Superseded v1 -> v2: $title\n";
} else { echo "[=] $title v2 already present\n"; }
$seeded[] = ['cert' => $v1, 'expected' => 'SUPERSEDED'];
$seeded[] = ['cert' => $v2, 'expected' => 'VALID'];

// ── 5. Summary ──────────────────────────────────────────────────────
echo "\n================ Demo Seed Summary ================\n";
echo "Institution login : " . DEMO_INST_EMAIL . " / " . DEMO_INST_PASSWORD . "\n";
echo "Student login     : " . DEMO_STUDENT_EMAIL . " / " . DEMO_STUDENT_PASSWORD . "\n\n";
printf("%-18s %-38s %-11s %-6s %s\n", 'certificate_id', 'title', 'status', 'ver.', 'qr_token');
foreach ($seeded as $row) {
    $c = $row['cert'];
    $stmt = $db->prepare('SELECT status, version, certificate_id, qr_token, title FROM certificates WHERE id = :id');
    $stmt->execute(['id' => $c['id']]);
    $fresh = $stmt->fetch();
    printf("%-18s %-38s %-11s v%-5s %s\n", $fresh['certificate_id'], $fresh['title'], $fresh['status'], $fresh['version'], $fresh['qr_token']);
    echo "   verify: " . BASE_URL . "/verify.php?token=" . $fresh['qr_token'] . "  (expect " . $row['expected'] . ")\n";
}
echo "====================================================\n";
