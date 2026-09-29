<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/QRService.php';
require_role('admin');

$db = Database::getInstance();
$old_cert_id = (int)($_GET['id'] ?? 0);
$error = '';
$success = '';
$success_qr_token = '';

// Get Institution ID
$stmt = $db->prepare('SELECT id FROM institutions WHERE user_id = :user_id LIMIT 1');
$stmt->execute(['user_id' => $_SESSION['user_id']]);
$institution_id = $stmt->fetchColumn();

if (!$institution_id) {
    show_error_page('Error', 'Institution profile not found.');
}

// Fetch the old certificate, ensure ownership
$stmt = $db->prepare('
    SELECT c.*, s.full_name as student_name, u.email as student_email
    FROM certificates c
    JOIN students s ON c.student_id = s.id
    JOIN users u ON s.user_id = u.id
    WHERE c.id = :id AND c.institution_id = :inst_id
');
$stmt->execute(['id' => $old_cert_id, 'inst_id' => $institution_id]);
$old_cert = $stmt->fetch();

if (!$old_cert) {
    show_error_page('Not Found', 'Certificate not found or access denied.');
}

if ($old_cert['status'] !== 'active' && $old_cert['status'] !== 'expired') {
    $error = "Only active or expired certificates can be superseded (current status: {$old_cert['status']}).";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    $title = sanitize_input($_POST['title'] ?? '');
    $issue_date = sanitize_input($_POST['issue_date'] ?? '');
    $expiry_date = sanitize_input($_POST['expiry_date'] ?? '');
    $file = $_FILES['certificate_file'] ?? null;
    
    if (empty($title) || empty($issue_date) || !$file || $file['error'] !== UPLOAD_ERR_OK) {
        $error = 'All fields including the certificate file are required.';
    } elseif ($expiry_date && strtotime($expiry_date) <= strtotime($issue_date)) {
        $error = 'Expiry date must be after the issue date.';
    } else {
        // File validation
        $allowed_types = ['application/pdf', 'image/png', 'image/jpeg'];
        $max_size = 5 * 1024 * 1024;
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        if (!in_array($mime_type, $allowed_types)) {
            $error = 'Invalid file type. Only PDF, PNG, and JPG are allowed.';
        } elseif ($file['size'] > $max_size) {
            $error = 'File size exceeds the 5MB limit.';
        } else {
            try {
                $db->beginTransaction();
                
                // 1. Generate new Certificate ID
                $year = date('Y');
                $stmt = $db->prepare("SELECT certificate_id FROM certificates WHERE certificate_id LIKE :prefix ORDER BY id DESC LIMIT 1 FOR UPDATE");
                $stmt->execute(['prefix' => "CV-$year-%"]);
                $lastId = $stmt->fetchColumn();
                if ($lastId) {
                    $parts = explode('-', $lastId);
                    $num = (int)end($parts) + 1;
                } else {
                    $num = 1;
                }
                $new_cert_id = sprintf("CV-%s-%06d", $year, $num);
                $new_version = $old_cert['version'] + 1;
                
                // 2. Save File
                $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
                $filename = $new_cert_id . '_' . time() . '.' . $ext;
                $upload_dir = __DIR__ . '/../private_data/uploads/';
                $destination = $upload_dir . $filename;
                
                if (!move_uploaded_file($file['tmp_name'], $destination)) {
                    throw new Exception('Failed to move uploaded file.');
                }
                
                // 3. Generate QR Token and QR Code
                $qr_token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
                $verify_url = BASE_URL . "/verify.php?token=" . $qr_token;
                $qr_path = __DIR__ . "/qrcodes/" . $qr_token . ".png";
                QRService::generateQRCode($verify_url, $qr_path);
                
                // 4. Compute hash
                $certData = [
                    'certificate_id' => $new_cert_id,
                    'institution_id' => $institution_id,
                    'student_id' => $old_cert['student_id'],
                    'title' => $title,
                    'issue_date' => $issue_date,
                    'expiry_date' => $expiry_date ?: null,
                ];
                $sha256_hash = CryptoService::computeCertificateHash($certData, $destination);
                
                // 5. Sign
                $instStmt = $db->prepare('SELECT encrypted_private_key FROM institutions WHERE id = :id');
                $instStmt->execute(['id' => $institution_id]);
                $encPrivKey = $instStmt->fetchColumn();
                $privateKey = CryptoService::decryptPrivateKey($encPrivKey);
                $digital_signature = CryptoService::signCertificateHash($sha256_hash, $privateKey);
                
                // 6. Insert new certificate
                $stmt = $db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, expiry_date, file_path, status, version, previous_version_id, qr_token, sha256_hash, digital_signature) VALUES (:cid, :iid, :sid, :title, :issue, :expiry, :path, "active", :ver, :prev, :qr_token, :hash, :sig)');
                $stmt->execute([
                    'cid' => $new_cert_id,
                    'iid' => $institution_id,
                    'sid' => $old_cert['student_id'],
                    'title' => $title,
                    'issue' => $issue_date,
                    'expiry' => $expiry_date ?: null,
                    'path' => $filename,
                    'ver' => $new_version,
                    'prev' => $old_cert['id'],
                    'qr_token' => $qr_token,
                    'hash' => $sha256_hash,
                    'sig' => $digital_signature
                ]);
                $new_db_id = $db->lastInsertId();
                
                // 7. Mark old certificate as superseded and link to new one
                $stmt = $db->prepare('UPDATE certificates SET status = "superseded", superseded_by_id = :new_id WHERE id = :old_id');
                $stmt->execute(['new_id' => $new_db_id, 'old_id' => $old_cert['id']]);
                
                $db->commit();
                $success = "Certificate superseded! New Certificate ID: " . $new_cert_id . " (v" . $new_version . ")";
                $success_qr_token = $qr_token;
            } catch (Exception $e) {
                $db->rollBack();
                $error = 'Error superseding certificate: ' . $e->getMessage();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Supersede Certificate - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container" style="max-width: 650px;">
        <h2>Supersede / Correct Certificate</h2>
        <a href="view_certificate_admin.php?id=<?= $old_cert_id ?>" class="btn" style="float: right; margin-top: -40px;">Back</a>
        
        <div class="alert alert-info" style="margin-top: 10px;">
            <strong>Original Certificate:</strong> <?= htmlspecialchars($old_cert['certificate_id']) ?> (v<?= $old_cert['version'] ?>)<br>
            <strong>Title:</strong> <?= htmlspecialchars($old_cert['title']) ?><br>
            <strong>Student:</strong> <?= htmlspecialchars($old_cert['student_name']) ?> (<?= htmlspecialchars($old_cert['student_email']) ?>)
        </div>
        
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success">
                <strong>Success!</strong> <?= htmlspecialchars($success) ?><br>
                The original certificate (<?= htmlspecialchars($old_cert['certificate_id']) ?>) is now marked as <strong>superseded</strong>.
            </div>
            
            <div style="text-align: center; margin: 20px 0; border: 1px solid #ccc; padding: 20px; border-radius: 8px;">
                <h3>New Certificate QR Code</h3>
                <img src="qrcodes/<?= htmlspecialchars($success_qr_token) ?>.png" alt="QR Code" style="max-width: 250px; border: 1px solid #eee;">
                <br>
                <a href="qrcodes/<?= htmlspecialchars($success_qr_token) ?>.png" download="Certificate_QR.png" class="btn" style="margin-top: 15px;">Download QR Code (PNG)</a>
            </div>
            
            <a href="admin_dashboard.php" class="btn">Back to Dashboard</a>
        <?php elseif (in_array($old_cert['status'], ['active', 'expired'])): ?>
        
        <p>Submit the corrected certificate data below. The original will be preserved but marked as <strong>superseded</strong>.</p>
        
        <form method="POST" action="" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            
            <div class="form-group">
                <label>Corrected Certificate Title:</label>
                <input type="text" name="title" value="<?= htmlspecialchars($old_cert['title']) ?>" required>
            </div>
            <div class="form-group">
                <label>Issue Date:</label>
                <input type="date" name="issue_date" value="<?= htmlspecialchars($old_cert['issue_date']) ?>" required>
            </div>
            <div class="form-group">
                <label>Expiry Date (Optional):</label>
                <input type="date" name="expiry_date" value="<?= htmlspecialchars($old_cert['expiry_date'] ?? '') ?>">
            </div>
            <div class="form-group">
                <label>Updated Certificate File (PDF, PNG, JPG - Max 5MB):</label>
                <input type="file" name="certificate_file" accept=".pdf, .png, .jpg, .jpeg" required>
            </div>
            
            <button type="submit" class="btn" style="width: 100%; background-color: #fd7e14;">Issue Corrected Version</button>
        </form>
        <?php endif; ?>
    </div>
</body>
</html>
