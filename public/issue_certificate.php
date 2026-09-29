<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

require_role('admin');

$db = Database::getInstance();
$error = '';
$success = '';

// Get Institution ID for the logged-in user
$stmt = $db->prepare('SELECT id FROM institutions WHERE user_id = :user_id LIMIT 1');
$stmt->execute(['user_id' => $_SESSION['user_id']]);
$institution = $stmt->fetch();
$institution_id = $institution['id'] ?? null;

if (!$institution_id) {
    show_error_page('Error', 'Institution profile not found.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    $student_email = sanitize_input($_POST['student_email'] ?? '');
    $student_name = sanitize_input($_POST['student_name'] ?? '');
    $title = sanitize_input($_POST['title'] ?? '');
    $issue_date = sanitize_input($_POST['issue_date'] ?? '');
    $expiry_date = sanitize_input($_POST['expiry_date'] ?? '');
    
    // File details
    $file = $_FILES['certificate_file'] ?? null;
    
    // Validation
    if (empty($student_email) || empty($student_name) || empty($title) || empty($issue_date) || !$file || $file['error'] !== UPLOAD_ERR_OK) {
        $error = 'All fields including the certificate file are required.';
    } elseif ($expiry_date && strtotime($expiry_date) <= strtotime($issue_date)) {
        $error = 'Expiry date must be after the issue date.';
    } else {
        // File validation
        $allowed_types = ['application/pdf', 'image/png', 'image/jpeg'];
        $max_size = 5 * 1024 * 1024; // 5MB
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
                
                // 1. Resolve Student
                $stmt = $db->prepare('SELECT s.id FROM users u JOIN students s ON u.id = s.user_id WHERE u.email = :email LIMIT 1');
                $stmt->execute(['email' => $student_email]);
                $student_id = $stmt->fetchColumn();
                
                if (!$student_id) {
                    // Create inline
                    $temp_password = password_hash(bin2hex(random_bytes(8)), PASSWORD_BCRYPT);
                    $stmt = $db->prepare('INSERT INTO users (email, password_hash, role) VALUES (:email, :hash, "student")');
                    $stmt->execute(['email' => $student_email, 'hash' => $temp_password]);
                    $new_user_id = $db->lastInsertId();
                    
                    $stmt = $db->prepare('INSERT INTO students (user_id, full_name) VALUES (:user_id, :full_name)');
                    $stmt->execute(['user_id' => $new_user_id, 'full_name' => $student_name]);
                    $student_id = $db->lastInsertId();
                }
                
                // 2. Generate Certificate ID
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
                $cert_id = sprintf("CV-%s-%06d", $year, $num);
                
                // 3. Save File
                $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
                $filename = $cert_id . '_' . time() . '.' . $ext;
                $upload_dir = __DIR__ . '/../private_data/uploads/';
                $destination = $upload_dir . $filename;
                
                if (!move_uploaded_file($file['tmp_name'], $destination)) {
                    throw new Exception('Failed to move uploaded file.');
                }
                
                // 4. Generate QR Token and QR Code
                require_once __DIR__ . '/../src/services/QRService.php';
                require_once __DIR__ . '/../src/services/CryptoService.php';
                $qr_token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
                $verify_url = BASE_URL . "/verify.php?token=" . $qr_token;
                $qr_path = __DIR__ . "/qrcodes/" . $qr_token . ".png";
                QRService::generateQRCode($verify_url, $qr_path);
                
                // 5. Compute SHA-256 hash of canonical certificate data
                $certData = [
                    'certificate_id' => $cert_id,
                    'institution_id' => $institution_id,
                    'student_id' => $student_id,
                    'title' => $title,
                    'issue_date' => $issue_date,
                    'expiry_date' => $expiry_date ?: null,
                ];
                $sha256_hash = CryptoService::computeCertificateHash($certData, $destination);
                
                // 6. Sign the hash with institution's RSA private key
                $instStmt = $db->prepare('SELECT encrypted_private_key FROM institutions WHERE id = :id');
                $instStmt->execute(['id' => $institution_id]);
                $encPrivKey = $instStmt->fetchColumn();
                $privateKey = CryptoService::decryptPrivateKey($encPrivKey);
                $digital_signature = CryptoService::signCertificateHash($sha256_hash, $privateKey);
                
                // 7. Insert Certificate with hash, signature, and QR token
                $stmt = $db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, expiry_date, file_path, status, version, qr_token, sha256_hash, digital_signature) VALUES (:cid, :iid, :sid, :title, :issue, :expiry, :path, "active", 1, :qr_token, :hash, :sig)');
                $stmt->execute([
                    'cid' => $cert_id,
                    'iid' => $institution_id,
                    'sid' => $student_id,
                    'title' => $title,
                    'issue' => $issue_date,
                    'expiry' => $expiry_date ?: null,
                    'path' => $filename,
                    'qr_token' => $qr_token,
                    'hash' => $sha256_hash,
                    'sig' => $digital_signature
                ]);
                
                $db->commit();
                $success = "Certificate successfully issued! Certificate ID: " . $cert_id;
                $success_qr_token = $qr_token;
            } catch (Exception $e) {
                $db->rollBack();
                $error = 'Error issuing certificate: ' . $e->getMessage();
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Issue Certificate - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container">
        <h2>Issue Certificate</h2>
        <a href="admin_dashboard.php" class="btn" style="float: right; margin-top: -40px;">Back to Dashboard</a>
        
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success">
                <strong>Success!</strong> <?= htmlspecialchars($success) ?>
            </div>
            
            <div style="text-align: center; margin: 20px 0; border: 1px solid #ccc; padding: 20px; border-radius: 8px;">
                <h3>Certificate QR Code</h3>
                <p>This QR code can be scanned by employers to verify the certificate's authenticity.</p>
                <img src="qrcodes/<?= htmlspecialchars($success_qr_token) ?>.png" alt="QR Code" style="max-width: 250px; border: 1px solid #eee;">
                <br>
                <a href="qrcodes/<?= htmlspecialchars($success_qr_token) ?>.png" download="Certificate_QR.png" class="btn" style="margin-top: 15px;">Download QR Code (PNG)</a>
            </div>
            
            <a href="issue_certificate.php" class="btn">Issue Another</a>
        <?php else: ?>
        
        <form method="POST" action="" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            
            <div class="form-group">
                <label>Student Email:</label>
                <input type="email" name="student_email" required>
                <small>If student does not exist, an account will be created automatically.</small>
            </div>
            <div class="form-group">
                <label>Student Full Name:</label>
                <input type="text" name="student_name" required>
            </div>
            <div class="form-group">
                <label>Certificate Title (e.g., Bachelor of Science in Computer Science):</label>
                <input type="text" name="title" required>
            </div>
            <div class="form-group">
                <label>Issue Date:</label>
                <input type="date" name="issue_date" required>
            </div>
            <div class="form-group">
                <label>Expiry Date (Optional):</label>
                <input type="date" name="expiry_date">
            </div>
            <div class="form-group">
                <label>Certificate File (PDF, PNG, JPG - Max 5MB):</label>
                <input type="file" name="certificate_file" accept=".pdf, .png, .jpg, .jpeg" required>
            </div>
            
            <button type="submit" class="btn">Issue Certificate</button>
        </form>
        <?php endif; ?>
    </div>
</body>
</html>
