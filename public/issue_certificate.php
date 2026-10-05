<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

require_role('admin');
require_approved_institution();

$db = Database::getInstance();
$error = '';
$errors = [];
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
    $errors = [];

    // File details
    $file = $_FILES['certificate_file'] ?? null;

    // Validation
    if (($e = v_required($student_email, 'Student Email')) !== true) { $errors['student_email'] = $e; }
    elseif (($e = v_email($student_email)) !== true) { $errors['student_email'] = $e; }
    if (($e = v_required($student_name, 'Student Full Name')) !== true) { $errors['student_name'] = $e; }
    elseif (($e = v_person_name($student_name)) !== true) { $errors['student_name'] = $e; }
    if (($e = v_required($title, 'Certificate Title')) !== true) { $errors['title'] = $e; }
    elseif (($e = v_length($title, 3, 200, 'Certificate Title')) !== true) { $errors['title'] = $e; }
    if (($e = v_required($issue_date, 'Issue Date')) !== true) {
        $errors['issue_date'] = $e;
    } else {
        $dr = v_date_range($issue_date, $expiry_date ?: null);
        if ($dr !== true) {
            $errors[strpos($dr, 'Expiry') === 0 ? 'expiry_date' : 'issue_date'] = $dr;
        }
    }
    if (($file_e = v_upload($file)) !== true) { $errors['certificate_file'] = $file_e; }

    if (!empty($errors)) {
        $error = 'Please correct the highlighted fields below.';
    } else {
            $destination = null;
            $qr_path = null;
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
                    $new_student_user_id = $new_user_id; // remember for activation email/OTP after commit
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
                $instStmt = $db->prepare('SELECT public_key, encrypted_private_key FROM institutions WHERE id = :id');
                $instStmt->execute(['id' => $institution_id]);
                $instKeys = $instStmt->fetch();
                try {
                    $privateKey = CryptoService::decryptPrivateKey($instKeys['encrypted_private_key'] ?? '');
                    if (!empty($instKeys['public_key']) && !CryptoService::verifyKeyPair($privateKey, $instKeys['public_key'])) {
                        throw new Exception('Stored private key does not match the stored public key.');
                    }
                    while (openssl_error_string()) {}
                    $digital_signature = CryptoService::signCertificateHash($sha256_hash, $privateKey);
                } catch (Exception $keyException) {
                    error_log('[CertiVault] Institution ' . (int)$institution_id . ' signing key error: ' . $keyException->getMessage());
                    throw new Exception('This institution\'s signing key is not available. Please contact the platform administrator.');
                }
                
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

                // For a brand-new inline student account, send an activation
                // OTP. The student sets their real password and activates via
                // activate_account.php — no orphaned accounts.
                if (!empty($new_student_user_id)) {
                    $activate_url = BASE_URL . '/activate_account.php?user_id=' . $new_student_user_id;
                    $otp_result = create_otp($db, $new_student_user_id, 'activation', $activate_url);
                    if ($otp_result === 'sent') {
                        $activation_msg = 'Activation email sent to ' . htmlspecialchars(mask_email($student_email)) . '.';
                    } else {
                        $activation_msg = "We couldn't send the activation email right now. The student can request a new code from the login page.";
                    }
                }
            } catch (Exception $e) {
                $db->rollBack();
                $error = 'Error issuing certificate: ' . $e->getMessage();
                // Remove orphaned files left behind by a failed issue attempt
                if ($destination && is_file($destination)) { @unlink($destination); }
                if ($qr_path && is_file($qr_path)) { @unlink($qr_path); }
            }
        }
    }
?>
<?php $page_title = 'Issue Certificate - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="container shell-wide">
        <div class="page-head">
            <h2>Issue Certificate</h2>
            <a href="admin_dashboard.php" class="btn btn-secondary">Back to Dashboard</a>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">Please correct the highlighted fields below.</div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success">
                <strong>Success!</strong> <?= htmlspecialchars($success) ?>
                <?php if (!empty($activation_msg)): ?>
                    <p><?= $activation_msg ?></p>
                <?php endif; ?>
            </div>
            
            <div class="seal-frame">
                <h3>Certificate QR — Digital Seal</h3>
                <p>This QR code can be scanned by employers to verify the certificate's authenticity.</p>
                <img src="qrcodes/<?= htmlspecialchars($success_qr_token) ?>.png" alt="QR Code">
                <br>
                <a href="qrcodes/<?= htmlspecialchars($success_qr_token) ?>.png" download="Certificate_QR.png" class="btn btn-primary">Download QR Code (PNG)</a>
            </div>

            <a href="issue_certificate.php" class="btn btn-secondary">Issue Another</a>
        <?php else: ?>
        
        <form method="POST" action="" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            
            <div class="form-row">
            <div class="form-group">
                <label>Student Email:</label>
                <input type="email" name="student_email" value="<?= htmlspecialchars($student_email ?? '') ?>" data-validate="required|email" required>
                <small>If student does not exist, an account will be created automatically.</small>
                <?php render_field_error($errors, 'student_email'); ?>
            </div>
            <div class="form-group">
                <label>Student Full Name:</label>
                <input type="text" name="student_name" value="<?= htmlspecialchars($student_name ?? '') ?>" data-validate="required|personname" required>
                <?php render_field_error($errors, 'student_name'); ?>
            </div>
            </div>
            <div class="form-group">
                <label>Certificate Title (e.g., Bachelor of Science in Computer Science):</label>
                <input type="text" name="title" value="<?= htmlspecialchars($title ?? '') ?>" data-validate="required|min:3|max:200" required>
                <?php render_field_error($errors, 'title'); ?>
            </div>
            <div class="form-row">
            <div class="form-group">
                <label>Issue Date:</label>
                <input type="date" name="issue_date" id="issue_date" value="<?= htmlspecialchars($issue_date ?? '') ?>" data-validate="required|daterange" required>
                <?php render_field_error($errors, 'issue_date'); ?>
            </div>
            <div class="form-group">
                <label>Expiry Date (Optional):</label>
                <input type="date" name="expiry_date" value="<?= htmlspecialchars($expiry_date ?? '') ?>" data-validate="after:#issue_date">
                <?php render_field_error($errors, 'expiry_date'); ?>
            </div>
            </div>
            <div class="form-group">
                <label>Certificate File (PDF, PNG, JPG - Max 5MB):</label>
                <input type="file" name="certificate_file" id="certificate_file" accept=".pdf, .png, .jpg, .jpeg" data-validate="upload" required>
                <small class="file-name-display" id="file_name_display"></small>
                <?php render_field_error($errors, 'certificate_file'); ?>
            </div>
            <script>
            document.getElementById('certificate_file').addEventListener('change', function (e) {
                var f = e.target.files[0];
                var el = document.getElementById('file_name_display');
                if (f) { el.textContent = f.name + ' — ' + (f.size / 1024).toFixed(1) + ' KB'; } else { el.textContent = ''; }
            });
            </script>

            <button type="submit" class="btn btn-primary">Issue Certificate</button>
        </form>
        <?php endif; ?>
    </div>
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
