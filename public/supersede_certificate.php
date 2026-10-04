<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/QRService.php';
require_role('admin');
require_approved_institution();

$db = Database::getInstance();
$old_cert_id = (int)($_GET['id'] ?? 0);
$error = '';
$errors = [];
$success = '';
$success_qr_token = '';
$title = '';
$issue_date = '';
$expiry_date = '';

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
    $errors = [];

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
                // Remove orphaned files left behind by a failed supersede attempt
                if ($destination && is_file($destination)) { @unlink($destination); }
                if ($qr_path && is_file($qr_path)) { @unlink($qr_path); }
            }
        }
    }
?>
<?php $page_title = 'Supersede Certificate - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="container shell-wide">
        <div class="page-head">
            <h2>Supersede / Correct Certificate</h2>
            <a href="view_certificate_admin.php?id=<?= (int)$old_cert_id ?>" class="btn btn-secondary">Back</a>
        </div>

        <div class="alert alert-info">
            <strong>Original Certificate:</strong> <?= htmlspecialchars($old_cert['certificate_id']) ?> (v<?= $old_cert['version'] ?>)<br>
            <strong>Title:</strong> <?= htmlspecialchars($old_cert['title']) ?><br>
            <strong>Student:</strong> <?= htmlspecialchars($old_cert['student_name']) ?> (<?= htmlspecialchars($old_cert['student_email']) ?>)
        </div>
        
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">Please correct the highlighted fields below.</div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success">
                <strong>Success!</strong> <?= htmlspecialchars($success) ?><br>
                The original certificate (<?= htmlspecialchars($old_cert['certificate_id']) ?>) is now marked as <strong>superseded</strong>.
            </div>
            
            <div class="seal-frame">
                <h3>New Certificate QR — Digital Seal</h3>
                <img src="qrcodes/<?= htmlspecialchars($success_qr_token) ?>.png" alt="QR Code">
                <br>
                <a href="qrcodes/<?= htmlspecialchars($success_qr_token) ?>.png" download="Certificate_QR.png" class="btn btn-primary">Download QR Code (PNG)</a>
            </div>
            
            <a href="admin_dashboard.php" class="btn btn-secondary">Back to Dashboard</a>
        <?php elseif (in_array($old_cert['status'], ['active', 'expired'])): ?>
        
        <p>Submit the corrected certificate data below. The original will be preserved but marked as <strong>superseded</strong>.</p>
        
        <form method="POST" action="" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            
            <div class="form-group">
                <label>Corrected Certificate Title:</label>
                <input type="text" name="title" value="<?= htmlspecialchars($title !== '' ? $title : $old_cert['title']) ?>" data-validate="required|min:3|max:200" required>
                <?php render_field_error($errors, 'title'); ?>
            </div>
            <div class="form-row">
            <div class="form-group">
                <label>Issue Date:</label>
                <input type="date" name="issue_date" id="issue_date" value="<?= htmlspecialchars($issue_date !== '' ? $issue_date : $old_cert['issue_date']) ?>" data-validate="required|daterange" required>
                <?php render_field_error($errors, 'issue_date'); ?>
            </div>
            <div class="form-group">
                <label>Expiry Date (Optional):</label>
                <input type="date" name="expiry_date" value="<?= htmlspecialchars($expiry_date !== '' ? $expiry_date : ($old_cert['expiry_date'] ?? '')) ?>" data-validate="after:#issue_date">
                <?php render_field_error($errors, 'expiry_date'); ?>
            </div>
            </div>
            <div class="form-group">
                <label>Updated Certificate File (PDF, PNG, JPG - Max 5MB):</label>
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

            <button type="submit" class="btn btn-warn btn-block">Issue Corrected Version</button>
        </form>
        <?php endif; ?>
    </div>
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
