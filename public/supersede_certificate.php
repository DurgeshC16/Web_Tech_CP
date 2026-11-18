<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/TransparencyLogService.php';
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
$institution_id = current_institution_id($db);

if (!$institution_id) {
    show_error_page('Error', 'Institution profile not found.');
}

// Fetch the old certificate — ownership enforced centrally (uniform 403).
$old_cert = require_owned_certificate(
    $db,
    $old_cert_id,
    'admin',
    $institution_id,
    'c.*, s.full_name as student_name, u.email as student_email',
    'JOIN students s ON c.student_id = s.id JOIN users u ON s.user_id = u.id'
);

if ($old_cert['status'] !== 'active' && $old_cert['status'] !== 'expired') {
    $error = "Only active or expired certificates can be superseded (current status: {$old_cert['status']}).";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    // post_max_size overflow empties $_POST+$_FILES (CSRF token included),
    // so detect it FIRST — otherwise the user sees a misleading 403.
    if (is_post_overflow()) {
        $error = 'The uploaded file is too large and was rejected by the server (post_max_size exceeded). Please use a file under 5 MB.';
    } else {
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
        // Issue leg first…
        $dr = v_date_range($issue_date, null);
        if ($dr !== true) {
            $errors['issue_date'] = $dr;
        } elseif ($expiry_date !== '') {
            // …then the compare rule: expiry must be after issue.
            $da = v_date_after($expiry_date, $issue_date, 'Expiry date');
            if ($da !== true) {
                $errors['expiry_date'] = $da;
            }
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
                
                // 2. Save File (unguessable name, validated lowercase ext, outside web root)
                $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                $filename = $new_cert_id . '_' . bin2hex(random_bytes(16)) . '.' . $ext;
                $upload_dir = __DIR__ . '/../private_data/uploads/';
                if (!is_dir($upload_dir) && !mkdir($upload_dir, 0755, true) && !is_dir($upload_dir)) {
                    throw new Exception('Upload directory is not available. Please contact the administrator.');
                }
                if (!is_writable($upload_dir)) {
                    throw new Exception('Upload directory is not writable. Please contact the administrator.');
                }
                $destination = $upload_dir . $filename;
                
                if (!move_uploaded_file($file['tmp_name'], $destination)) {
                    throw new Exception('Failed to move uploaded file.');
                }
                
                // 3. Generate QR Token and QR Code
                if (defined('QR_CACHE_DIR') && (!is_dir(QR_CACHE_DIR) || !is_writable(QR_CACHE_DIR))) {
                    throw new Exception('QR cache directory is not writable. Please contact the administrator.');
                }
                $qr_token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
                $verify_url = BASE_URL . "/verify.php?token=" . $qr_token;
                $qr_dir = __DIR__ . "/qrcodes/";
                if (!is_dir($qr_dir) && !mkdir($qr_dir, 0755, true) && !is_dir($qr_dir)) {
                    throw new Exception('QR directory is not available. Please contact the administrator.');
                }
                if (!is_writable($qr_dir)) {
                    throw new Exception('QR directory is not writable. Please contact the administrator.');
                }
                $qr_path = $qr_dir . $qr_token . ".png";
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
                $instStmt = $db->prepare('SELECT key_id, public_key, encrypted_private_key FROM institution_keys WHERE institution_id = :id AND status="active" ORDER BY key_id DESC LIMIT 1 FOR UPDATE');
                $instStmt->execute(['id' => $institution_id]);
                $instKeys = $instStmt->fetch();
                if (!$instKeys) throw new Exception('This institution has no active signing key. Please contact the platform administrator.');
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
                
                // 6. Insert new certificate
                $stmt = $db->prepare('INSERT INTO certificates (certificate_id, institution_id, key_id, student_id, title, issue_date, expiry_date, file_path, status, version, previous_version_id, qr_token, sha256_hash, file_sha256, digital_signature) VALUES (:cid, :iid, :key_id, :sid, :title, :issue, :expiry, :path, "active", :ver, :prev, :qr_token, :hash, :fhash, :sig)');
                $stmt->execute([
                    'cid' => $new_cert_id,
                    'iid' => $institution_id,
                    'key_id' => (int)$instKeys['key_id'],
                    'sid' => $old_cert['student_id'],
                    'title' => $title,
                    'issue' => $issue_date,
                    'expiry' => $expiry_date ?: null,
                    'path' => $filename,
                    'ver' => $new_version,
                    'prev' => $old_cert['id'],
                    'qr_token' => $qr_token,
                    'hash' => $sha256_hash, 'fhash' => hash_file('sha256', $destination),
                    'sig' => $digital_signature
                ]);
                $new_db_id = $db->lastInsertId();
                
                // 7. Mark old certificate as superseded and link to new one
                $stmt = $db->prepare('UPDATE certificates SET status = "superseded", superseded_by_id = :new_id WHERE id = :old_id');
                $stmt->execute(['new_id' => $new_db_id, 'old_id' => $old_cert['id']]);
                TransparencyLogService::append($db, $new_cert_id, 'ISSUE');
                TransparencyLogService::append($db, (string)$old_cert['certificate_id'], 'SUPERSEDE');
                
                $db->commit();
                $success = "Certificate superseded! New Certificate ID: " . $new_cert_id . " (v" . $new_version . ")";
                $success_qr_token = $qr_token;
            } catch (Exception $e) {
                if ($db->inTransaction()) { $db->rollBack(); }
                $error = 'Error superseding certificate: ' . $e->getMessage();
                // Remove orphaned files left behind by a failed supersede attempt
                if (!empty($destination) && is_file($destination)) { @unlink($destination); }
                if (!empty($qr_path) && is_file($qr_path)) { @unlink($qr_path); }
            }
        }
    } // end overflow-guard else
} // end POST
?>
<?php
require_once __DIR__ . '/../src/utils/admin_ui.php';
$page_title = 'Supersede Certificate - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main">
    <div class="admin-shell">
        <header class="admin-head admin-head-warn">
            <div class="admin-head-row">
                <span class="admin-head-icon" aria-hidden="true"><?= cv_icon('refresh') ?></span>
                <div class="admin-head-text">
                    <ol class="crumbs" aria-label="Breadcrumb"><li><a href="admin_dashboard.php">Dashboard</a></li><li><a href="view_certificate_admin.php?id=<?= (int)$old_cert_id ?>"><?= htmlspecialchars($old_cert['certificate_id']) ?></a></li><li aria-current="page">Supersede</li></ol>
                    <h1>Supersede / Correct Certificate</h1>
                    <p class="admin-head-sub">Issue a corrected version. The original stays on record but every verifier is pointed to the new one.</p>
                </div>
                <div class="admin-head-actions">
                    <a href="view_certificate_admin.php?id=<?= (int)$old_cert_id ?>" class="btn btn-light"><?= cv_icon('arrow-left') ?> Back</a>
                </div>
            </div>
        </header>

        <?php if ($error): ?>
            <div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">Please correct the highlighted fields below.</div>
        <?php endif; ?>

        <div class="zone-layout">
            <section class="card zone-card" aria-labelledby="origTitle">
                <div class="zone-head">
                    <span class="zone-icon" aria-hidden="true"><?= cv_icon('file') ?></span>
                    <div><h2 id="origTitle">Original Certificate</h2><p>Kept for the record, marked superseded.</p></div>
                </div>
                <dl class="summary-list">
                    <dt>Certificate ID</dt><dd><span class="id-chip"><?= htmlspecialchars($old_cert['certificate_id']) ?></span> <span class="badge badge-info">v<?= (int)$old_cert['version'] ?></span></dd>
                    <dt>Title</dt><dd><?= htmlspecialchars($old_cert['title']) ?></dd>
                    <dt>Student</dt><dd><?= htmlspecialchars($old_cert['student_name']) ?> <span class="cell-sub">(<?= htmlspecialchars($old_cert['student_email']) ?>)</span></dd>
                    <dt>Status</dt><dd><span class="badge-status badge-<?= htmlspecialchars(cv_status_badge($success ? 'superseded' : (string)$old_cert['status'])) ?>"><?= htmlspecialchars($success ? 'superseded' : (string)$old_cert['status']) ?></span></dd>
                </dl>
                <h3 class="aside-title mt-3">What superseding does</h3>
                <ul class="consequences">
                    <li><span class="cq-icon cq-info" aria-hidden="true"><?= cv_icon('refresh') ?></span><span><strong>The original becomes SUPERSEDED</strong> — verifiers see it was replaced and get a link to the current version.</span></li>
                    <li><span class="cq-icon cq-ok" aria-hidden="true"><?= cv_icon('award') ?></span><span><strong>A new certificate is signed</strong> with a fresh ID, version v<?= (int)$old_cert['version'] + 1 ?> and its own QR seal.</span></li>
                    <li><span class="cq-icon cq-warn" aria-hidden="true"><?= cv_icon('alert') ?></span><span><strong>The student keeps both records</strong>; only the new one verifies as VALID.</span></li>
                </ul>
            </section>

            <?php if ($success): ?>
            <section class="card success-card" aria-labelledby="supersededTitle">
                <span class="success-check" aria-hidden="true"><?= cv_icon('check') ?></span>
                <h2 id="supersededTitle">Corrected version issued</h2>
                <div class="alert alert-success" role="status">
                    <strong>Success!</strong> <?= htmlspecialchars($success) ?><br>
                    The original certificate (<?= htmlspecialchars($old_cert['certificate_id']) ?>) is now marked as <strong>superseded</strong>.
                </div>
                <div class="seal-frame">
                    <h3>New Certificate QR — Digital Seal</h3>
                    <img src="qrcodes/<?= htmlspecialchars($success_qr_token) ?>.png" alt="QR code that opens the verification page for the new certificate">
                    <br>
                    <a href="qrcodes/<?= htmlspecialchars($success_qr_token) ?>.png" download="Certificate_QR.png" class="btn btn-primary"><?= cv_icon('download') ?> Download QR Code (PNG)</a>
                </div>
                <a href="admin_dashboard.php" class="btn btn-secondary">Back to Dashboard</a>
            </section>
            <?php elseif (in_array($old_cert['status'], ['active', 'expired'])): ?>
            <section class="card zone-card zone-warn form-card" aria-labelledby="correctTitle">
                <div class="zone-head">
                    <span class="zone-icon" aria-hidden="true"><?= cv_icon('pen') ?></span>
                    <div><h2 id="correctTitle">Corrected details</h2><p>Submit the corrected certificate data below. The original will be preserved but marked as <strong>superseded</strong>.</p></div>
                </div>

                <form method="POST" action="" enctype="multipart/form-data" data-confirm="Issue a corrected version and mark <?= htmlspecialchars($old_cert['certificate_id']) ?> as superseded?" data-loading>
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">

                    <div class="form-group">
                        <label for="ss_title">Corrected Certificate Title</label>
                        <input type="text" name="title" id="ss_title" value="<?= htmlspecialchars($title !== '' ? $title : $old_cert['title']) ?>" data-validate="required|min:3|max:200" required>
                        <?php render_field_error($errors, 'title'); ?>
                    </div>
                    <div class="form-row">
                    <div class="form-group">
                        <label for="issue_date">Issue Date</label>
                        <input type="date" name="issue_date" id="issue_date" value="<?= htmlspecialchars($issue_date !== '' ? $issue_date : $old_cert['issue_date']) ?>" data-validate="required|daterange" required>
                        <?php render_field_error($errors, 'issue_date'); ?>
                    </div>
                    <div class="form-group">
                        <label for="ss_expiry">Expiry Date <span class="label-opt">(optional)</span></label>
                        <input type="date" name="expiry_date" id="ss_expiry" value="<?= htmlspecialchars($expiry_date !== '' ? $expiry_date : ($old_cert['expiry_date'] ?? '')) ?>" data-validate="after:#issue_date">
                        <?php render_field_error($errors, 'expiry_date'); ?>
                    </div>
                    </div>
                    <div class="form-group">
                        <label for="certificate_file">Updated Certificate File <span class="label-opt">(PDF, PNG, JPG — max 5 MB)</span></label>
                        <input type="hidden" name="MAX_FILE_SIZE" value="5242880">
                        <div class="upload-zone">
                            <span class="upload-zone-icon" aria-hidden="true"><?= cv_icon('upload') ?></span>
                            <span class="upload-zone-title" aria-hidden="true">Drag &amp; drop the corrected file, or <span class="link-like">browse</span></span>
                            <span class="upload-zone-hint" aria-hidden="true">PDF, PNG or JPG · up to 5 MB</span>
                            <small class="file-name-display" id="file_name_display" aria-live="polite"></small>
                            <input type="file" name="certificate_file" id="certificate_file" data-filename-target="file_name_display" accept=".pdf, .png, .jpg, .jpeg" data-validate="upload" required>
                        </div>
                        <?php render_field_error($errors, 'certificate_file'); ?>
                    </div>

                    <button type="submit" class="btn btn-warn btn-block btn-lg"><?= cv_icon('refresh') ?> Issue Corrected Version</button>
                </form>
            </section>
            <?php else: ?>
            <section class="card zone-card">
                <div class="empty-state">
                    <span class="empty-state-icon"><?= cv_icon('lock') ?></span>
                    <h3>This certificate can no longer be corrected</h3>
                    <p>Only active or expired certificates can be superseded.</p>
                    <a href="view_certificate_admin.php?id=<?= (int)$old_cert_id ?>" class="btn btn-secondary">Back to the certificate</a>
                </div>
            </section>
            <?php endif; ?>
        </div>
    </div>
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/admin-ui.js" defer></script>
</body>
</html>
