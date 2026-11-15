<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/IssuanceService.php';

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
    // post_max_size overflow empties $_POST+$_FILES (CSRF token included),
    // so detect it FIRST — otherwise the user sees a misleading 403.
    if (is_post_overflow()) {
        $error = 'The uploaded file is too large and was rejected by the server (post_max_size exceeded). Please use a file under 5 MB.';
    } else {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    $student_email = sanitize_input($_POST['student_email'] ?? '');
    $student_name = sanitize_input($_POST['student_name'] ?? '');
    $title = sanitize_input($_POST['title'] ?? '');
    $issue_date = sanitize_input($_POST['issue_date'] ?? '');
    $expiry_date = sanitize_input($_POST['expiry_date'] ?? '');
    $validity_years = sanitize_input($_POST['validity_years'] ?? '');
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
    // Optional custom ID (blank = auto CV-YYYY-NNNNNN). Needs $db for the
    // case-insensitive uniqueness check.
    $custom_id = sanitize_input($_POST['custom_id'] ?? '');
    if ($custom_id !== '' && ($e = v_certificate_id_flexible($custom_id, $db)) !== true) {
        $errors['custom_id'] = $e;
    }
    if (($e = v_required($issue_date, 'Issue Date')) !== true) {
        $errors['issue_date'] = $e;
    } else {
        // Issue leg first…
        $dr = v_date_range($issue_date, null);
        if ($dr !== true) {
            $errors['issue_date'] = $dr;
        }
    }
    // Optional validity window: whole years, 1–50 (Number + Range rules).
    if ($validity_years !== '') {
        if (($e = v_number($validity_years)) !== true) { $errors['validity_years'] = $e; }
        elseif (($e = v_range($validity_years, 1, 50, 'Validity')) !== true) { $errors['validity_years'] = $e; }
    }
    // Auto-fill: validity years complete an empty expiry date. An
    // explicitly entered expiry date always wins over the computed one.
    if (empty($errors['issue_date']) && empty($errors['validity_years']) && $validity_years !== '' && $expiry_date === '') {
        $expiry_date = date('Y-m-d', strtotime($issue_date . ' +' . (int)$validity_years . ' years'));
    }
    // …then the compare rule: expiry must be after issue.
    if ($expiry_date !== '' && empty($errors['issue_date'])) {
        $da = v_date_after($expiry_date, $issue_date, 'Expiry date');
        if ($da !== true) {
            $errors['expiry_date'] = $da;
        }
    }
    if (($file_e = v_upload($file)) !== true) { $errors['certificate_file'] = $file_e; }

    if (!empty($errors)) {
        $error = 'Please correct the highlighted fields below.';
    } else {
            try {
                // Shared pipeline (src/services/IssuanceService.php) — the
                // same code bulk issuance uses.
                $student = IssuanceService::resolveStudent($db, $student_email, $student_name);
                if ($student['status'] !== 'ok') {
                    throw new ActivationGate($student['message']);
                }
                $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                $issued = IssuanceService::issue($db, (int)$institution_id, (int)$student['student_id'], [
                    'title' => $title,
                    'issue_date' => $issue_date,
                    'expiry_date' => $expiry_date,
                    'custom_id' => $custom_id,
                ], $ext, function ($certId, $qrToken, $verifyUrl, $qrPath, $destination) use ($file) {
                    if (!move_uploaded_file($file['tmp_name'], $destination)) {
                        throw new Exception('Failed to move uploaded file.');
                    }
                });
                $instName = $db->prepare('SELECT name FROM institutions WHERE id = :id');
                $instName->execute(['id' => $institution_id]);
                $notified = IssuanceService::notifyStudent($student_email, $issued['certificate_id'], $title, (string)$instName->fetchColumn(), $issued['verify_url']);
                $success = 'Certificate successfully issued! Certificate ID: ' . $issued['certificate_id']
                    . ($notified ? ' — the student has been emailed.' : ' — the notification email could not be sent.');
                $success_qr_token = $issued['qr_token'];
            } catch (ActivationGate $e) {
                // Student gate: pending account committed, nothing issued.
                $error = $e->getMessage();
            } catch (PDOException $e) {
                // Race backstop: the UNIQUE indexes reject a duplicate ID
                // that slipped past validation (SQLSTATE 23000).
                $error = ($e->getCode() === '23000')
                    ? 'That certificate ID is already in use. Please choose another.'
                    : 'Error issuing certificate. Please try again.';
                error_log('[CertiVault] Issue certificate DB error: ' . $e->getMessage());
            } catch (Exception $e) {
                $error = 'Error issuing certificate: ' . $e->getMessage();
            }
        }
    } // end overflow-guard else
} // end POST
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
            <div class="form-group">
                <label>Custom certificate ID (optional — blank auto-generates CV-YYYY-NNNNNN):</label>
                <input type="text" name="custom_id" value="<?= htmlspecialchars($custom_id ?? '') ?>" data-validate="certid" maxlength="40" placeholder="e.g. DEPT/2024/001">
                <small>3–40 chars: letters, digits, spaces and - _ / . Must be unique; CV-YYYY-N… is reserved.</small>
                <?php render_field_error($errors, 'custom_id'); ?>
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
                <label>Validity (years, optional — auto-fills an empty expiry date):</label>
                <input type="number" name="validity_years" id="validity_years" min="1" max="50" step="1" inputmode="numeric" value="<?= htmlspecialchars($validity_years ?? '') ?>" data-validate="number|range:1,50">
                <?php render_field_error($errors, 'validity_years'); ?>
            </div>
            <div class="form-group">
                <label>Certificate File (PDF, PNG, JPG - Max 5MB):</label>
                <input type="hidden" name="MAX_FILE_SIZE" value="5242880">
                <input type="file" name="certificate_file" id="certificate_file" data-filename-target="file_name_display" accept=".pdf, .png, .jpg, .jpeg" data-validate="upload" required>
                <small class="file-name-display" id="file_name_display"></small>
                <?php render_field_error($errors, 'certificate_file'); ?>
            </div>

            <button type="submit" class="btn btn-primary">Issue Certificate</button>
        </form>
        <?php endif; ?>
    </div>
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
