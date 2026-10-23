<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_role('admin');
require_approved_institution();

$db = Database::getInstance();
$cert_db_id = (int)($_GET['id'] ?? 0);
$error = '';
$errors = [];
$success = '';
$reason = '';

// Get Institution ID
$institution_id = current_institution_id($db);

if (!$institution_id) {
    show_error_page('Error', 'Institution profile not found.');
}

// Fetch certificate — ownership enforced centrally (uniform 403).
$cert = require_owned_certificate(
    $db,
    $cert_db_id,
    'admin',
    $institution_id,
    'c.*, s.full_name as student_name',
    'JOIN students s ON c.student_id = s.id'
);

if (!in_array($cert['status'], ['active', 'expired'])) {
    $error = "This certificate cannot be revoked (current status: {$cert['status']}).";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    $reason = trim($_POST['reason'] ?? '');
    $errors = [];

    if (($e = v_required($reason, 'Revocation reason')) !== true) { $errors['reason'] = $e; }
    elseif (($e = v_length($reason, 10, 500, 'Revocation reason')) !== true) { $errors['reason'] = $e; }

    if (!empty($errors)) {
        $error = 'Please correct the highlighted fields below.';
    } else {
        $stmt = $db->prepare('UPDATE certificates SET status = "revoked", revocation_reason = :reason, revoked_at = :revoked_at, revoked_by = :revoked_by WHERE id = :id');
        $stmt->execute([
            'reason' => $reason,
            'id' => $cert_db_id,
            'revoked_at' => date('Y-m-d H:i:s'),
            'revoked_by' => $_SESSION['user_id'],
        ]);
        $success = "Certificate {$cert['certificate_id']} has been revoked.";
        // Refresh cert data
        $cert['status'] = 'revoked';
        $cert['revocation_reason'] = $reason;
    }
}
?>
<?php $page_title = 'Revoke Certificate - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="container shell-wide">
        <div class="page-head">
            <h2>Revoke Certificate</h2>
            <a href="view_certificate_admin.php?id=<?= (int)$cert_db_id ?>" class="btn btn-secondary">Back</a>
        </div>

        <div class="card danger-panel">
            <h3 style="color:var(--danger);">Revoke This Certificate</h3>
            <p><strong>Certificate ID:</strong> <?= htmlspecialchars($cert['certificate_id']) ?></p>
            <p><strong>Awarded To:</strong> <?= htmlspecialchars($cert['student_name']) ?></p>
            <p>
                <strong>Status:</strong>
                <span class="badge-status badge-<?= htmlspecialchars($cert['status'] === 'active' ? 'valid' : $cert['status']) ?>">
                    <?= htmlspecialchars($cert['status']) ?>
                </span>
            </p>
        </div>

        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">Please correct the highlighted fields below.</div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success">
                <strong>Revoked.</strong> <?= htmlspecialchars($success) ?>
            </div>
            <a href="admin_dashboard.php" class="btn btn-primary">Back to Dashboard</a>
        <?php elseif (empty($error) || !empty($_POST['reason']) || !empty($errors)): ?>
            <?php if (in_array($cert['status'], ['active', 'expired'])): ?>
            <form method="POST" action="">
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <div class="form-group">
                    <label>Reason for Revocation (required):</label>
                    <textarea name="reason" rows="4" data-validate="required|min:10|max:500" required><?= htmlspecialchars($reason) ?></textarea>
                    <?php render_field_error($errors, 'reason'); ?>
                </div>
                <div class="alert alert-danger">
                    <strong>Warning:</strong> This action is irreversible. The certificate will immediately fail verification with a REVOKED verdict.
                </div>
                <button type="submit" class="btn btn-danger btn-block">Confirm Revocation</button>
            </form>
            <?php endif; ?>
        <?php endif; ?>
    </div>
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
