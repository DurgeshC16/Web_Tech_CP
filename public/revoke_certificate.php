<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_role('admin');

$db = Database::getInstance();
$cert_db_id = (int)($_GET['id'] ?? 0);
$error = '';
$success = '';

// Get Institution ID
$stmt = $db->prepare('SELECT id FROM institutions WHERE user_id = :user_id LIMIT 1');
$stmt->execute(['user_id' => $_SESSION['user_id']]);
$institution_id = $stmt->fetchColumn();

if (!$institution_id) {
    show_error_page('Error', 'Institution profile not found.');
}

// Fetch certificate, ensure ownership and it's revocable
$stmt = $db->prepare('
    SELECT c.*, s.full_name as student_name
    FROM certificates c
    JOIN students s ON c.student_id = s.id
    WHERE c.id = :id AND c.institution_id = :inst_id
');
$stmt->execute(['id' => $cert_db_id, 'inst_id' => $institution_id]);
$cert = $stmt->fetch();

if (!$cert) {
    show_error_page('Not Found', 'Certificate not found or access denied.');
}

if (!in_array($cert['status'], ['active', 'expired'])) {
    $error = "This certificate cannot be revoked (current status: {$cert['status']}).";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    $reason = trim($_POST['reason'] ?? '');
    if (empty($reason)) {
        $error = 'A revocation reason is required.';
    } else {
        $stmt = $db->prepare('UPDATE certificates SET status = "revoked", revocation_reason = :reason WHERE id = :id');
        $stmt->execute(['reason' => $reason, 'id' => $cert_db_id]);
        $success = "Certificate {$cert['certificate_id']} has been revoked.";
        // Refresh cert data
        $cert['status'] = 'revoked';
        $cert['revocation_reason'] = $reason;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Revoke Certificate - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container shell-wide">
        <div class="page-head">
            <h2>Revoke Certificate</h2>
            <a href="view_certificate_admin.php?id=<?= $cert_db_id ?>" class="btn btn-secondary">Back</a>
        </div>

        <div class="card">
            <h3><?= htmlspecialchars($cert['title']) ?></h3>
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
        <?php if ($success): ?>
            <div class="alert alert-success">
                <strong>Revoked.</strong> <?= htmlspecialchars($success) ?>
            </div>
            <a href="admin_dashboard.php" class="btn btn-primary">Back to Dashboard</a>
        <?php elseif (empty($error) || !empty($_POST['reason'])): ?>
            <?php if (in_array($cert['status'], ['active', 'expired'])): ?>
            <form method="POST" action="">
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <div class="form-group">
                    <label>Reason for Revocation (required):</label>
                    <textarea name="reason" rows="4" required></textarea>
                </div>
                <div class="alert alert-danger">
                    <strong>Warning:</strong> This action is irreversible. The certificate will immediately fail verification with a REVOKED verdict.
                </div>
                <button type="submit" class="btn btn-danger btn-block">Confirm Revocation</button>
            </form>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</body>
</html>
