<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_role('student');

$db = Database::getInstance();
$cert_id = (int)($_GET['id'] ?? 0);
$share_link = '';

// Get student_id
$stmt = $db->prepare('SELECT id FROM students WHERE user_id = :user_id LIMIT 1');
$stmt->execute(['user_id' => $_SESSION['user_id']]);
$student_id = $stmt->fetchColumn();

// Fetch certificate details, ensure they own it
$stmt = $db->prepare('
    SELECT c.*, i.name as institution_name
    FROM certificates c
    JOIN institutions i ON c.institution_id = i.id
    WHERE c.id = :id AND c.student_id = :student_id
');
$stmt->execute(['id' => $cert_id, 'student_id' => $student_id]);
$cert = $stmt->fetch();

if (!$cert) {
    show_error_page('Not Found', 'Certificate not found or access denied.');
}

// Generate Share Link Logic
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['generate_share'])) {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    $expiry = time() + (24 * 3600); // Valid for 24 hours
    $payload = json_encode(['id' => $cert['id'], 'exp' => $expiry]);
    $encoded_payload = base64_encode($payload);
    $signature = hash_hmac('sha256', $encoded_payload, APP_ENCRYPTION_KEY);
    
    $token = $encoded_payload . '.' . $signature;
    $share_link = BASE_URL . '/share.php?token=' . urlencode($token);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>View Certificate - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container" style="max-width: 600px;">
        <h2>Certificate Details</h2>
        <a href="student_dashboard.php" class="btn" style="float: right; margin-top: -40px;">Back</a>
        
        <div class="card" style="margin-top: 20px;">
            <h3><?= htmlspecialchars($cert['title']) ?></h3>
            <p><strong>Certificate ID:</strong> <?= htmlspecialchars($cert['certificate_id']) ?></p>
            <p><strong>Version:</strong> <?= $cert['version'] ?></p>
            <p><strong>Institution:</strong> <?= htmlspecialchars($cert['institution_name']) ?></p>
            <p><strong>Issue Date:</strong> <?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></p>
            <?php if ($cert['expiry_date']): ?>
                <p><strong>Expiry Date:</strong> <?= htmlspecialchars(date('F j, Y', strtotime($cert['expiry_date']))) ?></p>
            <?php endif; ?>
            <p>
                <strong>Status:</strong> 
                <span class="status-badge status-<?= htmlspecialchars($cert['status']) ?>">
                    <?= htmlspecialchars($cert['status']) ?>
                </span>
            </p>
            
            <?php if ($cert['status'] === 'superseded' && !empty($cert['superseded_by_id'])): ?>
                <div class="alert alert-info" style="margin-top:10px;">
                    <strong>This version has been superseded.</strong> A corrected version has been issued.<br>
                    <a href="view_certificate_student.php?id=<?= $cert['superseded_by_id'] ?>">View Current Version →</a>
                </div>
            <?php endif; ?>
            
            <?php if ($cert['status'] === 'revoked'): ?>
                <div class="alert alert-danger" style="margin-top:10px;">
                    <strong>This certificate has been revoked</strong> by the issuing institution and is no longer valid.
                </div>
            <?php endif; ?>
            
            <?php if ($cert['qr_token'] && $cert['status'] === 'active'): ?>
                <div style="text-align: center; margin: 20px 0;">
                    <p><strong>Verification QR:</strong></p>
                    <img src="qrcodes/<?= htmlspecialchars($cert['qr_token']) ?>.png" alt="QR Code" style="max-width: 150px; border: 1px solid #ccc;">
                </div>
            <?php endif; ?>
            
            <?php if ($cert['status'] === 'active'): ?>
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                <a href="download.php?id=<?= $cert['id'] ?>" class="btn">Download File</a>
                <form method="POST" action="" style="margin: 0;">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                    <input type="hidden" name="generate_share" value="1">
                    <button type="submit" class="btn" style="background-color: #28a745;">Generate Share Link (24h)</button>
                </form>
            </div>
            <?php endif; ?>
            
            <?php if ($share_link): ?>
                <div class="alert alert-success" style="margin-top: 20px;">
                    <strong>Share Link:</strong><br>
                    <input type="text" value="<?= htmlspecialchars($share_link) ?>" readonly style="width: 100%; margin-top: 5px; padding: 5px;" onclick="this.select();">
                    <small>This link is valid for 24 hours.</small>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
