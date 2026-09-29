<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/config/config.php';

$token = $_GET['token'] ?? '';
$error = '';
$cert = null;

if (empty($token)) {
    $error = "No share token provided.";
} else {
    $parts = explode('.', $token);
    if (count($parts) !== 2) {
        $error = "Invalid token format.";
    } else {
        $encoded_payload = $parts[0];
        $signature = $parts[1];
        
        $expected_signature = hash_hmac('sha256', $encoded_payload, APP_ENCRYPTION_KEY);
        
        if (!hash_equals($expected_signature, $signature)) {
            $error = "Token signature verification failed. The link is invalid or corrupted.";
        } else {
            $payload = json_decode(base64_decode($encoded_payload), true);
            if (!$payload || !isset($payload['id']) || !isset($payload['exp'])) {
                $error = "Invalid token payload.";
            } elseif (time() > $payload['exp']) {
                $error = "This share link has expired.";
            } else {
                $db = Database::getInstance();
                $stmt = $db->prepare('
                    SELECT c.*, i.name as institution_name, s.full_name as student_name
                    FROM certificates c
                    JOIN institutions i ON c.institution_id = i.id
                    JOIN students s ON c.student_id = s.id
                    WHERE c.id = :id
                ');
                $stmt->execute(['id' => $payload['id']]);
                $cert = $stmt->fetch();
                
                if (!$cert) {
                    $error = "Certificate no longer exists.";
                }
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
    <title>Shared Certificate - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container" style="max-width: 600px; text-align: center;">
        <?php if ($error): ?>
            <h2>Access Denied</h2>
            <div class="alert alert-danger" style="margin-top: 20px;">
                <?= htmlspecialchars($error) ?>
            </div>
            <p>Please request a new share link from the certificate holder.</p>
        <?php else: ?>
            <h2>Verified Shared Certificate</h2>
            
            <div class="card" style="margin-top: 20px; text-align: left;">
                <h3><?= htmlspecialchars($cert['title']) ?></h3>
                <p><strong>Awarded To:</strong> <?= htmlspecialchars($cert['student_name']) ?></p>
                <p><strong>Certificate ID:</strong> <?= htmlspecialchars($cert['certificate_id']) ?></p>
                <p><strong>Institution:</strong> <?= htmlspecialchars($cert['institution_name']) ?></p>
                <p><strong>Issue Date:</strong> <?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></p>
                <p>
                    <strong>Status:</strong> 
                    <span class="status-badge status-<?= htmlspecialchars($cert['status']) ?>">
                        <?= htmlspecialchars($cert['status']) ?>
                    </span>
                </p>
                
                <?php if ($cert['qr_token']): ?>
                    <div style="text-align: center; margin: 20px 0;">
                        <p><strong>Official Verification QR:</strong></p>
                        <img src="qrcodes/<?= htmlspecialchars($cert['qr_token']) ?>.png" alt="QR Code" style="max-width: 150px; border: 1px solid #ccc;">
                    </div>
                <?php endif; ?>
                
                <p style="text-align: center; color: #666; font-size: 0.9em; margin-top: 20px;">
                    This is a secure, time-limited share link.
                </p>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
