<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$token = $_GET['token'] ?? '';
$error = '';
$cert = null;
$share_verdict = null;
$share_detail  = null;

if (empty($token)) {
    $error = "No share token provided.";
} else {
    $parts = explode('.', $token);
    if (count($parts) !== 2) {
        $error = "Invalid token format.";
    } else {
        $encoded_payload = $parts[0];
        $signature = $parts[1];
        
        $expected_signature = hash_hmac('sha256', $encoded_payload, SHARE_LINK_SECRET);
        
        if (!hash_equals($expected_signature, $signature)) {
            $error = "Token signature verification failed. The link is invalid or corrupted.";
        } else {
            $payload = json_decode(base64_decode(strtr($encoded_payload, '-_', '+/')), true);
            if (!$payload || !isset($payload['id']) || !isset($payload['exp'])) {
                $error = "Invalid token payload.";
            } elseif (time() > $payload['exp']) {
                $error = "This share link has expired.";
            } else {
                $db = Database::getInstance();
                $stmt = $db->prepare('
                    SELECT c.*, i.name as institution_name, i.public_key, s.full_name as student_name
                    FROM certificates c
                    JOIN institutions i ON c.institution_id = i.id
                    JOIN students s ON c.student_id = s.id
                    WHERE c.id = :id
                ');
                $stmt->execute(['id' => $payload['id']]);
                $cert = $stmt->fetch();

                if (!$cert) {
                    $error = "Certificate no longer exists.";
                } else {
                    // Run the real verification pipeline so a shared link
                    // shows VALID / TAMPERED / REVOKED / SUPERSEDED / EXPIRED.
                    $share_result = VerificationService::verify($db, $cert);
                    $share_verdict = $share_result['verdict'];
                    $share_detail  = $share_result['detail'];
                }
            }
        }
    }
}
?>
<?php $page_title = 'Shared Certificate - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="container" style="max-width: 600px; text-align: center;">
        <?php if ($error): ?>
            <h2>Access Denied</h2>
            <div class="alert alert-danger" style="margin-top: 20px;">
                <?= htmlspecialchars($error) ?>
            </div>
            <p>Please request a new share link from the certificate holder.</p>
        <?php else: ?>
            <h2>Shared Certificate</h2>

            <?php if (!empty($share_verdict)): ?>
                <div style="text-align:center; margin-top:20px;">
                    <div class="verdict-seal verdict-seal-<?= strtolower($share_verdict) ?>">
                        <?= htmlspecialchars($share_verdict) ?>
                    </div>
                    <p class="verdict-detail" style="text-align:center;"><?= htmlspecialchars($share_detail) ?></p>
                </div>
            <?php endif; ?>

            <div class="card diploma" style="margin-top: 20px; text-align: left;">
                <h3><?= htmlspecialchars($cert['title']) ?></h3>
                <p><strong>Awarded To:</strong> <?= htmlspecialchars($cert['student_name']) ?></p>
                <p><strong>Certificate ID:</strong> <?= htmlspecialchars($cert['certificate_id']) ?></p>
                <p><strong>Institution:</strong> <?= htmlspecialchars($cert['institution_name']) ?></p>
                <p><strong>Issue Date:</strong> <?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></p>
                <p>
                    <strong>Status:</strong>
                    <span class="status-badge status-<?= htmlspecialchars(VerificationService::effectiveStatus($cert)) ?>">
                        <?= htmlspecialchars(VerificationService::effectiveStatus($cert)) ?>
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
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
