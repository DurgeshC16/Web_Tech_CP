<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/GuestQuotaService.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$token = $_GET['token'] ?? '';
$error = '';
$cert = null;
$share_verdict = null;
$share_detail  = null;
$share_quota   = null;  // guest quota status (GuestQuotaService)
$share_blocked = false; // guest has used every free verification

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
            // Strict shape: the app only ever mints integer ids + integer exps
            // (accept digit-strings too — PDO may hand back string ids).
            // The HMAC already authenticates the payload; this is defense in depth.
            $share_id = filter_var($payload['id'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
            $share_exp = filter_var($payload['exp'] ?? null, FILTER_VALIDATE_INT);
            if (!$payload || $share_id === false || $share_exp === false) {
                $error = "Invalid token payload.";
            } elseif (time() > $share_exp) {
                $error = "This share link has expired.";
            } else {
                $db = Database::getInstance();
                // Guest quota: opening a share link runs the full verification
                // cascade, so it counts like verify.php (re-opening the same
                // link, or a certificate already verified, is free). Checked
                // BEFORE the certificate query; logged-in users are exempt.
                $share_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
                $share_quota = GuestQuotaService::check($db, $share_ip, $_SESSION, ['share:' . $share_id]);
                $share_blocked = !$share_quota['allowed'];
            }
            if (!$error && !$share_blocked) {
                $stmt = $db->prepare('
                    SELECT c.*, i.name as institution_name, ik.public_key, ik.status AS signing_key_status, s.full_name as student_name
                    FROM certificates c
                    JOIN institutions i ON c.institution_id = i.id
                    LEFT JOIN institution_keys ik ON ik.institution_id = c.institution_id AND ik.key_id = c.key_id
                    JOIN students s ON c.student_id = s.id
                    WHERE c.id = :id
                ');
                $stmt->execute(['id' => $share_id]);
                $cert = $stmt->fetch();
                // The lookup ran: record it (the certificate alias makes a
                // certificate the guest already verified a free repeat).
                $share_quota = GuestQuotaService::record($db, $share_ip, $_SESSION, $cert
                    ? ['share:' . $share_id, GuestQuotaService::certAlias((string)$cert['certificate_id'])]
                    : ['share:' . $share_id]);

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
if ($share_blocked) {
    GuestQuotaService::sendLimitHeaders($share_quota);
}
?>
<?php $page_title = $share_blocked ? 'Free verification limit reached - CertiVault' : 'Shared Certificate - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="container" style="max-width: 600px; text-align: center;">
        <?php if ($share_blocked): ?>
            <?= GuestQuotaService::renderLimitNotice($share_quota) ?>
        <?php elseif ($error): ?>
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
            <?= is_array($share_quota) ? GuestQuotaService::renderCounter($share_quota) : '' ?>
        <?php endif; ?>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
