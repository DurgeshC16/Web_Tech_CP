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
<?php
// ── View helpers (presentation only) ──────────────────────────────────
$sh_icon = static function (string $d): string {
    return '<svg class="sv-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' . $d . '</svg>';
};
$sh_seal_icons = [
    'VALID' => '<path d="M5 13l4 4L19 7"/>',
    'TAMPERED' => '<path d="M6 6l12 12M18 6L6 18"/>',
    'EXPIRED' => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>',
    'REVOKED' => '<circle cx="12" cy="12" r="9"/><path d="M6 6l12 12"/>',
    'SUPERSEDED' => '<path d="M4 16l4-4-4-4M12 16l4-4-4-4"/>',
    'INVALID' => '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
];
$sh_headlines = [
    'VALID'      => 'Authentic certificate',
    'TAMPERED'   => 'Tampering detected',
    'EXPIRED'    => 'Authentic, but expired',
    'REVOKED'    => 'Certificate revoked',
    'SUPERSEDED' => 'Replaced by a newer version',
    'INVALID'    => 'Could not be verified',
];
$sh_check = $sh_icon('<path d="M5 13l4 4L19 7"/>');
$sh_lock  = $sh_icon('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>');
?>
<main id="main" class="sv-main">
    <div class="container verify-shell<?= (!$share_blocked && !$error) ? ' sv-shell-result' : '' ?>">
        <?php if ($share_blocked): ?>
            <div class="sv-body">
                <div class="sv-limit">
                    <span class="sv-limit-badge" aria-hidden="true"><?= $sh_lock ?></span>
                    <?= GuestQuotaService::renderLimitNotice($share_quota) ?>
                    <ul class="sv-limit-perks" aria-label="Why create an account">
                        <li><?= $sh_check ?>No daily limit when signed in</li>
                        <li><?= $sh_check ?>Free to create</li>
                        <li><?= $sh_check ?>Same instant verification</li>
                    </ul>
                </div>
            </div>
        <?php elseif ($error): ?>
            <div class="sv-body sv-notice-page text-center">
                <span class="sv-notice-icon sv-tone-danger" aria-hidden="true"><?= $sh_icon('<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/><path d="M4 4l16 16"/>') ?></span>
                <h1 class="sv-notice-title">Access Denied</h1>
                <div class="alert alert-danger">
                    <?= htmlspecialchars($error) ?>
                </div>
                <p class="sv-notice-text">Please request a new share link from the certificate holder.</p>
                <a class="btn btn-secondary" href="verify.php">Verify a certificate instead</a>
            </div>
        <?php else: ?>
            <?php $sh_v = strtolower((string)($share_verdict ?? '')); ?>
            <section class="verdict-wrap sv-verdict sv-v-<?= htmlspecialchars($sh_v !== '' ? $sh_v : 'invalid') ?>" aria-labelledby="shTitle">
                <p class="sv-eyebrow">Shared certificate</p>
                <?php if (!empty($share_verdict)): ?>
                <div class="sv-seal-stage">
                    <?php if ($share_verdict === 'VALID'): ?>
                    <span class="sv-confetti" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></span>
                    <?php endif; ?>
                    <div class="verdict-seal verdict-seal-<?= strtolower($share_verdict) ?>">
                        <?php if (isset($sh_seal_icons[$share_verdict])): ?><svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true" focusable="false"><?= $sh_seal_icons[$share_verdict] ?></svg><?php endif; ?>
                        <?= htmlspecialchars($share_verdict) ?>
                    </div>
                </div>
                <h1 class="sv-verdict-title" id="shTitle"><?= htmlspecialchars($sh_headlines[$share_verdict] ?? 'Shared Certificate') ?></h1>
                <p class="verdict-detail"><?= htmlspecialchars($share_detail) ?></p>
                <?php else: ?>
                <h1 class="sv-verdict-title" id="shTitle">Shared Certificate</h1>
                <?php endif; ?>
            </section>

            <div class="sv-body sv-result-body">
                <article class="card diploma sv-cert" aria-labelledby="shCertTitle">
                    <header class="sv-cert-head">
                        <span class="sv-cert-mark" aria-hidden="true"><?= $sh_icon('<path d="M12 3 5 6v5c0 4.4 3 8.3 7 10 4-1.7 7-5.6 7-10V6z"/><path d="m9 12 2 2 4-4"/>') ?></span>
                        <div class="sv-cert-heading">
                            <p class="sv-cert-kicker">Issued by <?= htmlspecialchars($cert['institution_name']) ?></p>
                            <h2 class="cert-details-title" id="shCertTitle"><?= htmlspecialchars($cert['title']) ?></h2>
                        </div>
                    </header>
                    <div class="sv-cert-split<?= $cert['qr_token'] ? ' has-qr' : '' ?>">
                        <div class="sv-cert-main">
                            <p class="sv-cert-awarded"><span>Awarded To</span> <strong><?= htmlspecialchars($cert['student_name']) ?></strong></p>
                            <dl class="sv-facts">
                                <div><dt>Institution</dt><dd><?= htmlspecialchars($cert['institution_name']) ?></dd></div>
                                <div><dt>Issue Date</dt><dd><?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></dd></div>
                                <div><dt>Status</dt><dd>
                                    <span class="status-badge status-<?= htmlspecialchars(VerificationService::effectiveStatus($cert)) ?>">
                                        <?= htmlspecialchars(VerificationService::effectiveStatus($cert)) ?>
                                    </span>
                                </dd></div>
                            </dl>
                            <div class="sv-copy-row">
                                <span class="sv-copy-label">Certificate ID</span>
                                <code class="sv-copy-value" id="shCertId"><?= htmlspecialchars($cert['certificate_id']) ?></code>
                                <button type="button" class="btn btn-ghost btn-sm sv-copy" data-copy-target="shCertId" data-copy-message="Certificate ID copied" aria-label="Copy certificate ID"><?= $sh_icon('<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>') ?><span>Copy</span></button>
                            </div>
                        </div>
                        <?php if ($cert['qr_token']): ?>
                            <figure class="sv-qr">
                                <img src="qrcodes/<?= htmlspecialchars($cert['qr_token']) ?>.png" alt="QR Code" class="sv-qr-img" width="150" height="150">
                                <figcaption><strong>Official Verification QR</strong></figcaption>
                            </figure>
                        <?php endif; ?>
                    </div>
                    <p class="sv-share-note"><?= $sh_lock ?>This is a secure, time-limited share link.</p>
                </article>
                <?= is_array($share_quota) ? GuestQuotaService::renderCounter($share_quota) : '' ?>
                <div class="sv-again">
                    <a href="verify.php" class="btn btn-secondary">Verify another certificate</a>
                </div>
            </div>
        <?php endif; ?>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
