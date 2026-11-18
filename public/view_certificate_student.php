<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/TrustScoreService.php';
require_role('student');

$db = Database::getInstance();
$cert_id = (int)($_GET['id'] ?? 0);
$share_link = '';

// Get student_id
$student_id = current_student_id($db);

// Fetch certificate details — ownership enforced centrally (uniform 403).
$cert = require_owned_certificate(
    $db,
    $cert_id,
    'student',
    $student_id,
    'c.*, i.name as institution_name, ik.public_key, ik.status AS signing_key_status',
    'JOIN institutions i ON c.institution_id = i.id LEFT JOIN institution_keys ik ON ik.institution_id = c.institution_id AND ik.key_id = c.key_id'
);

// Phase 4: same rule-based trust score the public verifier sees.
try {
    $trusted = TrustScoreService::compute($db, $cert);
} catch (Throwable $trustError) {
    error_log('[CertiVault] Student trust score failed: ' . $trustError->getMessage());
    $trusted = null;
}

// Generate Share Link Logic
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['generate_share'])) {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    $expiry = time() + (24 * 3600); // Valid for 24 hours
    $payload = json_encode(['id' => $cert['id'], 'exp' => $expiry]);
    $encoded_payload = rtrim(strtr(base64_encode($payload), '+/', '-_'), '=');
    $signature = hash_hmac('sha256', $encoded_payload, SHARE_LINK_SECRET);
    
    $token = $encoded_payload . '.' . $signature;
    $share_link = BASE_URL . '/share.php?token=' . urlencode($token);
}
?>
<?php
// ── Presentation only (read-only; never affects access or data) ──────
require_once __DIR__ . '/../src/services/StudentStatsService.php';
$vc_status = VerificationService::effectiveStatus($cert);
$vc_badge = $vc_status === 'active' ? 'valid' : $vc_status;
$vc_active = $vc_status === 'active';
$vc_student_name = '';
$vc_stats = null;
try {
    $vc_name_stmt = $db->prepare('SELECT full_name FROM students WHERE id = :sid LIMIT 1');
    $vc_name_stmt->execute(['sid' => (int)$student_id]);
    $vc_student_name = trim((string)$vc_name_stmt->fetchColumn());
    $vc_stats = StudentStatsService::perCertificate($db, (int)$student_id)[(int)$cert['id']] ?? null;
} catch (Throwable $vc_error) {
    error_log('[CertiVault] Student certificate view stats failed: ' . $vc_error->getMessage());
}
$vc_verify_url = !empty($cert['qr_token']) ? BASE_URL . '/verify.php?token=' . $cert['qr_token'] : '';
$vc_score = $trusted ? max(0, min(100, (int)$trusted['score'])) : 0;
$vc_band = $vc_score >= 80 ? 'high' : ($vc_score >= 50 ? 'mid' : 'low');
$vc_checks = $trusted['checks'] ?? [];
$vc_passed = count(array_filter($vc_checks, static fn($c) => !empty($c['pass'])));
$vc_icon = static function (string $name): string {
    $paths = [
        'award'    => '<circle cx="12" cy="8" r="6"/><path d="M15.5 13.2 17 22l-5-3-5 3 1.5-8.8"/>',
        'shield'   => '<path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5z"/><path d="M9 12l2 2 4-4"/>',
        'clock'    => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        'download' => '<path d="M12 3v12m0 0-5-5m5 5 5-5M4 21h16"/>',
        'share'    => '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="M8.6 13.5l6.8 4M15.4 6.5l-6.8 4"/>',
        'code'     => '<path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/>',
        'copy'     => '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/>',
        'back'     => '<path d="M19 12H5M11 18l-6-6 6-6"/>',
        'file'     => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M9 13h6M9 17h6"/>',
        'link'     => '<path d="M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7"/><path d="M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
        'check'    => '<path d="M5 13l4 4L19 7"/>',
        'x'        => '<path d="M18 6 6 18M6 6l12 12"/>',
        'lock'     => '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
        'activity' => '<path d="M3 17l6-6 4 4 8-8M15 7h6v6"/>',
    ];
    return '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
        . ($paths[$name] ?? '') . '</svg>';
};
?>
<?php $page_title = 'View Certificate - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main" class="stu-main">
    <div class="stu-shell stu-view">
        <nav class="stu-crumbs" aria-label="Breadcrumb">
            <ol>
                <li><a href="student_dashboard.php">My Certificates</a></li>
                <li aria-current="page">Certificate Details</li>
            </ol>
        </nav>

        <div class="page-head stu-view-head">
            <div class="stu-view-title">
                <p class="eyebrow">Certificate Details</p>
                <h1><?= htmlspecialchars($cert['title']) ?></h1>
                <p class="page-head-sub">
                    Issued by <strong><?= htmlspecialchars($cert['institution_name']) ?></strong>
                    on <?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?>
                </p>
            </div>
            <div class="page-head-actions">
                <a href="student_dashboard.php" class="btn btn-secondary"><?= $vc_icon('back') ?>Back</a>
            </div>
        </div>

        <?php if ($cert['status'] === 'superseded' && !empty($cert['superseded_by_id'])): ?>
            <div class="alert alert-info">
                <strong>This version has been superseded.</strong> A corrected version has been issued.<br>
                <a href="view_certificate_student.php?id=<?= (int)$cert['superseded_by_id'] ?>">View Current Version →</a>
            </div>
        <?php endif; ?>

        <?php if ($cert['status'] === 'revoked'): ?>
            <div class="alert alert-danger">
                <strong>This certificate has been revoked</strong> by the issuing institution and is no longer valid.
            </div>
        <?php endif; ?>

        <?php if ($share_link): ?>
            <div class="alert alert-success stu-share-result">
                <strong>Share Link:</strong><br>
                <div class="copy-field">
                    <input type="text" id="shareLinkInput" class="share-input" value="<?= htmlspecialchars($share_link) ?>" readonly data-select-on-click aria-label="Share link (valid for 24 hours)">
                    <button type="button" class="btn btn-secondary" id="copyShareBtn"><?= $vc_icon('copy') ?>Copy</button>
                </div>
                <small>This link is valid for 24 hours.</small>
            </div>
            <div class="toast toast-success" id="copiedToast" role="status" hidden>Link copied to clipboard!</div>
        <?php endif; ?>

        <div class="stu-view-grid">
            <div class="stu-view-main">
                <!-- Certificate preview -->
                <section class="diploma stu-diploma stu-diploma-<?= htmlspecialchars($vc_badge) ?>" aria-labelledby="certPreviewTitle" data-tilt data-reveal="zoom">
                    <div class="stu-diploma-top">
                        <span class="stu-diploma-brand">
                            <span class="stu-diploma-logo"><?= $vc_icon('shield') ?></span>
                            CertiVault &middot; digitally signed
                        </span>
                        <span class="badge-status badge-<?= htmlspecialchars($vc_badge) ?>">
                            <?= htmlspecialchars($vc_status) ?>
                        </span>
                    </div>
                    <p class="stu-diploma-kicker">Certificate</p>
                    <h2 class="cert-details-title" id="certPreviewTitle"><?= htmlspecialchars($cert['title']) ?></h2>
                    <?php if ($vc_student_name !== ''): ?>
                        <p class="stu-diploma-awarded">Awarded to <strong><?= htmlspecialchars($vc_student_name) ?></strong></p>
                    <?php endif; ?>
                    <dl class="cert-details stu-diploma-details">
                        <dt>Certificate ID</dt>
                        <dd class="stu-cert-id">
                            <span class="mono"><?= htmlspecialchars($cert['certificate_id']) ?></span>
                            <button type="button" class="stu-copy" data-copy="<?= htmlspecialchars($cert['certificate_id']) ?>" data-copy-message="Certificate ID copied" aria-label="Copy certificate ID" title="Copy certificate ID"><?= $vc_icon('copy') ?></button>
                        </dd>
                        <dt>Version</dt>
                        <dd><?= (int)$cert['version'] ?></dd>
                        <dt>Institution</dt>
                        <dd><?= htmlspecialchars($cert['institution_name']) ?></dd>
                        <dt>Issue Date</dt>
                        <dd><?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></dd>
                        <?php if ($cert['expiry_date']): ?>
                            <dt>Expiry Date</dt>
                            <dd><?= htmlspecialchars(date('F j, Y', strtotime($cert['expiry_date']))) ?></dd>
                        <?php endif; ?>
                        <dt>Status</dt>
                        <dd>
                            <span class="badge-status badge-<?= htmlspecialchars($vc_badge) ?>">
                                <?= htmlspecialchars($vc_status) ?>
                            </span>
                        </dd>
                    </dl>
                    <div class="stu-diploma-foot" aria-hidden="true">
                        <span class="stu-diploma-sign"><?= htmlspecialchars($cert['institution_name']) ?></span>
                        <span class="stu-diploma-seal"><?= $vc_icon('award') ?></span>
                    </div>
                </section>

                <?php if ($vc_active): ?>
                <div class="actions-row stu-export">
                    <a href="download.php?id=<?= (int)$cert['id'] ?>" class="btn btn-primary"><?= $vc_icon('download') ?>Download File</a>
                    <a href="report.php?cert=<?= rawurlencode((string)$cert['certificate_id']) ?>" class="btn btn-secondary">
                        <?= $vc_icon('file') ?>Verification report (PDF)
                    </a>
                    <a href="credential.php?certificate_id=<?= rawurlencode((string)$cert['certificate_id']) ?>" class="btn btn-secondary">
                        <?= $vc_icon('code') ?>Signed credential (JSON)
                    </a>
                </div>
                <?php endif; ?>

                <?php if ($trusted): ?>
                <section class="card stu-trust stu-trust-<?= $vc_band ?>" aria-labelledby="trustTitle" data-reveal>
                    <div class="stu-trust-head">
                        <div class="stu-ring" aria-hidden="true">
                            <svg viewBox="0 0 120 120" width="120" height="120" focusable="false">
                                <circle class="stu-ring-track" cx="60" cy="60" r="50"/>
                                <circle class="stu-ring-bar" cx="60" cy="60" r="50" pathLength="100" stroke-dasharray="<?= $vc_score ?> 100"/>
                            </svg>
                            <span class="stu-ring-label"><span class="stu-ring-num" data-count-to="<?= $vc_score ?>"><?= $vc_score ?></span><span class="stu-ring-max">/ 100</span></span>
                        </div>
                        <div class="stu-trust-copy">
                            <h2 id="trustTitle">Trust score: <?= (int)$trusted['score'] ?> / 100</h2>
                            <?php if (($trusted['verdict'] ?? '') !== 'VALID'): ?>
                                <span class="badge-status badge-<?= strtolower(htmlspecialchars($trusted['verdict'])) ?>">
                                    <?= htmlspecialchars($trusted['verdict']) ?>
                                </span>
                            <?php else: ?>
                                <span class="badge-status badge-valid">VALID</span>
                            <?php endif; ?>
                            <p class="stu-trust-sum"><?= $vc_passed ?> of <?= count($vc_checks) ?> checks passed &mdash; the same rules the public verifier applies.</p>
                        </div>
                    </div>
                    <ul class="check-list stu-checks">
                        <?php foreach ($vc_checks as $check_row): ?>
                        <li class="check <?= $check_row['pass'] ? 'check-pass' : 'check-fail' ?>">
                            <span class="stu-check-icon"><?= $vc_icon($check_row['pass'] ? 'check' : 'x') ?></span>
                            <span class="visually-hidden"><?= $check_row['pass'] ? 'Passed:' : 'Failed:' ?></span>
                            <span><?= htmlspecialchars((string)$check_row['label']) ?></span>
                        </li>
                        <?php endforeach; ?>
                    </ul>
                    <small class="stu-trust-note"><?= htmlspecialchars(TrustScoreService::DISCLAIMER) ?></small>
                </section>
                <?php endif; ?>
            </div>

            <aside class="stu-view-side" aria-label="Share and activity">
                <!-- Share panel -->
                <section class="card stu-panel" id="share" aria-labelledby="shareTitle" data-reveal data-reveal-delay="1">
                    <div class="stu-panel-head">
                        <span class="stu-panel-icon"><?= $vc_icon('share') ?></span>
                        <h2 id="shareTitle">Share &amp; verify</h2>
                    </div>
                    <?php if ($vc_active): ?>
                        <div class="qr-hero stu-qr">
                            <p><strong>Verification QR:</strong></p>
                            <img src="qrcodes/<?= htmlspecialchars($cert['qr_token']) ?>.png" alt="QR Code" width="200" height="200">
                            <p class="stu-qr-caption">Anyone can scan this to check the certificate.</p>
                        </div>
                        <?php if ($vc_verify_url !== ''): ?>
                            <button type="button" class="btn btn-secondary btn-block" data-copy="<?= htmlspecialchars($vc_verify_url) ?>" data-copy-message="Verification link copied"><?= $vc_icon('link') ?>Copy verification link</button>
                        <?php endif; ?>
                        <form method="POST" action="" class="inline-form stu-share-form">
                            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                            <input type="hidden" name="generate_share" value="1">
                            <button type="submit" class="btn btn-verified btn-block"><?= $vc_icon('clock') ?>Generate Share Link (24h)</button>
                        </form>
                        <p class="stu-panel-note">A share link opens a read-only page for 24 hours, then stops working.</p>
                    <?php else: ?>
                        <p class="stu-panel-locked"><?= $vc_icon('lock') ?><span>Sharing, the QR code and downloads are available only while the certificate is active.</span></p>
                    <?php endif; ?>
                </section>

                <!-- Verification activity -->
                <section class="card stu-panel" aria-labelledby="activityTitle" data-reveal data-reveal-delay="2">
                    <div class="stu-panel-head">
                        <span class="stu-panel-icon stu-icon-cyan"><?= $vc_icon('activity') ?></span>
                        <h2 id="activityTitle">Verification activity</h2>
                    </div>
                    <?php if ($vc_stats !== null): ?>
                        <dl class="stu-mini-stats">
                            <div>
                                <dt>Checks</dt>
                                <dd data-count-to="<?= (int)$vc_stats['verifications'] ?>"><?= number_format((int)$vc_stats['verifications']) ?></dd>
                            </div>
                            <div>
                                <dt>VALID seals</dt>
                                <dd data-count-to="<?= (int)$vc_stats['valid_hits'] ?>"><?= number_format((int)$vc_stats['valid_hits']) ?></dd>
                            </div>
                        </dl>
                        <p class="stu-panel-note">
                            <?php if ($vc_stats['last_at']): ?>
                                Last checked <?= htmlspecialchars(date('Y-m-d H:i', strtotime($vc_stats['last_at']))) ?> (UTC in logs).
                            <?php else: ?>
                                Nobody has verified this certificate yet. Share it to get started.
                            <?php endif; ?>
                        </p>
                    <?php else: ?>
                        <p class="stu-panel-note">Verification activity is unavailable right now.</p>
                    <?php endif; ?>
                </section>
            </aside>
        </div>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
