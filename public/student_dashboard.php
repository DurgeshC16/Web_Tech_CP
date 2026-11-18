<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/StudentStatsService.php';
require_role('student');

$db = Database::getInstance();

// Get the student's ID based on their user_id
$stmt = $db->prepare('SELECT id FROM students WHERE user_id = :user_id LIMIT 1');
$stmt->execute(['user_id' => $_SESSION['user_id']]);
$student_id = $stmt->fetchColumn();

// Fetch their certificates
$stmt = $db->prepare('
    SELECT c.id, c.certificate_id, c.title, c.issue_date, c.status, c.superseded_by_id, i.name as institution_name
    FROM certificates c
    JOIN institutions i ON c.institution_id = i.id
    WHERE c.student_id = :student_id
    ORDER BY c.issue_date DESC
');
$stmt->execute(['student_id' => $student_id]);
$certificates = $stmt->fetchAll();

// Phase 4: per-certificate verification visibility (read-only stats).
$cert_stats = StudentStatsService::perCertificate($db, (int)$student_id);
$stats_totals = StudentStatsService::totals($db, (int)$student_id);

// ── Presentation only (read-only; never affects access or data) ──────
// First name for the welcome banner; the page still renders without it.
$sd_first_name = '';
try {
    $sd_name_stmt = $db->prepare('SELECT full_name FROM students WHERE id = :sid LIMIT 1');
    $sd_name_stmt->execute(['sid' => (int)$student_id]);
    $sd_full_name = trim((string)$sd_name_stmt->fetchColumn());
    $sd_first_name = $sd_full_name !== '' ? (string)preg_split('/\s+/u', $sd_full_name)[0] : '';
} catch (Throwable $sd_name_error) {
    $sd_first_name = '';
}
$sd_total = count($certificates);
$sd_active = 0;
$sd_institutions = [];
foreach ($certificates as $sd_row) {
    if (VerificationService::effectiveStatus($sd_row) === 'active') { $sd_active++; }
    $sd_institutions[(string)$sd_row['institution_name']] = true;
}
$sd_institution_count = count($sd_institutions);
$sd_last_ts = $stats_totals['last_at'] ? strtotime($stats_totals['last_at']) : false;
$sd_external_enabled = defined('ATTESTED_EXTERNAL_CREDENTIALS_ENABLED') && ATTESTED_EXTERNAL_CREDENTIALS_ENABLED;

// Inline SVG icons (decorative: aria-hidden, never focusable).
$sd_icon = static function (string $name): string {
    $paths = [
        'award'    => '<circle cx="12" cy="8" r="6"/><path d="M15.5 13.2 17 22l-5-3-5 3 1.5-8.8"/>',
        'shield'   => '<path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5z"/><path d="M9 12l2 2 4-4"/>',
        'eye'      => '<path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/>',
        'clock'    => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        'building' => '<path d="M3 21h18M5 21V9l7-5 7 5v12M9 21v-6h6v6"/>',
        'calendar' => '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 11h18"/>',
        'download' => '<path d="M12 3v12m0 0-5-5m5 5 5-5M4 21h16"/>',
        'share'    => '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="M8.6 13.5l6.8 4M15.4 6.5l-6.8 4"/>',
        'code'     => '<path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/>',
        'copy'     => '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/>',
        'arrow'    => '<path d="M5 12h14M13 6l6 6-6 6"/>',
        'search'   => '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
        'key'      => '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3 21 2m-4 4 3 3m-6 0 2 2"/>',
        'globe'    => '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
        'activity' => '<path d="M3 17l6-6 4 4 8-8M15 7h6v6"/>',
    ];
    return '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
        . ($paths[$name] ?? '') . '</svg>';
};
?>
<?php $page_title = 'Student Dashboard - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main" class="stu-main">
    <div class="stu-shell">
        <!-- Welcome banner -->
        <section class="stu-hero" aria-labelledby="stuHeroTitle">
            <div class="hero-orbs" aria-hidden="true"><span></span><span></span><span></span></div>
            <div class="stu-hero-copy">
                <p class="stu-eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span> Student portal</p>
                <h1 id="stuHeroTitle">Welcome back<?= $sd_first_name !== '' ? ', ' . htmlspecialchars($sd_first_name) : '' ?></h1>
                <p class="stu-hero-sub">
                    <?php if ($sd_total > 0): ?>
                        You hold <strong><?= $sd_total ?></strong> certificate<?= $sd_total === 1 ? '' : 's' ?>
                        from <strong><?= $sd_institution_count ?></strong> institution<?= $sd_institution_count === 1 ? '' : 's' ?>.
                        Share them with a link or QR code &mdash; anyone can verify them in seconds.
                    <?php else: ?>
                        This is where your digitally signed certificates will live once an institution issues them.
                    <?php endif; ?>
                </p>
                <div class="stu-hero-actions">
                    <a href="verify.php" class="btn btn-light"><?= $sd_icon('search') ?>Verify a certificate</a>
                    <a href="change_password.php" class="btn btn-outline-light"><?= $sd_icon('key') ?>Change Password</a>
                    <?php if ($sd_external_enabled): ?><a href="external_credentials.php" class="btn btn-outline-light"><?= $sd_icon('globe') ?>External credentials</a><?php endif; ?>
                </div>
            </div>
            <div class="stu-hero-art" aria-hidden="true">
                <svg viewBox="0 0 240 200" width="240" height="200" focusable="false">
                    <rect x="46" y="34" width="150" height="112" rx="14" fill="rgba(255,255,255,0.14)" stroke="rgba(255,255,255,0.35)" transform="rotate(-9 121 90)"/>
                    <rect x="40" y="40" width="160" height="118" rx="14" fill="rgba(255,255,255,0.22)" stroke="rgba(255,255,255,0.45)" transform="rotate(5 120 99)"/>
                    <g class="stu-hero-art-front">
                        <rect x="30" y="46" width="170" height="124" rx="16" fill="rgba(255,255,255,0.95)"/>
                        <rect x="50" y="68" width="78" height="9" rx="4.5" fill="#6d28d9" opacity=".85"/>
                        <rect x="50" y="86" width="104" height="6" rx="3" fill="#94a3b8"/>
                        <rect x="50" y="99" width="88" height="6" rx="3" fill="#cbd5e1"/>
                        <rect x="50" y="138" width="56" height="4" rx="2" fill="#cbd5e1"/>
                        <circle cx="166" cy="134" r="22" fill="#16a34a"/>
                        <circle cx="166" cy="134" r="27" fill="none" stroke="#16a34a" stroke-opacity=".35" stroke-width="3"/>
                        <path class="stu-hero-art-check" pathLength="100" d="M156 134l7 7 13-14" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
                    </g>
                    <circle cx="214" cy="40" r="5" fill="#a5f3fc"/>
                    <circle cx="22" cy="150" r="4" fill="#f5d0fe"/>
                    <circle cx="200" cy="182" r="3" fill="#c4b5fd"/>
                </svg>
            </div>
        </section>

        <!-- Animated stat tiles -->
        <div class="stat-grid stu-stats" role="list" aria-label="Your certificate statistics">
            <div class="stu-reveal" role="listitem" data-reveal data-reveal-delay="1"><div class="stat-card">
                <span class="stat-icon"><?= $sd_icon('award') ?></span>
                <span class="stat-num" data-count-to="<?= $sd_total ?>"><?= number_format($sd_total) ?></span>
                <span class="stat-label">Certificate<?= $sd_total === 1 ? '' : 's' ?> &middot; <?= $sd_active ?> active</span>
            </div></div>
            <div class="stu-reveal" role="listitem" data-reveal data-reveal-delay="2"><div class="stat-card">
                <span class="stat-icon stu-icon-cyan"><?= $sd_icon('eye') ?></span>
                <span class="stat-num" data-count-to="<?= (int)$stats_totals['verifications'] ?>"><?= number_format((int)$stats_totals['verifications']) ?></span>
                <span class="stat-label">Verification<?= (int)$stats_totals['verifications'] === 1 ? '' : 's' ?></span>
            </div></div>
            <div class="stu-reveal" role="listitem" data-reveal data-reveal-delay="3"><div class="stat-card">
                <span class="stat-icon stu-icon-green"><?= $sd_icon('shield') ?></span>
                <span class="stat-num" data-count-to="<?= (int)$stats_totals['valid_hits'] ?>"><?= number_format((int)$stats_totals['valid_hits']) ?></span>
                <span class="stat-label">Reached a VALID seal</span>
            </div></div>
            <div class="stu-reveal" role="listitem" data-reveal data-reveal-delay="4"><div class="stat-card">
                <span class="stat-icon stu-icon-amber"><?= $sd_icon('clock') ?></span>
                <?php if ($sd_last_ts): ?>
                    <span class="stat-num stu-stat-date"><time datetime="<?= htmlspecialchars(date('Y-m-d\TH:i', $sd_last_ts)) ?>"><?= htmlspecialchars(date('M j, Y', $sd_last_ts)) ?></time></span>
                    <span class="stat-label">Last verified &middot; <?= htmlspecialchars(date('H:i', $sd_last_ts)) ?></span>
                <?php else: ?>
                    <span class="stat-num stu-stat-date">Not yet</span>
                    <span class="stat-label">Last verified</span>
                <?php endif; ?>
            </div></div>
        </div>

        <?php if (count($certificates) > 0): ?>
            <div class="stu-activity" data-reveal>
                <span class="stu-activity-icon"><?= $sd_icon('activity') ?></span>
                <p>
                    <strong>Verification activity:</strong>
                    Your certificates have been verified
                    <strong><?= (int)$stats_totals['verifications'] ?></strong> time<?= $stats_totals['verifications'] === 1 ? '' : 's' ?>
                    (<?= (int)$stats_totals['valid_hits'] ?> reached a <strong>VALID</strong> seal).
                    <?php if ($stats_totals['last_at']): ?>
                        Most recent check: <?= htmlspecialchars(date('Y-m-d H:i', strtotime($stats_totals['last_at']))) ?> (UTC in logs).
                    <?php else: ?>
                        Nobody has verified them yet.
                    <?php endif; ?>
                </p>
            </div>
        <?php endif; ?>

        <section class="stu-section" aria-labelledby="stuCertsTitle">
            <div class="stu-section-head">
                <h2 id="stuCertsTitle">My Certificates</h2>
                <?php if ($sd_total > 0): ?><span class="pill"><?= $sd_total ?> total</span><?php endif; ?>
            </div>

            <?php if (count($certificates) > 0): ?>
                <div class="stu-cert-grid">
                    <?php foreach ($certificates as $sd_i => $cert): ?>
                        <?php
                        $cstat = $cert_stats[(int)$cert['id']] ?? null;
                        $effStatus = VerificationService::effectiveStatus($cert);
                        $sd_badge = $effStatus === 'active' ? 'valid' : $effStatus;
                        $sd_view = 'view_certificate_student.php?id=' . (int)$cert['id'];
                        ?>
                        <div class="stu-reveal" data-reveal data-reveal-delay="<?= ($sd_i % 3) + 1 ?>">
                        <article class="card card-hover stu-cert-card stu-cert-<?= htmlspecialchars($sd_badge) ?>" aria-labelledby="stuCert<?= (int)$cert['id'] ?>">
                            <div class="stu-cert-top">
                                <span class="stu-cert-icon"><?= $sd_icon('award') ?></span>
                                <span class="badge-status badge-<?= htmlspecialchars($sd_badge) ?>">
                                    <?= htmlspecialchars($effStatus) ?>
                                </span>
                            </div>
                            <h3 class="card-title" id="stuCert<?= (int)$cert['id'] ?>"><?= htmlspecialchars($cert['title']) ?></h3>
                            <p class="stu-cert-inst"><?= $sd_icon('building') ?><span><?= htmlspecialchars($cert['institution_name']) ?></span></p>
                            <dl class="stu-cert-meta">
                                <div>
                                    <dt>Certificate ID</dt>
                                    <dd class="stu-cert-id">
                                        <span class="mono"><?= htmlspecialchars($cert['certificate_id']) ?></span>
                                        <button type="button" class="stu-copy" data-copy="<?= htmlspecialchars($cert['certificate_id']) ?>" data-copy-message="Certificate ID copied" aria-label="Copy certificate ID <?= htmlspecialchars($cert['certificate_id']) ?>" title="Copy certificate ID"><?= $sd_icon('copy') ?></button>
                                    </dd>
                                </div>
                                <div>
                                    <dt>Issued</dt>
                                    <dd><time datetime="<?= htmlspecialchars(date('Y-m-d', strtotime($cert['issue_date']))) ?>"><?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></time></dd>
                                </div>
                            </dl>
                            <?php if ($cstat): ?>
                                <p class="stu-cert-stat">
                                    <?= $sd_icon('eye') ?>
                                    <span>
                                        Verified <?= (int)$cstat['verifications'] ?>&times;
                                        <?php if ($cstat['last_at']): ?>
                                            &middot; last <?= htmlspecialchars(date('Y-m-d H:i', strtotime($cstat['last_at']))) ?>
                                        <?php endif; ?>
                                    </span>
                                </p>
                            <?php endif; ?>
                            <?php if ($cert['status'] === 'superseded' && !empty($cert['superseded_by_id'])): ?>
                                <p class="stu-cert-note">
                                    This version has been replaced. <a href="view_certificate_student.php?id=<?= (int)$cert['superseded_by_id'] ?>">View current version &rarr;</a>
                                </p>
                            <?php endif; ?>
                            <div class="card-actions stu-cert-actions">
                                <a href="<?= $sd_view ?>" class="btn btn-primary btn-sm stu-cert-view">View Details<?= $sd_icon('arrow') ?></a>
                                <?php if ($effStatus === 'active'): ?>
                                    <a href="download.php?id=<?= (int)$cert['id'] ?>" class="btn btn-secondary btn-sm" aria-label="Download <?= htmlspecialchars($cert['title']) ?>"><?= $sd_icon('download') ?>Download</a>
                                    <a href="<?= $sd_view ?>#share" class="btn btn-secondary btn-sm" aria-label="Share <?= htmlspecialchars($cert['title']) ?>"><?= $sd_icon('share') ?>Share</a>
                                    <a href="credential.php?certificate_id=<?= rawurlencode((string)$cert['certificate_id']) ?>" class="btn btn-ghost btn-sm stu-cert-wide" aria-label="Export signed credential (JSON) for <?= htmlspecialchars($cert['title']) ?>"><?= $sd_icon('code') ?>Signed credential (JSON)</a>
                                <?php endif; ?>
                            </div>
                        </article>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="empty-state stu-empty" data-reveal="zoom">
                    <svg class="stu-empty-art" viewBox="0 0 200 150" width="200" height="150" aria-hidden="true" focusable="false">
                        <ellipse cx="100" cy="136" rx="70" ry="8" class="stu-empty-shadow"/>
                        <g class="stu-empty-float">
                            <rect x="38" y="22" width="124" height="92" rx="12" class="stu-empty-card"/>
                            <rect x="56" y="42" width="58" height="8" rx="4" class="stu-empty-line-strong"/>
                            <rect x="56" y="60" width="86" height="6" rx="3" class="stu-empty-line"/>
                            <rect x="56" y="74" width="70" height="6" rx="3" class="stu-empty-line"/>
                            <circle cx="138" cy="96" r="16" class="stu-empty-seal"/>
                            <path d="M131 96l5 5 9-10" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
                        </g>
                        <circle cx="30" cy="34" r="4" class="stu-empty-dot"/>
                        <circle cx="176" cy="24" r="3" class="stu-empty-dot"/>
                        <circle cx="172" cy="120" r="5" class="stu-empty-dot"/>
                    </svg>
                    <h3>No certificates yet</h3>
                    <p>You have not been issued any certificates yet. When an institution issues one to you, it appears here &mdash; ready to download, share and verify.</p>
                    <a href="verify.php" class="btn btn-primary"><?= $sd_icon('search') ?>Verify a certificate</a>
                </div>
            <?php endif; ?>
        </section>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
