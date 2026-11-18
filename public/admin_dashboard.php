<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_role('admin');
require_approved_institution();

$db = Database::getInstance();

// Get Institution ID for the logged-in user
$stmt = $db->prepare('SELECT id, name FROM institutions WHERE user_id = :user_id LIMIT 1');
$stmt->execute(['user_id' => $_SESSION['user_id']]);
$institution = $stmt->fetch();
$institution_id = $institution['id'] ?? null;
$active_key = null;
if ($institution_id && defined('CERTIFICATE_TRANSPARENCY_ENABLED') && CERTIFICATE_TRANSPARENCY_ENABLED) {
    $keyStmt = $db->prepare('SELECT key_id,public_key,valid_from FROM institution_keys WHERE institution_id=:iid AND status="active" ORDER BY key_id DESC LIMIT 1');
    $keyStmt->execute(['iid'=>$institution_id]);
    $active_key = $keyStmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

if (!$institution_id) {
    show_error_page('Error', 'Institution profile not found.');
}

// ── Statistics ────────────────────────────────────────────────────
$stats_stmt = $db->prepare("SELECT
    COUNT(*) AS total,
    SUM(status = 'active') AS active,
    SUM(status IN ('revoked','superseded')) AS revoked_superseded
    FROM certificates WHERE institution_id = :iid");
$stats_stmt->execute(['iid' => $institution_id]);
$stats = $stats_stmt->fetch();

$verif_stmt = $db->prepare("SELECT COUNT(*) FROM verification_logs v
    JOIN certificates c ON v.certificate_id_found = c.certificate_id
    WHERE c.institution_id = :iid");
$verif_stmt->execute(['iid' => $institution_id]);
$verification_count = (int)$verif_stmt->fetchColumn();

// ── Search / filter ───────────────────────────────────────────────
$search = trim($_GET['q'] ?? '');
$status_filter = $_GET['status'] ?? '';
$where = 'WHERE c.institution_id = :inst_id';
$params = ['inst_id' => $institution_id];
if ($search !== '') {
    // Escape LIKE wildcards so IDs containing % or _ match literally.
    $q_esc = addcslashes($search, '%_\\');
    $where .= ' AND (c.title LIKE :q ESCAPE \'\\\' OR c.certificate_id LIKE :q ESCAPE \'\\\' OR s.full_name LIKE :q ESCAPE \'\\\')';
    $params['q'] = '%' . $q_esc . '%';
}
if (in_array($status_filter, ['active', 'revoked', 'superseded', 'expired'], true)) {
    $where .= ' AND c.status = :st';
    $params['st'] = $status_filter;
}

$stmt = $db->prepare("
    SELECT c.id, c.certificate_id, c.title, c.issue_date, c.expiry_date, c.status, s.full_name as student_name
    FROM certificates c
    JOIN students s ON c.student_id = s.id
    $where
    ORDER BY c.issue_date DESC
");
$stmt->execute($params);
$certificates = $stmt->fetchAll();
?>
<?php
// ── Presentation only (no queries below this line) ───────────────
require_once __DIR__ . '/../src/utils/admin_ui.php';
$kpi_total = (int)$stats['total'];
$kpi_active = (int)$stats['active'];
$kpi_closed = (int)$stats['revoked_superseded'];
$kpi_active_pct = $kpi_total > 0 ? (int)round(100 * $kpi_active / $kpi_total) : 0;
$kpi_closed_pct = $kpi_total > 0 ? (int)round(100 * $kpi_closed / $kpi_total) : 0;
$cert_count = count($certificates);
$is_filtered = $search !== '' || $status_filter !== '';
$transparency_on = defined('CERTIFICATE_TRANSPARENCY_ENABLED') && CERTIFICATE_TRANSPARENCY_ENABLED;
$attest_on = defined('ATTESTED_EXTERNAL_CREDENTIALS_ENABLED') && ATTESTED_EXTERNAL_CREDENTIALS_ENABLED;
$page_title = 'Admin Dashboard - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main">
    <div class="admin-shell">
        <section class="admin-hero" aria-labelledby="dashTitle">
            <span class="admin-hero-art" aria-hidden="true"><?= cv_icon('shield') ?></span>
            <div class="admin-hero-grid">
                <div>
                    <span class="admin-eyebrow"><?= cv_icon('building') ?> Institution dashboard</span>
                    <h1 id="dashTitle"><?= htmlspecialchars($institution['name']) ?></h1>
                    <p class="admin-hero-sub">Issue tamper-evident certificates, follow every verification and keep your records trustworthy.</p>
                    <div class="hero-chips">
                        <span class="hero-chip"><?= cv_icon('shield') ?> Approved issuer</span>
                        <?php if ($active_key): $fp = CryptoService::fingerprintPublicKey($active_key['public_key']); ?>
                            <span class="hero-chip" title="SHA-256 fingerprint of your active signing key">
                                <?= cv_icon('key') ?> <span class="hero-chip-label">Key v<?= (int)$active_key['key_id'] ?></span>
                                <code id="keyFingerprint"><?= htmlspecialchars($fp) ?></code>
                                <button type="button" class="hero-chip-btn" data-copy-target="keyFingerprint" data-copy-message="Fingerprint copied" aria-label="Copy key fingerprint"><?= cv_icon('copy') ?></button>
                            </span>
                            <a class="hero-chip" href="institutions.php#institution-<?= (int)$institution_id ?>"><?= cv_icon('external') ?> Public key directory</a>
                        <?php endif; ?>
                    </div>
                </div>
                <div class="admin-hero-actions">
                    <a href="issue_certificate.php" class="btn btn-light btn-lg"><?= cv_icon('plus') ?> Issue New Certificate</a>
                    <?php if ($transparency_on): ?><a href="rotate_key.php" class="btn btn-outline-light"><?= cv_icon('key') ?> Rotate key</a><?php endif; ?>
                    <?php if ($attest_on): ?><a href="attest_external_credentials.php" class="btn btn-outline-light"><?= cv_icon('inbox') ?> External attestation queue</a><?php endif; ?>
                </div>
            </div>
        </section>

        <section class="stat-grid kpi-grid" aria-label="Certificate statistics">
            <div class="stat-card" data-reveal data-reveal-delay="1">
                <span class="stat-icon"><?= cv_icon('award') ?></span>
                <span class="stat-num" data-count-to="<?= $kpi_total ?>"><?= $kpi_total ?></span>
                <span class="stat-label">Total Issued</span>
                <span class="stat-hint">All versions, all time</span>
            </div>
            <div class="stat-card" data-reveal data-reveal-delay="2">
                <span class="stat-icon stat-icon-valid"><?= cv_icon('check') ?></span>
                <span class="stat-num" data-count-to="<?= $kpi_active ?>"><?= $kpi_active ?></span>
                <span class="stat-label">Active</span>
                <span class="stat-meter stat-meter-valid" aria-hidden="true"><span data-pct="<?= $kpi_active_pct ?>"></span></span>
                <span class="stat-hint"><?= $kpi_active_pct ?>% of everything issued</span>
            </div>
            <div class="stat-card" data-reveal data-reveal-delay="3">
                <span class="stat-icon stat-icon-danger"><?= cv_icon('ban') ?></span>
                <span class="stat-num" data-count-to="<?= $kpi_closed ?>"><?= $kpi_closed ?></span>
                <span class="stat-label">Revoked / Superseded</span>
                <span class="stat-meter stat-meter-danger" aria-hidden="true"><span data-pct="<?= $kpi_closed_pct ?>"></span></span>
                <span class="stat-hint"><?= $kpi_closed_pct ?>% replaced or withdrawn</span>
            </div>
            <div class="stat-card" data-reveal data-reveal-delay="4">
                <span class="stat-icon stat-icon-info"><?= cv_icon('activity') ?></span>
                <span class="stat-num" data-count-to="<?= $verification_count ?>"><?= $verification_count ?></span>
                <span class="stat-label">Verifications</span>
                <span class="stat-hint">Lookups of your certificates</span>
            </div>
        </section>

        <section aria-labelledby="quickTitle">
            <div class="section-label">
                <h2 id="quickTitle">Quick actions</h2>
                <p>Everything you need, one click away</p>
            </div>
            <div class="quick-actions">
                <a class="action-card" href="issue_certificate.php" data-tilt data-reveal data-reveal-delay="1">
                    <span class="action-icon"><?= cv_icon('award') ?></span>
                    <span class="action-title">Issue a certificate</span>
                    <span class="action-desc">Upload one document, sign it and email the student a QR seal.</span>
                    <span class="action-go">Start issuing <?= cv_icon('arrow-right') ?></span>
                </a>
                <a class="action-card" href="bulk_issue.php" data-tilt data-reveal data-reveal-delay="2">
                    <span class="action-icon action-icon-bulk"><?= cv_icon('layers') ?></span>
                    <span class="action-title">Bulk issue from CSV</span>
                    <span class="action-desc">Preview a whole cohort, then issue every valid row at once.</span>
                    <span class="action-go">Upload a CSV <?= cv_icon('arrow-right') ?></span>
                </a>
                <a class="action-card" href="analytics.php" data-tilt data-reveal data-reveal-delay="3">
                    <span class="action-icon action-icon-analytics"><?= cv_icon('chart') ?></span>
                    <span class="action-title">Analytics</span>
                    <span class="action-desc">Daily verifications, verdict mix and most-checked certificates.</span>
                    <span class="action-go">See trends <?= cv_icon('arrow-right') ?></span>
                </a>
                <a class="action-card" href="audit_logs.php" data-tilt data-reveal data-reveal-delay="4">
                    <span class="action-icon action-icon-audit"><?= cv_icon('history') ?></span>
                    <span class="action-title">Audit logs</span>
                    <span class="action-desc">Every verification attempt, with verdict, reason and IP.</span>
                    <span class="action-go">Review activity <?= cv_icon('arrow-right') ?></span>
                </a>
            </div>
        </section>

        <section class="card data-card" aria-labelledby="certsTitle">
            <div class="card-head">
                <div class="card-head-text">
                    <h2 id="certsTitle">Issued Certificates</h2>
                    <p><?= $is_filtered ? 'Filtered results — clear the filters to see everything.' : 'Newest first. Type to filter instantly, press Enter to search the server.' ?></p>
                </div>
                <span class="count-pill" id="certCount"><?= $cert_count ?> shown</span>
            </div>

            <form method="GET" action="" class="toolbar" role="search" aria-label="Search certificates">
                <div class="form-group toolbar-grow">
                    <label for="dashSearch">Search</label>
                    <span class="search-field">
                        <input type="text" name="q" id="dashSearch" value="<?= htmlspecialchars($search) ?>" placeholder="Title, ID or student name"
                               data-table-filter="certTable" data-filter-count="certCount" data-filter-empty="certFilterEmpty" autocomplete="off">
                        <?= cv_icon('search') ?>
                    </span>
                </div>
                <div class="form-group">
                    <label for="dashStatus">Status</label>
                    <select name="status" id="dashStatus">
                        <option value="">All</option>
                        <?php foreach (['active', 'expired', 'revoked', 'superseded'] as $s): ?>
                            <option value="<?= $s ?>" <?= $status_filter === $s ? 'selected' : '' ?>><?= ucfirst($s) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="toolbar-actions">
                    <button type="submit" class="btn btn-primary"><?= cv_icon('filter') ?> Apply</button>
                    <a href="admin_dashboard.php" class="btn btn-ghost">Clear</a>
                </div>
            </form>

            <?php if ($cert_count > 0): ?>
                <div class="table-wrap">
                <table class="table table-striped admin-table" id="certTable">
                    <thead>
                        <tr><th scope="col">Certificate</th><th scope="col">Student</th><th scope="col">Issue Date</th><th scope="col">Status</th><th scope="col" class="actions-cell">Action</th></tr>
                    </thead>
                    <tbody>
                    <?php foreach ($certificates as $cert): $effStatus = VerificationService::effectiveStatus($cert); ?>
                        <tr>
                            <td data-label="Certificate">
                                <span class="cell-stack">
                                    <span class="cell-title"><?= htmlspecialchars($cert['title']) ?></span>
                                    <span class="id-chip"><?= htmlspecialchars($cert['certificate_id']) ?></span>
                                </span>
                            </td>
                            <td data-label="Student">
                                <span class="cell-main">
                                    <span class="avatar avatar-<?= cv_avatar_hue($cert['student_name']) ?>" aria-hidden="true"><?= htmlspecialchars(cv_initials($cert['student_name'])) ?></span>
                                    <span class="cell-title"><?= htmlspecialchars($cert['student_name']) ?></span>
                                </span>
                            </td>
                            <td data-label="Issue Date" class="nowrap"><?= htmlspecialchars(date('M j, Y', strtotime($cert['issue_date']))) ?></td>
                            <td data-label="Status">
                                <span class="badge-status badge-<?= htmlspecialchars($effStatus === 'active' ? 'valid' : $effStatus) ?>"><?= htmlspecialchars($effStatus) ?></span>
                            </td>
                            <td data-label="Action" class="actions-cell">
                                <span class="row-actions">
                                    <a href="view_certificate_admin.php?id=<?= (int)$cert['id'] ?>" class="btn btn-secondary btn-sm"><?= cv_icon('eye') ?> View</a>
                                    <?php if (in_array($effStatus, ['active', 'expired'], true)): ?>
                                        <a href="supersede_certificate.php?id=<?= (int)$cert['id'] ?>" class="btn btn-ghost btn-warn-ghost btn-sm btn-icon-sm" title="Supersede / correct" aria-label="Supersede <?= htmlspecialchars($cert['certificate_id']) ?>"><?= cv_icon('refresh') ?></a>
                                        <a href="revoke_certificate.php?id=<?= (int)$cert['id'] ?>" class="btn btn-ghost btn-danger-ghost btn-sm btn-icon-sm" title="Revoke" aria-label="Revoke <?= htmlspecialchars($cert['certificate_id']) ?>"><?= cv_icon('ban') ?></a>
                                    <?php endif; ?>
                                </span>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
                </div>
                <div class="empty-state filter-empty" id="certFilterEmpty" hidden>
                    <span class="empty-state-icon"><?= cv_icon('search') ?></span>
                    <h3>No rows match that text</h3>
                    <p>Press Enter to search every certificate on the server instead.</p>
                </div>
            <?php else: ?>
                <div class="empty-state">
                    <span class="empty-state-icon"><?= cv_icon($is_filtered ? 'search' : 'award') ?></span>
                    <h3><?= $is_filtered ? 'No certificates match your filters.' : 'No certificates yet' ?></h3>
                    <p><?= $is_filtered ? 'Try a different search term or status.' : 'Issued certificates appear here with their live status.' ?></p>
                    <?php if ($is_filtered): ?>
                        <a class="btn btn-secondary" href="admin_dashboard.php">Clear filters</a>
                    <?php else: ?>
                        <a class="btn btn-primary" href="issue_certificate.php"><?= cv_icon('plus') ?> Issue your first certificate</a>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </section>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/admin-ui.js" defer></script>
</body>
</html>
