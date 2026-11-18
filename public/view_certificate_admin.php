<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_role('admin');
require_approved_institution();

$db = Database::getInstance();
$cert_id_param = $_GET['id'] ?? '';

// Get Institution ID for the logged-in user
$institution_id = current_institution_id($db);

if (!$institution_id) {
    show_error_page('Error', 'Institution profile not found.');
}

// Fetch certificate details — ownership enforced centrally (uniform 403).
// Use two separate prepared statements — never interpolate column names.
if (is_numeric($cert_id_param)) {
    $cert = require_owned_certificate(
        $db,
        $cert_id_param,
        'admin',
        $institution_id,
        'c.*, s.full_name as student_name',
        'JOIN students s ON c.student_id = s.id'
    );
} else {
    // Lenient ID lookup (normalized CV form first, then raw
    // case-insensitive), still scoped to this institution.
    $cert = VerificationService::findByFlexibleCertificateId($db, $cert_id_param);
    if (!$cert || !can_access_certificate($cert, 'admin', $institution_id)) {
        deny_access_403();
    }
}

// Fetch specific verification history for this certificate (paginated)
$page = max(1, (int)($_GET['page'] ?? 1));
$limit = 10;
$offset = ($page - 1) * $limit;

$hist_count_stmt = $db->prepare('SELECT COUNT(*) FROM verification_logs WHERE certificate_id_found = :cid');
$hist_count_stmt->execute(['cid' => $cert['certificate_id']]);
$total_history = $hist_count_stmt->fetchColumn();
$total_pages = ceil($total_history / $limit);

$hist_stmt = $db->prepare('
    SELECT * FROM verification_logs 
    WHERE certificate_id_found = :cid 
    ORDER BY verified_at DESC 
    LIMIT :limit OFFSET :offset
');
$hist_stmt->bindValue('cid', $cert['certificate_id']);
$hist_stmt->bindValue('limit', $limit, PDO::PARAM_INT);
$hist_stmt->bindValue('offset', $offset, PDO::PARAM_INT);
$hist_stmt->execute();
$history = $hist_stmt->fetchAll();

?>
<?php
require_once __DIR__ . '/../src/utils/admin_ui.php';
$effStatus = VerificationService::effectiveStatus($cert);
$page_title = 'Certificate Detail & History - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main">
    <div class="admin-shell">
        <header class="admin-head">
            <div class="admin-head-row">
                <span class="admin-head-icon" aria-hidden="true"><?= cv_icon('award') ?></span>
                <div class="admin-head-text">
                    <ol class="crumbs" aria-label="Breadcrumb"><li><a href="admin_dashboard.php">Dashboard</a></li><li aria-current="page"><?= htmlspecialchars($cert['certificate_id']) ?></li></ol>
                    <h1>Certificate Detail &amp; Verification History</h1>
                    <p class="admin-head-sub">Everything about this record and every time someone checked it.</p>
                </div>
                <div class="admin-head-actions">
                    <a href="admin_dashboard.php" class="btn btn-light"><?= cv_icon('arrow-left') ?> Back to Dashboard</a>
                </div>
            </div>
        </header>

        <div class="cert-view">
            <!-- Certificate Details Card -->
            <section class="card card-gradient cert-summary" aria-labelledby="certTitle">
                <div class="cert-summary-top">
                    <span class="avatar avatar-lg avatar-<?= cv_avatar_hue($cert['student_name']) ?>" aria-hidden="true"><?= htmlspecialchars(cv_initials($cert['student_name'])) ?></span>
                    <div class="flex-1">
                        <h2 id="certTitle"><?= htmlspecialchars($cert['title']) ?></h2>
                        <div class="cert-badges">
                            <span class="badge-status badge-<?= htmlspecialchars($effStatus === 'active' ? 'valid' : $effStatus) ?>"><?= htmlspecialchars($effStatus) ?></span>
                            <span class="badge badge-info">Version <?= (int)$cert['version'] ?></span>
                        </div>
                    </div>
                </div>

                <dl class="cert-details">
                    <dt>Certificate ID</dt>
                    <dd><span class="id-row"><span class="id-chip" id="certIdValue"><?= htmlspecialchars($cert['certificate_id']) ?></span>
                        <button type="button" class="btn btn-ghost btn-sm btn-icon-sm" data-copy-target="certIdValue" data-copy-message="Certificate ID copied" aria-label="Copy certificate ID" title="Copy"><?= cv_icon('copy') ?></button></span></dd>
                    <dt>Version</dt><dd><?= (int)$cert['version'] ?></dd>
                    <dt>Awarded To</dt><dd><?= htmlspecialchars($cert['student_name']) ?></dd>
                    <dt>Issue Date</dt><dd><?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></dd>
                    <?php if ($cert['expiry_date']): ?>
                        <dt>Expiry Date</dt><dd><?= htmlspecialchars(date('F j, Y', strtotime($cert['expiry_date']))) ?></dd>
                    <?php endif; ?>
                    <dt>Status</dt>
                    <dd><span class="badge-status badge-<?= htmlspecialchars($effStatus === 'active' ? 'valid' : $effStatus) ?>"><?= htmlspecialchars($effStatus) ?></span></dd>
                </dl>

                <?php if ($cert['status'] === 'revoked' && !empty($cert['revocation_reason'])): ?>
                    <div class="alert alert-danger">
                        <strong>Revocation Reason:</strong><br>
                        <?= htmlspecialchars($cert['revocation_reason']) ?>
                        <?php if (!empty($cert['revoked_at']) || !empty($cert['revoked_by'])): ?>
                            <p class="mt-2 mb-0"><small>
                                <?php if (!empty($cert['revoked_at'])): ?>Revoked at: <?= htmlspecialchars(date('F j, Y H:i', strtotime($cert['revoked_at']))) ?><?php endif; ?>
                                <?php if (!empty($cert['revoked_by'])): ?><?= !empty($cert['revoked_at']) ? ' · ' : '' ?>Revoked by user ID <?= (int)$cert['revoked_by'] ?><?php endif; ?>
                            </small></p>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>

                <?php if ($cert['status'] === 'superseded' && !empty($cert['superseded_by_id'])): ?>
                    <div class="alert alert-info">
                        <strong>Superseded.</strong> This version has been replaced.<br>
                        <a href="view_certificate_admin.php?id=<?= (int)$cert['superseded_by_id'] ?>">View Current Version →</a>
                    </div>
                <?php endif; ?>

                <?php if (!empty($cert['previous_version_id'])): ?>
                    <p class="m-0"><small><a href="view_certificate_admin.php?id=<?= (int)$cert['previous_version_id'] ?>">← View Previous Version</a></small></p>
                <?php endif; ?>

                <div>
                <h3>Version Timeline</h3>
                <?php
                $prevRow = null; $nextRow = null;
                if (!empty($cert['previous_version_id'])) {
                    $ps = $db->prepare('SELECT id, certificate_id, version, status FROM certificates WHERE id = :id');
                    $ps->execute(['id' => $cert['previous_version_id']]);
                    $prevRow = $ps->fetch() ?: null;
                }
                if (!empty($cert['superseded_by_id'])) {
                    $ns = $db->prepare('SELECT id, certificate_id, version, status FROM certificates WHERE id = :id');
                    $ns->execute(['id' => $cert['superseded_by_id']]);
                    $nextRow = $ns->fetch() ?: null;
                }
                ?>
                <ul class="timeline">
                    <?php if ($prevRow): ?>
                        <li><a href="view_certificate_admin.php?id=<?= (int)$prevRow['id'] ?>"><?= htmlspecialchars($prevRow['certificate_id']) ?> (v<?= (int)$prevRow['version'] ?>)</a> — <?= htmlspecialchars($prevRow['status']) ?></li>
                    <?php endif; ?>
                    <li class="current"><?= htmlspecialchars($cert['certificate_id']) ?> (v<?= (int)$cert['version'] ?>) — current (<?= htmlspecialchars($cert['status']) ?>)</li>
                    <?php if ($nextRow): ?>
                        <li><a href="view_certificate_admin.php?id=<?= (int)$nextRow['id'] ?>"><?= htmlspecialchars($nextRow['certificate_id']) ?> (v<?= (int)$nextRow['version'] ?>)</a> — <?= htmlspecialchars($nextRow['status']) ?></li>
                    <?php endif; ?>
                </ul>
                </div>

                <?php if ($cert['qr_token']): ?>
                    <div>
                        <h3>QR Token</h3>
                        <div class="token-row">
                            <code class="fingerprint" id="qrTokenValue"><?= htmlspecialchars($cert['qr_token']) ?></code>
                            <button type="button" class="btn btn-ghost btn-sm btn-icon-sm" data-copy-target="qrTokenValue" data-copy-message="QR token copied" aria-label="Copy QR token" title="Copy"><?= cv_icon('copy') ?></button>
                        </div>
                    </div>
                <?php endif; ?>

                <?php if (in_array($effStatus, ['active', 'expired'], true)): ?>
                    <div class="cert-actions">
                        <a href="revoke_certificate.php?id=<?= (int)$cert['id'] ?>" class="btn btn-danger"><?= cv_icon('ban') ?> Revoke</a>
                        <a href="supersede_certificate.php?id=<?= (int)$cert['id'] ?>" class="btn btn-warn"><?= cv_icon('refresh') ?> Supersede / Correct</a>
                    </div>
                <?php endif; ?>
            </section>

            <!-- History Table -->
            <section class="card data-card history-card" aria-labelledby="historyTitle">
                <div class="card-head">
                    <div class="card-head-text">
                        <h2 id="historyTitle">Verification History</h2>
                        <p>Newest first, <?= (int)$limit ?> per page.</p>
                    </div>
                    <span class="count-pill"><?= (int)$total_history ?> check<?= (int)$total_history === 1 ? '' : 's' ?></span>
                </div>
                <div class="table-wrap">
                <table class="table admin-table log-table">
                    <thead>
                        <tr>
                            <th scope="col" class="log-rail">Timestamp</th>
                            <th scope="col">Result</th>
                            <th scope="col">Detail</th>
                            <th scope="col">IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (count($history) > 0): ?>
                            <?php foreach ($history as $log): $ts = strtotime($log['verified_at']); ?>
                                <tr class="log-<?= htmlspecialchars(strtolower($log['result'])) ?>">
                                    <td data-label="Timestamp" class="log-rail"><span class="log-when"><strong><?= htmlspecialchars(date('M j, Y', $ts)) ?></strong><span><?= htmlspecialchars(date('H:i', $ts)) ?></span></span></td>
                                    <td data-label="Result">
                                        <span class="badge-status badge-<?= htmlspecialchars(strtolower($log['result'])) ?>"><?= htmlspecialchars($log['result']) ?></span>
                                    </td>
                                    <td data-label="Detail"><span class="cell-sub"><?= htmlspecialchars($log['detail']) ?></span></td>
                                    <td data-label="IP"><span class="ip-text"><?= htmlspecialchars($log['verifier_ip']) ?></span></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr class="table-empty-row">
                                <td colspan="4" class="text-center">No verification attempts yet.</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
                </div>

                <?php if ($total_pages > 1): ?>
                    <nav class="pagination" aria-label="History pages">
                        <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                            <a href="?id=<?= urlencode($cert_id_param) ?>&page=<?= (int)$i ?>" class="<?= $i === $page ? 'active' : '' ?>"<?= $i === $page ? ' aria-current="page"' : '' ?>><?= (int)$i ?></a>
                        <?php endfor; ?>
                    </nav>
                <?php endif; ?>
            </section>
        </div>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/admin-ui.js" defer></script>
</body>
</html>
