<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_role('admin');
require_approved_institution();

$db = Database::getInstance();
$cert_id_param = $_GET['id'] ?? '';

// Get Institution ID for the logged-in user
$stmt = $db->prepare('SELECT id FROM institutions WHERE user_id = :user_id LIMIT 1');
$stmt->execute(['user_id' => $_SESSION['user_id']]);
$institution_id = $stmt->fetchColumn();

if (!$institution_id) {
    show_error_page('Error', 'Institution profile not found.');
}

// Fetch certificate details, ensuring ownership.
// Use two separate prepared statements — never interpolate column names.
if (is_numeric($cert_id_param)) {
    $stmt = $db->prepare('SELECT c.*, s.full_name as student_name FROM certificates c JOIN students s ON c.student_id = s.id WHERE c.id = :id AND c.institution_id = :inst_id');
} else {
    $stmt = $db->prepare('SELECT c.*, s.full_name as student_name FROM certificates c JOIN students s ON c.student_id = s.id WHERE c.certificate_id = :id AND c.institution_id = :inst_id');
}
$stmt->execute(['id' => $cert_id_param, 'inst_id' => $institution_id]);
$cert = $stmt->fetch();

if (!$cert) {
    show_error_page('Not Found', 'Certificate not found or access denied.');
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
<?php $page_title = 'Certificate Detail & History - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="container shell-wide">
        <div class="page-head">
            <h2>Certificate Detail & Verification History</h2>
            <a href="admin_dashboard.php" class="btn btn-secondary">Back to Dashboard</a>
        </div>

        <div class="split">
            <!-- Certificate Details Card -->
            <div class="card split-main">
                <h3><?= htmlspecialchars($cert['title']) ?></h3>
                <p><strong>Certificate ID:</strong> <?= htmlspecialchars($cert['certificate_id']) ?></p>
                <p><strong>Version:</strong> <?= (int)$cert['version'] ?></p>
                <p><strong>Awarded To:</strong> <?= htmlspecialchars($cert['student_name']) ?></p>
                <p><strong>Issue Date:</strong> <?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></p>
                <?php if ($cert['expiry_date']): ?>
                    <p><strong>Expiry Date:</strong> <?= htmlspecialchars(date('F j, Y', strtotime($cert['expiry_date']))) ?></p>
                <?php endif; ?>
                <p>
                    <strong>Status:</strong> 
                    <?php $effStatus = VerificationService::effectiveStatus($cert); ?>
                    <span class="badge-status badge-<?= htmlspecialchars($effStatus === 'active' ? 'valid' : $effStatus) ?>">
                        <?= htmlspecialchars($effStatus) ?>
                    </span>
                </p>
                
                <?php if ($cert['status'] === 'revoked' && !empty($cert['revocation_reason'])): ?>
                    <div class="alert alert-danger">
                        <strong>Revocation Reason:</strong><br>
                        <?= htmlspecialchars($cert['revocation_reason']) ?>
                        <?php if (!empty($cert['revoked_at']) || !empty($cert['revoked_by'])): ?>
                            <p style="margin-top:8px;margin-bottom:0;"><small>
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
                    <p><small><a href="view_certificate_admin.php?id=<?= (int)$cert['previous_version_id'] ?>">← View Previous Version</a></small></p>
                <?php endif; ?>

                <h4>Version Timeline</h4>
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

                <?php if ($cert['qr_token']): ?>
                    <div>
                        <p><strong>QR Token:</strong> <br><small class="break-all"><?= htmlspecialchars($cert['qr_token']) ?></small></p>
                    </div>
                <?php endif; ?>
                
                <?php if (in_array(VerificationService::effectiveStatus($cert), ['active', 'expired'], true)): ?>
                    <div class="actions-row">
                        <a href="revoke_certificate.php?id=<?= (int)$cert['id'] ?>" class="btn btn-danger">Revoke</a>
                        <a href="supersede_certificate.php?id=<?= (int)$cert['id'] ?>" class="btn btn-warn">Supersede / Correct</a>
                    </div>
                <?php endif; ?>
            </div>
            
            <!-- History Table -->
            <div class="split-side">
                <h3>Verification History</h3>
                <div class="table-wrap">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Result</th>
                            <th>Detail</th>
                            <th>IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (count($history) > 0): ?>
                            <?php foreach ($history as $log): ?>
                                <tr>
                                    <td><?= htmlspecialchars(date('M j, Y H:i', strtotime($log['verified_at']))) ?></td>
                                    <td>
                                        <span class="badge-status badge-<?= htmlspecialchars(strtolower($log['result'])) ?>">
                                            <?= htmlspecialchars($log['result']) ?>
                                        </span>
                                    </td>
                                    <td><small><?= htmlspecialchars($log['detail']) ?></small></td>
                                    <td><?= htmlspecialchars($log['verifier_ip']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <tr>
                                <td colspan="4" class="text-center">No verification attempts yet.</td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
                </div>
                
                <?php if ($total_pages > 1): ?>
                    <div class="pagination">
                        <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                            <a href="?id=<?= urlencode($cert_id_param) ?>&page=<?= (int)$i ?>" class="<?= $i === $page ? 'active' : '' ?>">
                                <?= (int)$i ?>
                            </a>
                        <?php endfor; ?>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
