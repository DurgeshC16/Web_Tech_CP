<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_role('admin');
require_approved_institution();

$db = Database::getInstance();

// Get Institution ID for the logged-in user
$stmt = $db->prepare('SELECT id, name FROM institutions WHERE user_id = :user_id LIMIT 1');
$stmt->execute(['user_id' => $_SESSION['user_id']]);
$institution = $stmt->fetch();
$institution_id = $institution['id'] ?? null;

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
    $where .= ' AND (c.title LIKE :q OR c.certificate_id LIKE :q OR s.full_name LIKE :q)';
    $params['q'] = '%' . $search . '%';
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
<?php $page_title = 'Admin Dashboard - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="container shell-wide">
        <div class="page-head">
            <h2><?= htmlspecialchars($institution['name']) ?> Dashboard</h2>
            <a href="issue_certificate.php" class="btn btn-primary">Issue New Certificate</a>
        </div>

        <div class="stat-grid">
            <div class="stat-card"><div class="stat-num"><?= (int)$stats['total'] ?></div><div class="stat-label">Total Issued</div></div>
            <div class="stat-card"><div class="stat-num"><?= (int)$stats['active'] ?></div><div class="stat-label">Active</div></div>
            <div class="stat-card"><div class="stat-num"><?= (int)$stats['revoked_superseded'] ?></div><div class="stat-label">Revoked / Superseded</div></div>
            <div class="stat-card"><div class="stat-num"><?= $verification_count ?></div><div class="stat-label">Verifications</div></div>
        </div>

        <form method="GET" action="" class="filter-form" style="margin-bottom:var(--sp-4);">
            <div class="form-row">
                <div class="form-group">
                    <label>Search</label>
                    <input type="text" name="q" value="<?= htmlspecialchars($search) ?>" placeholder="Title, ID or student name">
                </div>
                <div class="form-group">
                    <label>Status</label>
                    <select name="status">
                        <option value="">All</option>
                        <?php foreach (['active', 'expired', 'revoked', 'superseded'] as $s): ?>
                            <option value="<?= $s ?>" <?= $status_filter === $s ? 'selected' : '' ?>><?= ucfirst($s) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
            </div>
            <button type="submit" class="btn btn-secondary">Apply</button>
            <a href="admin_dashboard.php" class="btn btn-ghost">Clear</a>
        </form>

        <h3>Issued Certificates</h3>
        <?php if (count($certificates) > 0): ?>
            <div class="table-wrap">
            <table class="table table-striped">
                <thead>
                    <tr><th>Title</th><th>ID</th><th>Student</th><th>Issue Date</th><th>Status</th><th>Action</th></tr>
                </thead>
                <tbody>
                <?php foreach ($certificates as $cert): ?>
                    <tr>
                        <td data-label="Title"><?= htmlspecialchars($cert['title']) ?></td>
                        <td data-label="ID"><?= htmlspecialchars($cert['certificate_id']) ?></td>
                        <td data-label="Student"><?= htmlspecialchars($cert['student_name']) ?></td>
                        <td data-label="Issue Date"><?= htmlspecialchars(date('M j, Y', strtotime($cert['issue_date']))) ?></td>
                        <td data-label="Status">
                            <?php $effStatus = VerificationService::effectiveStatus($cert); ?>
                            <span class="badge-status badge-<?= htmlspecialchars($effStatus === 'active' ? 'valid' : $effStatus) ?>"><?= htmlspecialchars($effStatus) ?></span>
                        </td>
                        <td data-label="Action"><a href="view_certificate_admin.php?id=<?= (int)$cert['id'] ?>" class="btn btn-sm">View</a></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
        <?php else: ?>
            <div class="empty-state">No certificates match your filters.</div>
        <?php endif; ?>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
