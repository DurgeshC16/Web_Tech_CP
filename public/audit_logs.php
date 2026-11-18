<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_role('admin');
require_approved_institution();

$db = Database::getInstance();

// Get Institution ID
$stmt = $db->prepare('SELECT id FROM institutions WHERE user_id = :user_id LIMIT 1');
$stmt->execute(['user_id' => $_SESSION['user_id']]);
$institution_id = $stmt->fetchColumn();

if (!$institution_id) {
    show_error_page('Error', 'Institution profile not found.');
}

// Filtering and Pagination
$page = max(1, (int)($_GET['page'] ?? 1));
$limit = 20;
$offset = ($page - 1) * $limit;

$filter_result = $_GET['result'] ?? '';
// Include unmatched (INVALID) lookups too: their certificate join is NULL.
$where_clauses = ['(c.institution_id = :inst_id OR c.institution_id IS NULL)'];
$params = ['inst_id' => $institution_id];

if ($filter_result && in_array($filter_result, ['VALID', 'TAMPERED', 'EXPIRED', 'REVOKED', 'INVALID', 'SUPERSEDED'])) {
    $where_clauses[] = 'v.result = :res';
    $params['res'] = $filter_result;
}

$where_sql = implode(' AND ', $where_clauses);

// Count total for pagination
$count_stmt = $db->prepare("
    SELECT COUNT(*) 
    FROM verification_logs v
    LEFT JOIN certificates c ON v.certificate_id_found = c.certificate_id
    WHERE $where_sql
");
$count_stmt->execute($params);
$total_rows = $count_stmt->fetchColumn();
$total_pages = ceil($total_rows / $limit);

// Fetch logs
$query = "
    SELECT v.*, c.title, s.full_name as student_name
    FROM verification_logs v
    LEFT JOIN certificates c ON v.certificate_id_found = c.certificate_id
    LEFT JOIN students s ON c.student_id = s.id
    WHERE $where_sql
    ORDER BY v.verified_at DESC
    LIMIT :limit OFFSET :offset
";
$stmt = $db->prepare($query);
foreach ($params as $key => $val) {
    $stmt->bindValue($key, $val);
}
$stmt->bindValue('limit', $limit, PDO::PARAM_INT);
$stmt->bindValue('offset', $offset, PDO::PARAM_INT);
$stmt->execute();
$logs = $stmt->fetchAll();

// ── Transparency summary: outcome mix for this institution ──────────
// One aggregate query over the same scoped rows; the "top failure
// reasons" show WHY verdicts failed (truncated detail strings).
$stats_stmt = $db->prepare("
    SELECT v.result, COUNT(*) AS cnt,
           MAX(CASE WHEN v.result IN ('VALID') THEN 0 ELSE 1 END) AS order_key
    FROM verification_logs v
    LEFT JOIN certificates c ON v.certificate_id_found = c.certificate_id
    WHERE $where_sql
    GROUP BY v.result
    ORDER BY cnt DESC
");
$stats_stmt->execute($params);
$result_counts = $stats_stmt->fetchAll();

$reasons_stmt = $db->prepare("
    SELECT v.detail, COUNT(*) AS cnt
    FROM verification_logs v
    LEFT JOIN certificates c ON v.certificate_id_found = c.certificate_id
    WHERE $where_sql AND v.result IN ('TAMPERED', 'EXPIRED', 'REVOKED', 'SUPERSEDED')
    GROUP BY v.detail
    ORDER BY cnt DESC
    LIMIT 5
");
$reasons_stmt->execute($params);
$failure_reasons = $reasons_stmt->fetchAll();

?>
<?php
// ── Presentation only ─────────────────────────────────────────────
require_once __DIR__ . '/../src/utils/admin_ui.php';
$outcome_total = array_sum(array_map(fn($rc) => (int)$rc['cnt'], $result_counts));
// Windowed pagination: first, last and current ± 2 (links keep the same URLs).
$page_links = [];
if ($total_pages > 1) {
    for ($i = 1; $i <= $total_pages; $i++) {
        if ($i === 1 || $i === (int)$total_pages || abs($i - $page) <= 2) {
            $page_links[] = $i;
        } elseif (end($page_links) !== '…') {
            $page_links[] = '…';
        }
    }
}
$res_label = fn($r) => (string)$r !== '' ? (string)$r : 'UNKNOWN'; // blank enum values read as UNKNOWN
$page_url = fn($p) => '?page=' . (int)$p . '&result=' . urlencode($filter_result);
$page_title = 'Audit Logs - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main">
    <div class="admin-shell">
        <header class="admin-head">
            <div class="admin-head-row">
                <span class="admin-head-icon" aria-hidden="true"><?= cv_icon('history') ?></span>
                <div class="admin-head-text">
                    <ol class="crumbs" aria-label="Breadcrumb"><li><a href="admin_dashboard.php">Dashboard</a></li><li aria-current="page">Audit logs</li></ol>
                    <h1>Global Audit Logs</h1>
                    <p class="admin-head-sub">This trail shows all verification attempts against certificates issued by your institution.</p>
                </div>
                <div class="admin-head-actions">
                    <a href="analytics.php" class="btn btn-outline-light"><?= cv_icon('chart') ?> Analytics</a>
                    <a href="admin_dashboard.php" class="btn btn-light"><?= cv_icon('arrow-left') ?> Back to Dashboard</a>
                </div>
            </div>
        </header>

        <section class="card" aria-labelledby="summaryTitle">
            <div class="card-head">
                <div class="card-head-text">
                    <h2 id="summaryTitle">Transparency summary</h2>
                    <p>Outcome mix across all logged verification attempts for your certificates.</p>
                </div>
                <span class="count-pill"><?= (int)$outcome_total ?> attempts</span>
            </div>
            <div class="summary-grid">
                <div>
                    <?php if (count($result_counts) > 0): ?>
                        <div class="outcome-bar" aria-hidden="true">
                            <?php foreach ($result_counts as $rc): ?>
                                <span class="outcome-seg outcome-seg-<?= htmlspecialchars(strtolower($res_label($rc['result']))) ?>" data-share="<?= (int)$rc['cnt'] ?>" title="<?= htmlspecialchars($res_label($rc['result'])) ?>: <?= (int)$rc['cnt'] ?>"></span>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    <div class="chip-row">
                        <?php if (count($result_counts) === 0): ?>
                            <span class="chip">No verification attempts yet</span>
                        <?php else: ?>
                            <?php foreach ($result_counts as $rc): ?>
                                <span class="chip chip-<?= strtolower(htmlspecialchars($res_label($rc['result']))) ?>">
                                    <?= htmlspecialchars($res_label($rc['result'])) ?>: <span class="chip-count"><?= (int)$rc['cnt'] ?></span>
                                </span>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
                <div>
                    <?php if (count($failure_reasons) > 0): ?>
                        <h3>Most frequent non-VALID verdict reasons</h3>
                        <ol class="reason-list">
                            <?php foreach ($failure_reasons as $fr): ?>
                                <li>
                                    <span class="reason-count"><?= htmlspecialchars((string)$fr['cnt']) ?>&times;</span>
                                    <span><?= htmlspecialchars(mb_substr((string)($fr['detail'] ?? '—'), 0, 140)) ?></span>
                                </li>
                            <?php endforeach; ?>
                        </ol>
                    <?php else: ?>
                        <h3>Most frequent non-VALID verdict reasons</h3>
                        <p class="text-sm text-muted m-0">No failed verdicts recorded — nothing to explain.</p>
                    <?php endif; ?>
                </div>
            </div>
        </section>

        <section class="card data-card" aria-labelledby="logTitle">
            <div class="card-head">
                <div class="card-head-text">
                    <h2 id="logTitle">Verification timeline</h2>
                    <p>Newest first<?= $filter_result !== '' ? ' · showing ' . htmlspecialchars($filter_result) . ' only' : '' ?> · <?= (int)$total_rows ?> matching attempt(s)</p>
                </div>
            </div>
            <div class="filter-panel">
                <nav class="chip-row" aria-label="Quick filter by result">
                    <a href="audit_logs.php" class="chip <?= $filter_result === '' ? 'active' : '' ?>"<?= $filter_result === '' ? ' aria-current="true"' : '' ?>>All</a>
                    <?php foreach (['VALID','TAMPERED','EXPIRED','REVOKED','INVALID','SUPERSEDED'] as $v): ?>
                        <a href="?result=<?= $v ?>" class="chip chip-<?= strtolower($v) ?> <?= $filter_result === $v ? 'active' : '' ?>"<?= $filter_result === $v ? ' aria-current="true"' : '' ?>><?= $v ?></a>
                    <?php endforeach; ?>
                </nav>
                <form method="GET" action="" class="filter-form">
                    <div class="form-group">
                        <label for="auditResult">Filter by Result</label>
                        <select name="result" id="auditResult">
                            <option value="">All Results</option>
                            <option value="VALID" <?= $filter_result === 'VALID' ? 'selected' : '' ?>>VALID</option>
                            <option value="TAMPERED" <?= $filter_result === 'TAMPERED' ? 'selected' : '' ?>>TAMPERED</option>
                            <option value="EXPIRED" <?= $filter_result === 'EXPIRED' ? 'selected' : '' ?>>EXPIRED</option>
                            <option value="REVOKED" <?= $filter_result === 'REVOKED' ? 'selected' : '' ?>>REVOKED</option>
                            <option value="INVALID" <?= $filter_result === 'INVALID' ? 'selected' : '' ?>>INVALID</option>
                            <option value="SUPERSEDED" <?= $filter_result === 'SUPERSEDED' ? 'selected' : '' ?>>SUPERSEDED</option>
                        </select>
                    </div>
                    <div class="toolbar-actions">
                        <button type="submit" class="btn btn-primary"><?= cv_icon('filter') ?> Apply Filter</button>
                        <a href="audit_logs.php" class="btn btn-secondary">Clear</a>
                    </div>
                </form>
            </div>

            <div class="table-wrap">
            <table class="table admin-table log-table">
                <thead>
                    <tr>
                        <th scope="col" class="log-rail">Timestamp</th>
                        <th scope="col">Entered ID / Token</th>
                        <th scope="col">Matched Certificate</th>
                        <th scope="col">Student</th>
                        <th scope="col">Result</th>
                        <th scope="col">IP Address</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (count($logs) > 0): ?>
                        <?php foreach ($logs as $log): $ts = strtotime($log['verified_at']); ?>
                            <tr class="log-<?= htmlspecialchars(strtolower($res_label($log['result']))) ?>">
                                <td data-label="Timestamp" class="log-rail">
                                    <span class="log-when"><strong><?= htmlspecialchars(date('Y-m-d', $ts)) ?></strong><span><?= htmlspecialchars(date('H:i:s', $ts)) ?></span></span>
                                </td>
                                <td data-label="Entered ID / Token"><span class="query-chip"><?= htmlspecialchars($log['query_value']) ?></span></td>
                                <td data-label="Matched Certificate">
                                    <?php if (!empty($log['certificate_id_found'])): ?>
                                        <span class="cell-stack">
                                            <a href="view_certificate_admin.php?id=<?= urlencode($log['certificate_id_found']) ?>" class="text-link"><?= htmlspecialchars($log['certificate_id_found']) ?></a>
                                            <span class="cell-sub"><?= htmlspecialchars($log['title'] ?? '') ?></span>
                                        </span>
                                    <?php else: ?>
                                        <span class="no-match">— no match —</span>
                                    <?php endif; ?>
                                </td>
                                <td data-label="Student"><?= $log['student_name'] !== null ? htmlspecialchars($log['student_name']) : '<span class="no-match">— no match —</span>' ?></td>
                                <td data-label="Result">
                                    <span class="badge-status badge-<?= htmlspecialchars(strtolower($res_label($log['result']))) ?>"><?= htmlspecialchars($res_label($log['result'])) ?></span>
                                </td>
                                <td data-label="IP Address"><span class="ip-text"><?= htmlspecialchars($log['verifier_ip']) ?></span></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr class="table-empty-row">
                            <td colspan="6" class="text-center">No verification logs found.</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
            </div>

            <?php if ($total_pages > 1): ?>
                <nav class="pagination" aria-label="Audit log pages">
                    <?php if ($page > 1): ?><a href="<?= htmlspecialchars($page_url($page - 1)) ?>" aria-label="Previous page"><?= cv_icon('arrow-left') ?></a><?php endif; ?>
                    <?php foreach ($page_links as $i): ?>
                        <?php if ($i === '…'): ?>
                            <span class="page-gap" aria-hidden="true">…</span>
                        <?php else: ?>
                            <a href="<?= htmlspecialchars($page_url($i)) ?>" class="<?= $i === $page ? 'active' : '' ?>"<?= $i === $page ? ' aria-current="page"' : '' ?>><?= (int)$i ?></a>
                        <?php endif; ?>
                    <?php endforeach; ?>
                    <?php if ($page < $total_pages): ?><a href="<?= htmlspecialchars($page_url($page + 1)) ?>" aria-label="Next page"><?= cv_icon('arrow-right') ?></a><?php endif; ?>
                </nav>
            <?php endif; ?>
        </section>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/admin-ui.js" defer></script>
</body>
</html>
