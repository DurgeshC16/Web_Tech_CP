<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_role('admin');

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

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Audit Logs - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <?php require_once __DIR__ . '/../src/partials/head_fonts.php'; ?>
</head>
<body>
    <div class="container shell-wide">
        <div class="page-head">
            <h2>Global Audit Logs</h2>
            <a href="admin_dashboard.php" class="btn btn-secondary">Back to Dashboard</a>
        </div>
        <p>This trail shows all verification attempts against certificates issued by your institution.</p>

        <div class="filter-bar">
            <form method="GET" action="" class="filter-form">
                <div>
                    <label>Filter by Result:</label>
                    <select name="result">
                        <option value="">All Results</option>
                        <option value="VALID" <?= $filter_result === 'VALID' ? 'selected' : '' ?>>VALID</option>
                        <option value="TAMPERED" <?= $filter_result === 'TAMPERED' ? 'selected' : '' ?>>TAMPERED</option>
                        <option value="EXPIRED" <?= $filter_result === 'EXPIRED' ? 'selected' : '' ?>>EXPIRED</option>
                        <option value="REVOKED" <?= $filter_result === 'REVOKED' ? 'selected' : '' ?>>REVOKED</option>
                        <option value="INVALID" <?= $filter_result === 'INVALID' ? 'selected' : '' ?>>INVALID</option>
                        <option value="SUPERSEDED" <?= $filter_result === 'SUPERSEDED' ? 'selected' : '' ?>>SUPERSEDED</option>
                    </select>
                </div>
                <div>
                    <button type="submit" class="btn btn-primary">Apply Filter</button>
                    <a href="audit_logs.php" class="btn btn-secondary">Clear</a>
                </div>
            </form>
        </div>

        <div class="table-wrap">
        <table class="table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Entered ID / Token</th>
                    <th>Matched Certificate</th>
                    <th>Student</th>
                    <th>Result</th>
                    <th>IP Address</th>
                </tr>
            </thead>
            <tbody>
                <?php if (count($logs) > 0): ?>
                    <?php foreach ($logs as $log): ?>
                        <tr>
                            <td><?= htmlspecialchars(date('Y-m-d H:i:s', strtotime($log['verified_at']))) ?></td>
                            <td class="break-all"><small><?= htmlspecialchars($log['query_value']) ?></small></td>
                            <td>
                                <?php if (!empty($log['certificate_id_found'])): ?>
                                    <a href="view_certificate_admin.php?id=<?= urlencode($log['certificate_id_found']) ?>" class="text-link">
                                        <?= htmlspecialchars($log['certificate_id_found']) ?>
                                    </a><br>
                                    <small><?= htmlspecialchars($log['title'] ?? '') ?></small>
                                <?php else: ?>
                                    — no match —
                                <?php endif; ?>
                            </td>
                            <td><?= $log['student_name'] !== null ? htmlspecialchars($log['student_name']) : '— no match —' ?></td>
                            <td>
                                <span class="badge-status badge-<?= htmlspecialchars(strtolower($log['result'])) ?>">
                                    <?= htmlspecialchars($log['result']) ?>
                                </span>
                            </td>
                            <td><?= htmlspecialchars($log['verifier_ip']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="6" class="text-center">No verification logs found.</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
        </div>

        <?php if ($total_pages > 1): ?>
            <div class="pagination">
                <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                    <a href="?page=<?= $i ?>&result=<?= urlencode($filter_result) ?>" class="<?= $i === $page ? 'active' : '' ?>">
                        <?= $i ?>
                    </a>
                <?php endfor; ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
