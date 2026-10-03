<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_role('admin');

$db = Database::getInstance();

// Get Institution ID for the logged-in user
$stmt = $db->prepare('SELECT id, name FROM institutions WHERE user_id = :user_id LIMIT 1');
$stmt->execute(['user_id' => $_SESSION['user_id']]);
$institution = $stmt->fetch();
$institution_id = $institution['id'] ?? null;

if (!$institution_id) {
    show_error_page('Error', 'Institution profile not found.');
}

// Fetch issued certificates
$stmt = $db->prepare('
    SELECT c.id, c.certificate_id, c.title, c.issue_date, c.status, s.full_name as student_name
    FROM certificates c
    JOIN students s ON c.student_id = s.id
    WHERE c.institution_id = :inst_id
    ORDER BY c.issue_date DESC
');
$stmt->execute(['inst_id' => $institution_id]);
$certificates = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <?php require_once __DIR__ . '/../src/partials/head_fonts.php'; ?>
</head>
<body>
    <div class="container shell-wide">
        <div class="page-head">
            <h2><?= htmlspecialchars($institution['name']) ?> Dashboard</h2>
            <a href="logout.php" class="btn btn-secondary">Logout</a>
        </div>

        <div class="actions-row">
            <a href="issue_certificate.php" class="btn btn-primary">Issue New Certificate</a>
            <a href="audit_logs.php" class="btn btn-secondary">View Global Audit Logs</a>
        </div>

        <h3>Issued Certificates</h3>
        <?php if (count($certificates) > 0): ?>
            <div class="grid-container">
                <?php foreach ($certificates as $cert): ?>
                    <div class="card">
                        <div class="card-title"><?= htmlspecialchars($cert['title']) ?></div>
                        <div class="card-meta"><strong>ID:</strong> <?= htmlspecialchars($cert['certificate_id']) ?></div>
                        <div class="card-meta"><strong>Awarded To:</strong> <?= htmlspecialchars($cert['student_name']) ?></div>
                        <div class="card-meta"><strong>Issue Date:</strong> <?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></div>
                        <div>
                            <span class="badge-status badge-<?= htmlspecialchars($cert['status'] === 'active' ? 'valid' : $cert['status']) ?>">
                                <?= htmlspecialchars($cert['status']) ?>
                            </span>
                        </div>
                        <div class="card-actions">
                            <a href="view_certificate_admin.php?id=<?= $cert['id'] ?>" class="btn btn-sm">View Details & History</a>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <p>You have not issued any certificates yet.</p>
        <?php endif; ?>
    </div>
</body>
</html>
