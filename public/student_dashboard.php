<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Student Dashboard - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container" style="max-width: 800px;">
        <h2>My Certificates</h2>
        <a href="logout.php" class="btn" style="float: right; margin-top: -40px;">Logout</a>
        
        <?php if (count($certificates) > 0): ?>
            <div class="grid-container">
                <?php foreach ($certificates as $cert): ?>
                    <div class="card">
                        <div class="card-title"><?= htmlspecialchars($cert['title']) ?></div>
                        <div class="card-meta"><strong>ID:</strong> <?= htmlspecialchars($cert['certificate_id']) ?></div>
                        <div class="card-meta"><strong>Issued By:</strong> <?= htmlspecialchars($cert['institution_name']) ?></div>
                        <div class="card-meta"><strong>Date:</strong> <?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></div>
                        <div>
                            <span class="status-badge status-<?= htmlspecialchars($cert['status']) ?>">
                                <?= htmlspecialchars($cert['status']) ?>
                            </span>
                        </div>
                        <?php if ($cert['status'] === 'superseded' && !empty($cert['superseded_by_id'])): ?>
                            <div class="card-meta" style="margin-top:8px; color:#856404;">
                                <small>This version has been replaced. <a href="view_certificate_student.php?id=<?= $cert['superseded_by_id'] ?>">View current version →</a></small>
                            </div>
                        <?php endif; ?>
                        <div class="card-actions">
                            <a href="view_certificate_student.php?id=<?= $cert['id'] ?>" class="btn btn-sm">View Details</a>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <p>You have not been issued any certificates yet.</p>
        <?php endif; ?>
    </div>
</body>
</html>
