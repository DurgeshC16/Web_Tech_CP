<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
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
<?php $page_title = 'Student Dashboard - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="container shell-wide">
        <div class="page-head">
            <h2>My Certificates</h2>
            <div>
                <a href="change_password.php" class="btn btn-secondary">Change Password</a>
            </div>
        </div>

        <?php if (count($certificates) > 0): ?>
            <div class="grid-container">
                <?php foreach ($certificates as $cert): ?>
                    <div class="card">
                        <div class="card-title"><?= htmlspecialchars($cert['title']) ?></div>
                        <div class="card-meta"><strong>ID:</strong> <?= htmlspecialchars($cert['certificate_id']) ?></div>
                        <div class="card-meta"><strong>Issued By:</strong> <?= htmlspecialchars($cert['institution_name']) ?></div>
                        <div class="card-meta"><strong>Date:</strong> <?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></div>
                        <div>
                            <?php $effStatus = VerificationService::effectiveStatus($cert); ?>
                            <span class="badge-status badge-<?= htmlspecialchars($effStatus === 'active' ? 'valid' : $effStatus) ?>">
                                <?= htmlspecialchars($effStatus) ?>
                            </span>
                        </div>
                        <?php if ($cert['status'] === 'superseded' && !empty($cert['superseded_by_id'])): ?>
                            <div class="card-meta text-warn">
                                <small>This version has been replaced. <a href="view_certificate_student.php?id=<?= (int)$cert['superseded_by_id'] ?>">View current version →</a></small>
                            </div>
                        <?php endif; ?>
                        <div class="card-actions">
                            <a href="view_certificate_student.php?id=<?= (int)$cert['id'] ?>" class="btn btn-sm">View Details</a>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php else: ?>
            <p>You have not been issued any certificates yet.</p>
        <?php endif; ?>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
