<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_role('student');

$db = Database::getInstance();
$cert_id = (int)($_GET['id'] ?? 0);
$share_link = '';

// Get student_id
$stmt = $db->prepare('SELECT id FROM students WHERE user_id = :user_id LIMIT 1');
$stmt->execute(['user_id' => $_SESSION['user_id']]);
$student_id = $stmt->fetchColumn();

// Fetch certificate details, ensure they own it
$stmt = $db->prepare('
    SELECT c.*, i.name as institution_name
    FROM certificates c
    JOIN institutions i ON c.institution_id = i.id
    WHERE c.id = :id AND c.student_id = :student_id
');
$stmt->execute(['id' => $cert_id, 'student_id' => $student_id]);
$cert = $stmt->fetch();

if (!$cert) {
    show_error_page('Not Found', 'Certificate not found or access denied.');
}

// Generate Share Link Logic
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['generate_share'])) {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    $expiry = time() + (24 * 3600); // Valid for 24 hours
    $payload = json_encode(['id' => $cert['id'], 'exp' => $expiry]);
    $encoded_payload = rtrim(strtr(base64_encode($payload), '+/', '-_'), '=');
    $signature = hash_hmac('sha256', $encoded_payload, SHARE_LINK_SECRET);
    
    $token = $encoded_payload . '.' . $signature;
    $share_link = BASE_URL . '/share.php?token=' . urlencode($token);
}
?>
<?php $page_title = 'View Certificate - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="container shell-wide">
        <div class="page-head">
            <h2>Certificate Details</h2>
            <a href="student_dashboard.php" class="btn btn-secondary">Back</a>
        </div>

        <div class="card">
            <h3><?= htmlspecialchars($cert['title']) ?></h3>
            <p><strong>Certificate ID:</strong> <?= htmlspecialchars($cert['certificate_id']) ?></p>
            <p><strong>Version:</strong> <?= (int)$cert['version'] ?></p>
            <p><strong>Institution:</strong> <?= htmlspecialchars($cert['institution_name']) ?></p>
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
            
            <?php if ($cert['status'] === 'superseded' && !empty($cert['superseded_by_id'])): ?>
                <div class="alert alert-info">
                    <strong>This version has been superseded.</strong> A corrected version has been issued.<br>
                    <a href="view_certificate_student.php?id=<?= (int)$cert['superseded_by_id'] ?>">View Current Version →</a>
                </div>
            <?php endif; ?>
            
            <?php if ($cert['status'] === 'revoked'): ?>
                <div class="alert alert-danger">
                    <strong>This certificate has been revoked</strong> by the issuing institution and is no longer valid.
                </div>
            <?php endif; ?>
            
            <?php if (VerificationService::effectiveStatus($cert) === 'active'): ?>
                <div class="qr-hero">
                    <p><strong>Verification QR:</strong></p>
                    <img src="qrcodes/<?= htmlspecialchars($cert['qr_token']) ?>.png" alt="QR Code">
                </div>
            <?php endif; ?>
            
            <?php if (VerificationService::effectiveStatus($cert) === 'active'): ?>
            <div class="actions-row">
                <a href="download.php?id=<?= (int)$cert['id'] ?>" class="btn btn-primary">Download File</a>
                <form method="POST" action="" class="inline-form">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                    <input type="hidden" name="generate_share" value="1">
                    <button type="submit" class="btn btn-verified">Generate Share Link (24h)</button>
                </form>
            </div>
            <?php endif; ?>
            
            <?php if ($share_link): ?>
                <div class="alert alert-success">
                    <strong>Share Link:</strong><br>
                    <div class="copy-field">
                        <input type="text" id="shareLinkInput" value="<?= htmlspecialchars($share_link) ?>" readonly onclick="this.select();">
                        <button type="button" class="btn btn-secondary" id="copyShareBtn">Copy</button>
                    </div>
                    <small>This link is valid for 24 hours.</small>
                </div>
                <div class="toast toast-success" id="copiedToast" style="display:none;">Link copied to clipboard!</div>
                <script>
                document.getElementById('copyShareBtn').addEventListener('click', function () {
                    var input = document.getElementById('shareLinkInput');
                    input.select();
                    document.execCommand('copy');
                    var t = document.getElementById('copiedToast');
                    t.style.display = 'block';
                    setTimeout(function () { t.style.display = 'none'; }, 2500);
                });
                </script>
            <?php endif; ?>
        </div>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
