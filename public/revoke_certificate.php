<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/TransparencyLogService.php';
require_role('admin');
require_approved_institution();

$db = Database::getInstance();
$cert_db_id = (int)($_GET['id'] ?? 0);
$error = '';
$errors = [];
$success = '';
$reason = '';

// Get Institution ID
$institution_id = current_institution_id($db);

if (!$institution_id) {
    show_error_page('Error', 'Institution profile not found.');
}

// Fetch certificate — ownership enforced centrally (uniform 403).
$cert = require_owned_certificate(
    $db,
    $cert_db_id,
    'admin',
    $institution_id,
    'c.*, s.full_name as student_name',
    'JOIN students s ON c.student_id = s.id'
);

if (!in_array($cert['status'], ['active', 'expired'])) {
    $error = "This certificate cannot be revoked (current status: {$cert['status']}).";
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($error)) {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    $reason = trim($_POST['reason'] ?? '');
    $errors = [];

    if (($e = v_required($reason, 'Revocation reason')) !== true) { $errors['reason'] = $e; }
    elseif (($e = v_length($reason, 10, 500, 'Revocation reason')) !== true) { $errors['reason'] = $e; }

    if (!empty($errors)) {
        $error = 'Please correct the highlighted fields below.';
    } else {
        try {
            $db->beginTransaction();
            $stmt = $db->prepare('UPDATE certificates SET status = "revoked", revocation_reason = :reason, revoked_at = :revoked_at, revoked_by = :revoked_by WHERE id = :id AND institution_id=:iid AND status IN ("active","expired")');
            $stmt->execute([
                'reason' => $reason,
                'id' => $cert_db_id,
                'iid' => $institution_id,
                'revoked_at' => date('Y-m-d H:i:s'),
                'revoked_by' => $_SESSION['user_id'],
            ]);
            if ($stmt->rowCount() !== 1) throw new RuntimeException('Certificate status changed before revocation.');
            TransparencyLogService::append($db, (string)$cert['certificate_id'], 'REVOKE');
            $db->commit();
            $success = "Certificate {$cert['certificate_id']} has been revoked.";
            $cert['status'] = 'revoked';
            $cert['revocation_reason'] = $reason;
        } catch (Throwable $e) {
            if ($db->inTransaction()) $db->rollBack();
            error_log('[CertiVault] Certificate revocation failed: ' . $e->getMessage());
            $error = 'Certificate could not be revoked. Please retry or contact the administrator.';
        }
    }
}
?>
<?php
require_once __DIR__ . '/../src/utils/admin_ui.php';
$page_title = 'Revoke Certificate - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main">
    <div class="admin-shell">
        <header class="admin-head admin-head-danger">
            <div class="admin-head-row">
                <span class="admin-head-icon" aria-hidden="true"><?= cv_icon('ban') ?></span>
                <div class="admin-head-text">
                    <ol class="crumbs" aria-label="Breadcrumb"><li><a href="admin_dashboard.php">Dashboard</a></li><li><a href="view_certificate_admin.php?id=<?= (int)$cert_db_id ?>"><?= htmlspecialchars($cert['certificate_id']) ?></a></li><li aria-current="page">Revoke</li></ol>
                    <h1>Revoke Certificate</h1>
                    <p class="admin-head-sub">Danger zone — revoking permanently withdraws this certificate for every verifier.</p>
                </div>
                <div class="admin-head-actions">
                    <a href="view_certificate_admin.php?id=<?= (int)$cert_db_id ?>" class="btn btn-light"><?= cv_icon('arrow-left') ?> Back</a>
                </div>
            </div>
        </header>

        <div class="zone-layout">
            <section class="card zone-card" aria-labelledby="revokeWhat">
                <div class="zone-head">
                    <span class="zone-icon" aria-hidden="true"><?= cv_icon('award') ?></span>
                    <div><h2 id="revokeWhat">Certificate</h2><p>The record you are about to withdraw.</p></div>
                </div>
                <dl class="summary-list">
                    <dt>Certificate ID</dt><dd><span class="id-chip"><?= htmlspecialchars($cert['certificate_id']) ?></span></dd>
                    <dt>Title</dt><dd><?= htmlspecialchars($cert['title'] ?? '') ?></dd>
                    <dt>Awarded To</dt><dd><?= htmlspecialchars($cert['student_name']) ?></dd>
                    <dt>Status</dt>
                    <dd><span class="badge-status badge-<?= htmlspecialchars($cert['status'] === 'active' ? 'valid' : $cert['status']) ?>"><?= htmlspecialchars($cert['status']) ?></span></dd>
                </dl>
                <h3 class="aside-title mt-3">What revoking does</h3>
                <ul class="consequences">
                    <li><span class="cq-icon cq-bad" aria-hidden="true"><?= cv_icon('x') ?></span><span><strong>Every verification fails</strong> — QR scans, ID lookups and file checks return a REVOKED verdict immediately.</span></li>
                    <li><span class="cq-icon cq-bad" aria-hidden="true"><?= cv_icon('lock') ?></span><span><strong>It cannot be undone.</strong> To correct a mistake instead, supersede the certificate.</span></li>
                    <li><span class="cq-icon cq-ok" aria-hidden="true"><?= cv_icon('check') ?></span><span><strong>The history is kept</strong> — your reason is shown to verifiers and recorded with the date and your user.</span></li>
                </ul>
                <?php if (in_array($cert['status'], ['active', 'expired']) && !$success): ?>
                    <a href="supersede_certificate.php?id=<?= (int)$cert['id'] ?>" class="btn btn-ghost btn-warn-ghost"><?= cv_icon('refresh') ?> Supersede / correct instead</a>
                <?php endif; ?>
            </section>

            <section class="card zone-card zone-danger" aria-labelledby="revokeTitle">
                <div class="zone-head">
                    <span class="zone-icon" aria-hidden="true"><?= cv_icon('alert') ?></span>
                    <div><h2 id="revokeTitle">Revoke This Certificate</h2><p>Tell verifiers why it is no longer valid.</p></div>
                </div>

                <?php if ($error): ?>
                    <div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div>
                <?php endif; ?>
                <?php if (!empty($errors)): ?>
                    <div class="alert alert-danger">Please correct the highlighted fields below.</div>
                <?php endif; ?>
                <?php if ($success): ?>
                    <div class="alert alert-success" role="status">
                        <strong>Revoked.</strong> <?= htmlspecialchars($success) ?>
                    </div>
                    <div class="btn-row">
                        <a href="admin_dashboard.php" class="btn btn-primary">Back to Dashboard</a>
                        <a href="view_certificate_admin.php?id=<?= (int)$cert_db_id ?>" class="btn btn-secondary">View certificate</a>
                    </div>
                <?php elseif (empty($error) || !empty($_POST['reason']) || !empty($errors)): ?>
                    <?php if (in_array($cert['status'], ['active', 'expired'])): ?>
                    <form method="POST" action="" data-confirm="Revoke <?= htmlspecialchars($cert['certificate_id']) ?>? This cannot be undone." data-loading>
                        <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                        <div class="form-group">
                            <label for="revoke_reason">Reason for Revocation (required)</label>
                            <textarea name="reason" id="revoke_reason" rows="5" placeholder="e.g. Issued in error — the course was not completed." data-validate="required|min:10|max:500" required><?= htmlspecialchars($reason) ?></textarea>
                            <div class="char-counter" data-char-count="revoke_reason" data-min="10" data-max="500"><?= mb_strlen(trim($reason)) ?> / 500</div>
                            <?php render_field_error($errors, 'reason'); ?>
                        </div>
                        <div class="irreversible" role="note">
                            <?= cv_icon('alert') ?>
                            <span><strong>Warning:</strong> This action is irreversible. The certificate will immediately fail verification with a REVOKED verdict.</span>
                        </div>
                        <button type="submit" class="btn btn-danger btn-block btn-lg"><?= cv_icon('ban') ?> Confirm Revocation</button>
                    </form>
                    <?php endif; ?>
                <?php else: ?>
                    <a href="view_certificate_admin.php?id=<?= (int)$cert_db_id ?>" class="btn btn-secondary"><?= cv_icon('arrow-left') ?> Back to the certificate</a>
                <?php endif; ?>
            </section>
        </div>
    </div>
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/admin-ui.js" defer></script>
</body>
</html>
