<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/AttestedCredentialService.php';
if (!defined('ATTESTED_EXTERNAL_CREDENTIALS_ENABLED') || !ATTESTED_EXTERNAL_CREDENTIALS_ENABLED) { http_response_code(404); exit('External credential attestations are disabled.'); }
require_role('admin');
require_approved_institution();
$db = Database::getInstance();
$institutionId = (int)current_institution_id($db);
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    $id = (int)($_POST['credential_id'] ?? 0);
    try {
        if (isset($_POST['attest'])) {
            AttestedCredentialService::attest($db, $id, $institutionId);
            $record = ['id'=>$id];
            AttestedCredentialService::logEvent($db, $record, 'ATTESTED', 'Institution user #' . (int)$_SESSION['user_id'] . ' attested after manual comparison.');
            $message = 'Credential attested. The institution signed the attestation; CertiVault did not verify it with the issuer.';
        } elseif (isset($_POST['withdraw'])) {
            $stmt = $db->prepare('UPDATE external_credentials SET status="WITHDRAWN",withdrawn_at=NOW(),withdrawn_by=:uid WHERE id=:id AND attesting_institution_id=:iid AND status="ATTESTED"');
            $stmt->execute(['uid'=>(int)$_SESSION['user_id'],'id'=>$id,'iid'=>$institutionId]);
            if ($stmt->rowCount() !== 1) throw new RuntimeException('Only your institution can withdraw its own active attestation.');
            AttestedCredentialService::logEvent($db, ['id'=>$id], 'WITHDRAWN', 'Institution user #' . (int)$_SESSION['user_id'] . ' withdrew attestation.');
            $message = 'Attestation withdrawn.';
        }
    } catch (Throwable $e) {
        error_log('[CertiVault] External credential attestation action failed: ' . $e->getMessage());
        $error = 'Action could not be completed. It may already have been processed.';
    }
}

$queue = $db->prepare('SELECT ec.*,i.name AS attesting_name FROM external_credentials ec LEFT JOIN institutions i ON i.id=ec.attesting_institution_id WHERE ec.status="SELF_DECLARED" OR ec.attesting_institution_id=:iid ORDER BY CASE ec.status WHEN "SELF_DECLARED" THEN 0 ELSE 1 END,ec.created_at DESC');
$queue->execute(['iid'=>$institutionId]);
$credentials = $queue->fetchAll(PDO::FETCH_ASSOC);
foreach ($credentials as &$record) $record['verdict'] = AttestedCredentialService::verdict($db, $record);
unset($record);
?>
<?php
require_once __DIR__ . '/../src/utils/admin_ui.php';
$page_title = 'External Credential Attestations - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main"><div class="admin-shell">
    <header class="admin-head">
        <div class="admin-head-row">
            <span class="admin-head-icon" aria-hidden="true"><?= cv_icon('inbox') ?></span>
            <div class="admin-head-text">
                <ol class="crumbs" aria-label="Breadcrumb"><li><a href="admin_dashboard.php">Dashboard</a></li><li aria-current="page">Attestation queue</li></ol>
                <h1>External credential review</h1>
                <p class="admin-head-sub">Open the issuer’s official link and compare the student’s evidence yourself. Attesting records your institution’s statement only; CertiVault does not contact the issuer.</p>
            </div>
            <div class="admin-head-actions"><a href="admin_dashboard.php" class="btn btn-light"><?= cv_icon('arrow-left') ?> Back</a></div>
        </div>
    </header>
    <?php if ($message): ?><div class="alert alert-info" role="status"><?= htmlspecialchars($message) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <?php if (!$credentials): ?>
        <div class="card">
            <div class="empty-state">
                <span class="empty-state-icon"><?= cv_icon('inbox') ?></span>
                <h2>All caught up</h2>
                <p>No credentials are awaiting review, and your institution has no existing attestations.</p>
            </div>
        </div>
    <?php else: ?>
    <div class="approval-grid"><?php foreach ($credentials as $idx => $record): ?>
        <article class="card approval-card" data-reveal data-reveal-delay="<?= min(5, $idx + 1) ?>">
            <div class="approval-top">
                <span class="avatar avatar-<?= cv_avatar_hue($record['student_name']) ?>" aria-hidden="true"><?= htmlspecialchars(cv_initials($record['student_name'])) ?></span>
                <div class="flex-1"><h3><?= htmlspecialchars($record['title']) ?></h3><p><?= htmlspecialchars($record['student_name']) ?></p></div>
            </div>
            <div class="approval-meta"><span class="badge-status badge-<?= htmlspecialchars(cv_status_badge((string)$record['verdict'])) ?>"><?= htmlspecialchars(str_replace('_', ' ', (string)$record['verdict'])) ?></span></div>
            <dl class="meta-list">
                <dt>Student</dt><dd><?= htmlspecialchars($record['student_name']) ?></dd>
                <dt>Issuer</dt><dd><?= htmlspecialchars($record['issuer_label']) ?><?= $record['issuer_code'] ? ' — ' . htmlspecialchars($record['issuer_code']) : '' ?></dd>
                <dt>Claimed issue date</dt><dd><?= htmlspecialchars($record['issue_date']) ?></dd>
                <dt>Record status</dt><dd><?= htmlspecialchars($record['verdict']) ?></dd>
            </dl>
            <?php [$safeLink] = AttestedCredentialService::validateIssuerUrl($db, (string)$record['issuer_slug'], (string)$record['verification_url']); ?>
            <div class="card-links">
                <?php if ($safeLink && $record['verdict'] !== 'TAMPERED'): ?><a href="<?= htmlspecialchars($safeLink['url']) ?>" class="btn btn-secondary btn-sm" target="_blank" rel="noopener noreferrer"><?= cv_icon('external') ?> Open issuer’s official link ↗</a><?php else: ?><span class="field-error">Issuer link is not safe to open; review the stored host.</span><?php endif; ?>
                <a href="external_credential.php?token=<?= rawurlencode($record['public_token']) ?>" class="btn btn-ghost btn-sm">Public record</a>
                <?php if (!empty($record['file_path'])): ?> <a href="external_credential_file.php?id=<?= (int)$record['id'] ?>" class="btn btn-ghost btn-sm"><?= cv_icon('download') ?> Download student PDF</a><?php endif; ?>
            </div>
            <?php if ($record['verdict'] === 'SELF_DECLARED'): ?>
            <div class="approval-actions">
                <form method="POST" class="inline-form" data-confirm="You checked this credential at the issuer. This records your institution’s attestation, not CertiVault verification. Continue?">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>"><input type="hidden" name="credential_id" value="<?= (int)$record['id'] ?>">
                    <button class="btn btn-primary btn-block" name="attest" value="1"><?= cv_icon('shield') ?> Attest after checking</button>
                </form>
            </div>
            <?php elseif ($record['attesting_institution_id'] == $institutionId && $record['verdict'] === 'ATTESTED'): ?>
            <div class="approval-actions">
                <p class="m-0"><small>Attested <?= htmlspecialchars((string)$record['attested_at']) ?> by <?= htmlspecialchars((string)$record['attesting_name']) ?></small></p>
                <form method="POST" class="inline-form" data-confirm="Withdraw your institution’s attestation?">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>"><input type="hidden" name="credential_id" value="<?= (int)$record['id'] ?>">
                    <button class="btn btn-danger" name="withdraw" value="1"><?= cv_icon('x') ?> Withdraw attestation</button>
                </form>
            </div>
            <?php endif; ?>
        </article>
    <?php endforeach; ?></div><?php endif; ?>
</div></main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/admin-ui.js" defer></script>
</body>
</html>
