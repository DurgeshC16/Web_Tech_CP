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
<?php $page_title = 'External Credential Attestations - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main"><div class="container shell-wide">
    <div class="page-head"><h2>External credential review</h2><a href="admin_dashboard.php" class="btn btn-secondary">Back</a></div>
    <p>Open the issuer’s official link and compare the student’s evidence yourself. Attesting records your institution’s statement only; CertiVault does not contact the issuer.</p>
    <?php if ($message): ?><div class="alert alert-info"><?= htmlspecialchars($message) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <?php if (!$credentials): ?><p>No credentials are awaiting review, and your institution has no existing attestations.</p><?php else: ?>
    <div class="grid-container"><?php foreach ($credentials as $record): ?>
        <article class="card"><h3><?= htmlspecialchars($record['title']) ?></h3>
            <p><strong>Student:</strong> <?= htmlspecialchars($record['student_name']) ?></p>
            <p><strong>Issuer:</strong> <?= htmlspecialchars($record['issuer_label']) ?><?= $record['issuer_code'] ? ' — ' . htmlspecialchars($record['issuer_code']) : '' ?></p>
            <p><strong>Claimed issue date:</strong> <?= htmlspecialchars($record['issue_date']) ?></p>
            <p><strong>Record status:</strong> <?= htmlspecialchars($record['verdict']) ?></p>
            <?php [$safeLink] = AttestedCredentialService::validateIssuerUrl($db, (string)$record['issuer_slug'], (string)$record['verification_url']); ?>
            <?php if ($safeLink && $record['verdict'] !== 'TAMPERED'): ?><a href="<?= htmlspecialchars($safeLink['url']) ?>" class="btn btn-secondary" target="_blank" rel="noopener noreferrer">Open issuer’s official link ↗</a><?php else: ?><span class="field-error">Issuer link is not safe to open; review the stored host.</span><?php endif; ?>
            <a href="external_credential.php?token=<?= rawurlencode($record['public_token']) ?>" class="btn btn-ghost">Public record</a>
            <?php if (!empty($record['file_path'])): ?> <a href="external_credential_file.php?id=<?= (int)$record['id'] ?>" class="btn btn-ghost">Download student PDF</a><?php endif; ?>
            <?php if ($record['verdict'] === 'SELF_DECLARED'): ?>
            <form method="POST" class="inline-form" style="margin-top:10px;" onsubmit="return confirm('You checked this credential at the issuer. This records your institution’s attestation, not CertiVault verification. Continue?');">
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>"><input type="hidden" name="credential_id" value="<?= (int)$record['id'] ?>">
                <button class="btn btn-primary" name="attest" value="1">Attest after checking</button>
            </form>
            <?php elseif ($record['attesting_institution_id'] == $institutionId && $record['verdict'] === 'ATTESTED'): ?>
                <p><small>Attested <?= htmlspecialchars((string)$record['attested_at']) ?> by <?= htmlspecialchars((string)$record['attesting_name']) ?></small></p>
                <form method="POST" class="inline-form" onsubmit="return confirm('Withdraw your institution’s attestation?');">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>"><input type="hidden" name="credential_id" value="<?= (int)$record['id'] ?>">
                    <button class="btn btn-danger" name="withdraw" value="1">Withdraw attestation</button>
                </form>
            <?php endif; ?>
        </article>
    <?php endforeach; ?></div><?php endif; ?>
</div></main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
