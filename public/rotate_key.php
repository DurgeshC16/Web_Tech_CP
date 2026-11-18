<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/KeyPinService.php';
if (!CERTIFICATE_TRANSPARENCY_ENABLED) { http_response_code(404); exit('Certificate transparency and key rotation are disabled.'); }
require_role('admin');
require_approved_institution();
$db = Database::getInstance();
$institutionId = (int)current_institution_id($db);
$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    try {
        $db->beginTransaction();
        $stmt = $db->prepare('SELECT id FROM institutions WHERE id=:iid AND user_id=:uid AND status="approved" FOR UPDATE');
        $stmt->execute(['iid'=>$institutionId,'uid'=>(int)$_SESSION['user_id']]);
        if (!$stmt->fetch()) throw new RuntimeException('Institution approval is required to rotate its signing key.');
        $keyStmt = $db->prepare('SELECT key_id FROM institution_keys WHERE institution_id=:iid AND status="active" ORDER BY key_id DESC LIMIT 1 FOR UPDATE');
        $keyStmt->execute(['iid'=>$institutionId]);
        $oldKeyId = $keyStmt->fetchColumn();
        $maxStmt = $db->prepare('SELECT COALESCE(MAX(key_id),0)+1 FROM institution_keys WHERE institution_id=:iid');
        $maxStmt->execute(['iid'=>$institutionId]);
        $newKeyId = (int)$maxStmt->fetchColumn();
        $keys = CryptoService::generateRSAKeyPair();
        $encrypted = CryptoService::encryptPrivateKey($keys['private_key']);
        if (!CryptoService::verifyKeyPair(CryptoService::decryptPrivateKey($encrypted), $keys['public_key'])) throw new RuntimeException('New key pair failed its round-trip check.');
        if ($oldKeyId !== false) {
            $retire = $db->prepare('UPDATE institution_keys SET status="retired",valid_to=NOW() WHERE institution_id=:iid AND key_id=:kid AND status="active"');
            $retire->execute(['iid'=>$institutionId,'kid'=>(int)$oldKeyId]);
        }
        $insert = $db->prepare('INSERT INTO institution_keys (institution_id,key_id,public_key,encrypted_private_key,status,valid_from) VALUES (:iid,:kid,:pub,:priv,"active",NOW())');
        $insert->execute(['iid'=>$institutionId,'kid'=>$newKeyId,'pub'=>$keys['public_key'],'priv'=>$encrypted]);
        $db->commit();
        KeyPinService::pinQuietly($institutionId, $newKeyId, $keys['public_key'], 'rotation');
        $fingerprint = CryptoService::fingerprintPublicKey($keys['public_key']);
        $message = 'Key rotated. New signing key v' . $newKeyId . ' fingerprint: ' . $fingerprint . '. Previously signed certificates continue to verify with their recorded key version.';
    } catch (Throwable $e) {
        if ($db->inTransaction()) $db->rollBack();
        error_log('[CertiVault] Institution key rotation failed: ' . $e->getMessage());
        $error = 'Key rotation failed. The current key remains active.';
    }
}

$stmt = $db->prepare('SELECT i.name,k.key_id,k.public_key,k.valid_from FROM institutions i JOIN institution_keys k ON k.institution_id=i.id AND k.status="active" WHERE i.id=:iid LIMIT 1');
$stmt->execute(['iid'=>$institutionId]);
$activeKey = $stmt->fetch(PDO::FETCH_ASSOC);
?>
<?php
require_once __DIR__ . '/../src/utils/admin_ui.php';
$page_title = 'Rotate Institution Key - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main"><div class="admin-shell admin-shell-narrow">
    <header class="admin-head admin-head-warn">
        <div class="admin-head-row">
            <span class="admin-head-icon" aria-hidden="true"><?= cv_icon('key') ?></span>
            <div class="admin-head-text">
                <ol class="crumbs" aria-label="Breadcrumb"><li><a href="admin_dashboard.php">Dashboard</a></li><li aria-current="page">Rotate key</li></ol>
                <h1>Rotate signing key</h1>
                <p class="admin-head-sub"><?= htmlspecialchars((string)($activeKey['name'] ?? 'Your institution')) ?>’s certificates retain their key version. Rotating changes the key used for future certificates only.</p>
            </div>
        </div>
    </header>
    <?php if ($message): ?><div class="alert alert-info" role="status"><?= htmlspecialchars($message) ?></div><?php endif; ?>
    <?php if ($error): ?><div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <?php if ($activeKey): ?>
        <section class="card zone-card" aria-labelledby="currentKeyTitle">
            <div class="key-card-head">
                <div class="zone-head">
                    <span class="zone-icon" aria-hidden="true"><?= cv_icon('shield') ?></span>
                    <div><h2 id="currentKeyTitle">Current key v<?= (int)$activeKey['key_id'] ?></h2><p>Active since <?= htmlspecialchars(date('M j, Y', strtotime((string)$activeKey['valid_from']))) ?></p></div>
                </div>
                <span class="badge-status badge-valid">active</span>
            </div>
            <div>
                <p class="text-sm text-muted mb-1">SHA-256 fingerprint</p>
                <div class="token-row">
                    <code class="fingerprint" id="currentFingerprint"><?= htmlspecialchars(CryptoService::fingerprintPublicKey($activeKey['public_key'])) ?></code>
                    <button type="button" class="btn btn-ghost btn-sm btn-icon-sm" data-copy-target="currentFingerprint" data-copy-message="Fingerprint copied" aria-label="Copy fingerprint" title="Copy"><?= cv_icon('copy') ?></button>
                </div>
            </div>
        </section>
    <?php endif; ?>
    <form method="POST" class="card zone-card zone-warn" data-confirm="Generate a new signing key? Old certificates will continue using their recorded key version." data-loading>
        <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
        <div class="zone-head">
            <span class="zone-icon" aria-hidden="true"><?= cv_icon('refresh') ?></span>
            <div><h2>Generate a new key</h2><p>Use this after a suspected compromise or as routine hygiene.</p></div>
        </div>
        <ul class="consequences">
            <li><span class="cq-icon cq-ok" aria-hidden="true"><?= cv_icon('check') ?></span><span><strong>Old certificates keep verifying</strong> with the key version recorded on each of them.</span></li>
            <li><span class="cq-icon cq-info" aria-hidden="true"><?= cv_icon('key') ?></span><span><strong>New certificates use the new key.</strong> The current key is retired, not deleted.</span></li>
            <li><span class="cq-icon cq-warn" aria-hidden="true"><?= cv_icon('lock') ?></span><span>The new private key is encrypted at rest. Download or publish its fingerprint after rotation so verifiers can pin it independently.</span></li>
        </ul>
        <div class="form-actions">
            <a href="admin_dashboard.php" class="btn btn-secondary">Cancel</a>
            <button type="submit" class="btn btn-warn"><?= cv_icon('key') ?> Rotate key</button>
        </div>
    </form>
</div></main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/admin-ui.js" defer></script>
</body>
</html>
