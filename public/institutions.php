<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/utils/helpers.php';
if (!CERTIFICATE_TRANSPARENCY_ENABLED) { http_response_code(404); exit('Institution key directory is disabled.'); }
$db = Database::getInstance();
$stmt = $db->query("SELECT i.id AS institution_id,i.name,k.key_id,k.public_key,k.status,k.valid_from,k.valid_to
    FROM institutions i JOIN institution_keys k ON k.institution_id=i.id
    WHERE i.status='approved' ORDER BY i.name,k.key_id DESC");
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
$institutions=[];
foreach ($rows as $row) {
    $id=(int)$row['institution_id'];
    $row['fingerprint']=CryptoService::fingerprintPublicKey((string)$row['public_key']);
    $institutions[$id]['name']=$row['name'];
    $institutions[$id]['keys'][]=$row;
}
?>
<?php $page_title='Institution Public Keys - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main"><div class="container shell-wide">
    <h2>Institution public-key directory</h2>
    <p>Compare these SHA-256 fingerprints with a value published independently by the institution. Retired keys remain listed because they verify historical certificates. <a href=".well-known/certivault-keys.json">Machine-readable key list</a>.</p>
    <?php if (!$institutions): ?><p>No approved institution keys are available.</p><?php endif; ?>
    <?php foreach ($institutions as $id=>$institution): ?>
        <section class="card" id="institution-<?= (int)$id ?>"><h3><?= htmlspecialchars($institution['name']) ?></h3>
            <?php foreach ($institution['keys'] as $key): ?>
                <div style="border-top:1px solid var(--border);padding:10px 0;">
                    <strong>Key v<?= (int)$key['key_id'] ?></strong> — <?= htmlspecialchars(strtoupper($key['status'])) ?>
                    <p><strong>SHA-256:</strong> <code class="break-all"><?= htmlspecialchars($key['fingerprint']) ?></code></p>
                    <small>Valid from <?= htmlspecialchars((string)$key['valid_from']) ?><?= $key['valid_to'] ? ' until ' . htmlspecialchars((string)$key['valid_to']) : '' ?></small>
                </div>
            <?php endforeach; ?>
        </section>
    <?php endforeach; ?>
</div></main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
