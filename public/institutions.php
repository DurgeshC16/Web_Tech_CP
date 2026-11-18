<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/utils/helpers.php';
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
<?php
$kd_key_count = 0;
foreach ($institutions as $kd_inst) { $kd_key_count += count($kd_inst['keys']); }
$kd_icon = static function (string $d): string {
    return '<svg class="sv-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' . $d . '</svg>';
};
$kd_copy = $kd_icon('<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>');
$kd_key  = $kd_icon('<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l3 3M14 9l2 2"/>');
$kd_json = $kd_icon('<path d="M8 4H7a2 2 0 0 0-2 2v4l-2 2 2 2v4a2 2 0 0 0 2 2h1M16 4h1a2 2 0 0 1 2 2v4l2 2-2 2v4a2 2 0 0 1-2 2h-1"/>');
?>
<main id="main" class="sv-main">
<div class="container verify-shell sv-shell-wide">
    <header class="sv-hero sv-hero-compact">
        <p class="sv-eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span> Public-key directory</p>
        <h1 class="sv-hero-title">Institution public-key directory</h1>
        <p class="sv-hero-sub">Compare these SHA-256 fingerprints with a value published independently by the institution. Retired keys remain listed because they verify historical certificates.</p>
        <ul class="sv-trust-chips">
            <li><span class="kd-num" data-count-to="<?= count($institutions) ?>"><?= count($institutions) ?></span>&nbsp;institutions</li>
            <li><span class="kd-num" data-count-to="<?= (int)$kd_key_count ?>"><?= (int)$kd_key_count ?></span>&nbsp;signing keys</li>
            <li><a href=".well-known/certivault-keys.json"><?= $kd_json ?>Machine-readable key list</a></li>
        </ul>
        <svg class="sv-hero-art" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l3 3M14 9l2 2"/></svg>
    </header>
    <div class="sv-body">
    <?php if (!$institutions): ?>
        <div class="empty-state"><span class="empty-state-icon"><?= $kd_key ?></span><h2>No keys yet</h2><p>No approved institution keys are available.</p></div>
    <?php endif; ?>
    <div class="kd-list">
    <?php $kd_i = 0; foreach ($institutions as $id=>$institution): $kd_i++; ?>
        <section class="card kd-card" id="institution-<?= (int)$id ?>" data-reveal data-reveal-delay="<?= min(5, $kd_i) ?>" aria-labelledby="kd-name-<?= (int)$id ?>">
            <div class="kd-head">
                <span class="kd-avatar" aria-hidden="true"><?= htmlspecialchars(mb_strtoupper(mb_substr(trim((string)$institution['name']), 0, 1))) ?></span>
                <h2 class="kd-name" id="kd-name-<?= (int)$id ?>"><?= htmlspecialchars($institution['name']) ?></h2>
                <span class="pill kd-count"><?= count($institution['keys']) ?> key<?= count($institution['keys']) === 1 ? '' : 's' ?></span>
            </div>
            <?php foreach ($institution['keys'] as $key): ?>
                <?php $kd_fp_id = 'kd-fp-' . (int)$id . '-' . (int)$key['key_id']; $kd_status = strtolower((string)$key['status']); ?>
                <div class="kd-key">
                    <div class="kd-key-top">
                        <strong class="kd-key-name"><?= $kd_key ?>Key v<?= (int)$key['key_id'] ?></strong>
                        <span class="badge-status badge-<?= $kd_status === 'active' ? 'active' : htmlspecialchars($kd_status) ?>"><?= htmlspecialchars(strtoupper($key['status'])) ?></span>
                    </div>
                    <p class="kd-fp-label"><strong>SHA-256:</strong></p>
                    <div class="kd-fp">
                        <code class="break-all" id="<?= $kd_fp_id ?>"><?= htmlspecialchars($key['fingerprint']) ?></code>
                        <button type="button" class="btn btn-ghost btn-sm kd-copy" data-copy-target="<?= $kd_fp_id ?>" data-copy-message="Fingerprint copied" aria-label="Copy fingerprint of key v<?= (int)$key['key_id'] ?>"><?= $kd_copy ?><span>Copy</span></button>
                    </div>
                    <small class="kd-valid">Valid from <?= htmlspecialchars((string)$key['valid_from']) ?><?= $key['valid_to'] ? ' until ' . htmlspecialchars((string)$key['valid_to']) : '' ?></small>
                </div>
            <?php endforeach; ?>
        </section>
    <?php endforeach; ?>
    </div>
    </div>
</div></main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
