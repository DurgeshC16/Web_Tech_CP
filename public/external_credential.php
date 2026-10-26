<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/AttestedCredentialService.php';
require_once __DIR__ . '/../src/services/TrustScoreService.php';
if (!defined('ATTESTED_EXTERNAL_CREDENTIALS_ENABLED') || !ATTESTED_EXTERNAL_CREDENTIALS_ENABLED) { http_response_code(404); exit('External credential attestations are disabled.'); }
$db = Database::getInstance();
$token = (string)($_GET['token'] ?? '');
$record = null;
$verdict = null;
if (preg_match('/^[A-Za-z0-9_-]{43}$/', $token)) {
$stmt = $db->prepare('SELECT ec.* FROM external_credentials ec WHERE ec.public_token=:token LIMIT 1');
    $stmt->execute(['token'=>$token]);
    $record = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}
if ($record) {
    $verdict = AttestedCredentialService::verdict($db, $record);
    AttestedCredentialService::logEvent($db, $record, $verdict, 'Public external credential record viewed.');
    [$officialLink, $linkError] = AttestedCredentialService::validateIssuerUrl($db, (string)$record['issuer_slug'], (string)$record['verification_url']);
    if ($verdict === 'TAMPERED') $officialLink = null;
    $score = TrustScoreService::computeExternalCredential($db, $record);
}
?>
<?php $page_title = 'External Credential Record - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main"><div class="container shell-narrow">
    <?php if (!$record): ?>
        <h2>External credential record not found</h2><p>This public link is invalid or no longer available.</p>
    <?php else: ?>
        <h2>Attested external credential</h2>
        <article class="card">
            <h3><?= htmlspecialchars($record['title']) ?></h3>
            <p><strong>Student-declared holder:</strong> <?= htmlspecialchars($record['student_name']) ?></p>
            <p><strong>Issuer:</strong> <?= htmlspecialchars($record['issuer_label']) ?></p>
            <?php if ($record['issuer_code']): ?><p><strong>Issuer code:</strong> <?= htmlspecialchars($record['issuer_code']) ?></p><?php endif; ?>
            <p><strong>Claimed issue date:</strong> <?= htmlspecialchars($record['issue_date']) ?></p>
            <p><strong>Record verdict:</strong> <span class="badge-status"><?= htmlspecialchars($verdict) ?></span></p>
            <?php if ($verdict === 'ATTESTED'): ?>
                <div class="alert alert-info">
                    <strong><?= htmlspecialchars((string)$record['attesting_institution_name']) ?> attests it checked this on <?= htmlspecialchars(date('F j, Y', strtotime($record['attested_at']))) ?>. CertiVault has NOT verified it with <?= htmlspecialchars($record['issuer_label']) ?>.</strong>
                </div>
            <?php elseif ($verdict === 'SELF_DECLARED'): ?>
                <div class="alert alert-info">SELF_DECLARED by the student. No institution has attested this record. CertiVault has NOT verified it with <?= htmlspecialchars($record['issuer_label']) ?>.</div>
            <?php elseif ($verdict === 'TAMPERED'): ?>
                <div class="alert alert-danger">The attestation signature or a signed field does not match. Do not rely on this record.</div>
            <?php else: ?>
                <div class="alert alert-danger">This institution has withdrawn its attestation. CertiVault has NOT verified it with <?= htmlspecialchars($record['issuer_label']) ?>.</div>
            <?php endif; ?>
            <p><strong>Attestation trust score:</strong> <?= (int)$score['score'] ?>/70 <small>(never a VALID verdict; does not establish issuer authenticity)</small></p>
            <?php if ($officialLink): ?><a class="btn btn-primary" href="<?= htmlspecialchars($officialLink['url']) ?>" target="_blank" rel="noopener noreferrer">Open <?= htmlspecialchars($record['issuer_label']) ?> official link ↗</a>
            <?php elseif ($verdict !== 'TAMPERED'): ?><p class="field-error">The stored issuer URL is no longer on the exact allow-list; it is not clickable.</p><?php endif; ?>
            <p style="margin-top:14px;"><small>Shared via a public CertiVault record link. No issuer was contacted to display this page.</small></p>
        </article>
        <?php if (is_file(__DIR__ . '/qrcodes/' . $record['public_token'] . '.png')): ?><div class="qr-hero"><p><strong>Public record QR:</strong></p><img src="qrcodes/<?= htmlspecialchars($record['public_token']) ?>.png" alt="QR code for this external credential record"></div><?php endif; ?>
    <?php endif; ?>
</div></main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
