<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/AttestedCredentialService.php';
require_once __DIR__ . '/../src/services/TrustScoreService.php';
require_once __DIR__ . '/../src/services/GuestQuotaService.php';
if (!defined('ATTESTED_EXTERNAL_CREDENTIALS_ENABLED') || !ATTESTED_EXTERNAL_CREDENTIALS_ENABLED) { http_response_code(404); exit('External credential attestations are disabled.'); }
$db = Database::getInstance();
$token = (string)($_GET['token'] ?? '');
$record = null;
$verdict = null;
$ec_quota = null;    // guest quota status (GuestQuotaService)
$ec_blocked = false; // guest has used every free verification
if (preg_match('/^[A-Za-z0-9_-]{43}$/', $token)) {
    // Guest quota: a public record lookup counts like verify.php (the same
    // link again is free; logged-in users are exempt). Checked BEFORE the
    // query; a malformed token never reaches a lookup and costs nothing.
    $ec_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $ec_quota = GuestQuotaService::check($db, $ec_ip, $_SESSION, ['ext:' . $token]);
    $ec_blocked = !$ec_quota['allowed'];
}
if (preg_match('/^[A-Za-z0-9_-]{43}$/', $token) && !$ec_blocked) {
    $stmt = $db->prepare('SELECT ec.* FROM external_credentials ec WHERE ec.public_token=:token LIMIT 1');
    $stmt->execute(['token'=>$token]);
    $record = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    $ec_quota = GuestQuotaService::record($db, $ec_ip, $_SESSION, ['ext:' . $token]);
}
if ($ec_blocked) {
    GuestQuotaService::sendLimitHeaders($ec_quota);
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
<?php
$ec_icon = static function (string $d): string {
    return '<svg class="sv-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' . $d . '</svg>';
};
$ec_check = $ec_icon('<path d="M5 13l4 4L19 7"/>');
// Badge colour per record verdict (presentation only).
$ec_badge = ['ATTESTED' => 'badge-info', 'SELF_DECLARED' => 'badge-pending', 'TAMPERED' => 'badge-tampered'];
?>
<main id="main" class="sv-main"><div class="container verify-shell">
    <?php if ($ec_blocked): ?>
        <div class="sv-body">
            <div class="sv-limit">
                <span class="sv-limit-badge" aria-hidden="true"><?= $ec_icon('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>') ?></span>
                <?= GuestQuotaService::renderLimitNotice($ec_quota) ?>
                <ul class="sv-limit-perks" aria-label="Why create an account">
                    <li><?= $ec_check ?>No daily limit when signed in</li>
                    <li><?= $ec_check ?>Free to create</li>
                    <li><?= $ec_check ?>Same instant verification</li>
                </ul>
            </div>
        </div>
    <?php elseif (!$record): ?>
        <div class="sv-body sv-notice-page text-center">
            <span class="sv-notice-icon sv-tone-neutral" aria-hidden="true"><?= $ec_icon('<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5M8.5 8.5l5 5M13.5 8.5l-5 5"/>') ?></span>
            <h1 class="sv-notice-title">External credential record not found</h1>
            <p class="sv-notice-text">This public link is invalid or no longer available.</p>
            <a class="btn btn-secondary" href="verify.php">Verify a certificate</a>
        </div>
    <?php else: ?>
        <header class="sv-hero sv-hero-compact">
            <p class="sv-eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span> Public record · not a CertiVault verdict</p>
            <h1 class="sv-hero-title">Attested external credential</h1>
            <p class="sv-hero-sub">A credential issued outside CertiVault, recorded here with an institution's attestation or the student's own declaration.</p>
        </header>
        <div class="sv-body sv-result-body">
        <article class="card diploma sv-cert ec-card" aria-labelledby="ecTitle">
            <header class="sv-cert-head">
                <span class="sv-cert-mark" aria-hidden="true"><?= $ec_icon('<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>') ?></span>
                <div class="sv-cert-heading">
                    <p class="sv-cert-kicker">Issuer: <?= htmlspecialchars($record['issuer_label']) ?></p>
                    <h2 class="cert-details-title" id="ecTitle"><?= htmlspecialchars($record['title']) ?></h2>
                </div>
            </header>
            <dl class="sv-facts">
                <div><dt>Student-declared holder</dt><dd><?= htmlspecialchars($record['student_name']) ?></dd></div>
                <div><dt>Issuer</dt><dd><?= htmlspecialchars($record['issuer_label']) ?></dd></div>
                <?php if ($record['issuer_code']): ?><div><dt>Issuer code</dt><dd><?= htmlspecialchars($record['issuer_code']) ?></dd></div><?php endif; ?>
                <div><dt>Claimed issue date</dt><dd><?= htmlspecialchars($record['issue_date']) ?></dd></div>
                <div><dt>Record verdict</dt><dd><span class="badge-status <?= $ec_badge[$verdict] ?? 'badge-revoked' ?>"><?= htmlspecialchars($verdict) ?></span></dd></div>
            </dl>
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
            <div class="ec-score">
                <p class="m-0"><strong>Attestation trust score:</strong> <span class="ec-score-num"><?= (int)$score['score'] ?>/70</span> <small>(never a VALID verdict; does not establish issuer authenticity)</small></p>
                <meter class="ec-meter" min="0" max="70" low="30" high="55" optimum="70" value="<?= max(0, min(70, (int)$score['score'])) ?>" aria-label="Attestation trust score"><?= (int)$score['score'] ?>/70</meter>
            </div>
            <?php if ($officialLink): ?><div><a class="btn btn-primary" href="<?= htmlspecialchars($officialLink['url']) ?>" target="_blank" rel="noopener noreferrer">Open <?= htmlspecialchars($record['issuer_label']) ?> official link ↗</a></div>
            <?php elseif ($verdict !== 'TAMPERED'): ?><p class="field-error">The stored issuer URL is no longer on the exact allow-list; it is not clickable.</p><?php endif; ?>
            <p class="sv-share-note"><small>Shared via a public CertiVault record link. No issuer was contacted to display this page.</small></p>
        </article>
        <?= is_array($ec_quota) ? GuestQuotaService::renderCounter($ec_quota) : '' ?>
        <?php if (is_file(__DIR__ . '/qrcodes/' . $record['public_token'] . '.png')): ?><div class="qr-hero"><p><strong>Public record QR:</strong></p><img src="qrcodes/<?= htmlspecialchars($record['public_token']) ?>.png" alt="QR code for this external credential record"></div><?php endif; ?>
        </div>
    <?php endif; ?>
</div></main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
