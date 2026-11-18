<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/utils/validators.php';
require_once __DIR__ . '/../src/services/AttestedCredentialService.php';
require_once __DIR__ . '/../src/services/TrustScoreService.php';
if (!defined('ATTESTED_EXTERNAL_CREDENTIALS_ENABLED') || !ATTESTED_EXTERNAL_CREDENTIALS_ENABLED) { http_response_code(404); exit('External credential attestations are disabled.'); }
require_role('student');
$db = Database::getInstance();
$studentId = (int)current_student_id($db);
$error = '';
$success = '';
$issuers = AttestedCredentialService::issuerOptions($db);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    $issuer = trim((string)($_POST['issuer'] ?? ''));
    $title = trim((string)($_POST['title'] ?? ''));
    $issueDate = trim((string)($_POST['issue_date'] ?? ''));
    $code = trim((string)($_POST['issuer_code'] ?? ''));
    $urlInput = trim((string)($_POST['verification_url'] ?? ''));
    if (!isset($issuers[$issuer])) $error = 'Choose a supported issuer.';
    elseif (($e = v_length($title, 3, 200, 'Title')) !== true) $error = $e;
    elseif (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $issueDate) || ($e = v_date_range($issueDate, null)) !== true) $error = 'Enter a valid issue date that is not in the future.';
    elseif ($code !== '' && (strlen($code) > 255 || !preg_match('/^[A-Za-z0-9._:-]+$/', $code))) $error = 'Credential code contains unsupported characters.';
    elseif ($urlInput === '' && $code === '') $error = 'Enter either the issuer verification URL or a credential code.';
    else {
        $url = $urlInput !== '' ? $urlInput : AttestedCredentialService::urlFromCode($issuer, $code);
        if ($url === null) $error = 'A verification URL is required for this custom issuer.';
        else {
            [$validatedUrl, $urlError] = AttestedCredentialService::validateIssuerUrl($db, $issuer, $url);
            if ($validatedUrl === null) $error = $urlError;
        }
    }

    $file = $_FILES['credential_pdf'] ?? null;
    if ($error === '' && $file && ($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
        if (($file['error'] ?? UPLOAD_ERR_OK) !== UPLOAD_ERR_OK) $error = 'The optional PDF upload failed. Please retry.';
        elseif ((int)($file['size'] ?? 0) < 100 || (int)$file['size'] > 5 * 1024 * 1024) $error = 'PDF must be between 100 bytes and 5 MB.';
        elseif (strtolower(pathinfo((string)$file['name'], PATHINFO_EXTENSION)) !== 'pdf'
            || !class_exists('finfo') || (new finfo(FILEINFO_MIME_TYPE))->file($file['tmp_name']) !== 'application/pdf') $error = 'Only a genuine PDF file is accepted.';
        elseif (!is_uploaded_file($file['tmp_name'])) $error = 'The uploaded file could not be validated.';
    }

    if ($error === '') {
        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $storedFile = null;
        $fileHash = null;
        try {
            if ($file && ($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_OK) {
                $dir = __DIR__ . '/../private_data/external_credentials';
                if (!is_dir($dir) && !mkdir($dir, 0750, true) && !is_dir($dir)) throw new RuntimeException('Credential storage is unavailable.');
                $storedFile = bin2hex(random_bytes(24)) . '.pdf';
                $destination = $dir . '/' . $storedFile;
                if (!move_uploaded_file($file['tmp_name'], $destination)) throw new RuntimeException('The optional PDF could not be saved.');
                $fileHash = hash_file('sha256', $destination);
            }
            $studentStmt = $db->prepare('SELECT full_name FROM students WHERE id=:sid');
            $studentStmt->execute(['sid'=>$studentId]);
            $studentName = (string)$studentStmt->fetchColumn();
            $stmt = $db->prepare('INSERT INTO external_credentials (public_token,student_id,student_name,issuer_slug,issuer_label,verification_url,issuer_code,title,issue_date,file_path,file_sha256,status) VALUES (:token,:sid,:student_name,:slug,:label,:url,:code,:title,:date,:path,:sha,"SELF_DECLARED")');
            $stmt->execute(['token'=>$token,'sid'=>$studentId,'student_name'=>$studentName,'slug'=>$issuer,'label'=>$validatedUrl['label'],'url'=>$validatedUrl['url'],'code'=>$code !== '' ? $code : null,'title'=>$title,'date'=>$issueDate,'path'=>$storedFile,'sha'=>$fileHash]);
            $record = ['id'=>(int)$db->lastInsertId()];
            AttestedCredentialService::logEvent($db, $record, 'SELF_DECLARED', 'Student user #' . (int)$_SESSION['user_id'] . ' submitted external credential.');
            try {
                require_once __DIR__ . '/../src/services/QRService.php';
                QRService::generateQRCode(BASE_URL . '/external_credential.php?token=' . rawurlencode($token), __DIR__ . '/qrcodes/' . $token . '.png');
            } catch (Throwable $qrError) { error_log('[CertiVault] External credential QR generation failed: ' . $qrError->getMessage()); }
            $success = 'Credential added as SELF_DECLARED. It is not verified until an approved institution attests it.';
        } catch (Throwable $e) {
            if (!empty($destination) && is_file($destination)) @unlink($destination);
            error_log('[CertiVault] External credential submission failed: ' . $e->getMessage());
            $error = 'The credential could not be saved. Please try again.';
        }
    }
}

$stmt = $db->prepare('SELECT * FROM external_credentials WHERE student_id=:sid ORDER BY created_at DESC');
$stmt->execute(['sid'=>$studentId]);
$credentials = $stmt->fetchAll(PDO::FETCH_ASSOC);
foreach ($credentials as &$credential) $credential['verdict'] = AttestedCredentialService::verdict($db, $credential);
unset($credential);
?>
<?php
// ── Presentation only ─────────────────────────────────────────────────
// Badge colour per verdict (never the green "valid" style: an external
// credential is at most ATTESTED, never VALID).
$ec_badge = static function (string $verdict): string {
    return [
        'ATTESTED'      => 'info',
        'SELF_DECLARED' => 'pending',
        'TAMPERED'      => 'tampered',
        'WITHDRAWN'     => 'invalid',
    ][$verdict] ?? 'invalid';
};
$ec_icon = static function (string $name): string {
    $paths = [
        'globe'  => '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
        'plus'   => '<path d="M12 5v14M5 12h14"/>',
        'back'   => '<path d="M19 12H5M11 18l-6-6 6-6"/>',
        'info'   => '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
        'calendar' => '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 11h18"/>',
        'building' => '<path d="M3 21h18M5 21V9l7-5 7 5v12M9 21v-6h6v6"/>',
        'qr'     => '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20h.01M17 20h4v-3"/>',
        'stack'  => '<path d="M12 2 2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5M2 12l10 5 10-5"/>',
    ];
    return '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
        . ($paths[$name] ?? '') . '</svg>';
};
?>
<?php $page_title = 'External Credentials - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main" class="stu-main"><div class="stu-shell">
    <nav class="stu-crumbs" aria-label="Breadcrumb">
        <ol>
            <li><a href="student_dashboard.php">My Certificates</a></li>
            <li aria-current="page">External credentials</li>
        </ol>
    </nav>
    <div class="page-head">
        <div>
            <p class="eyebrow">Beyond CertiVault</p>
            <h1>My external credentials</h1>
            <p class="page-head-sub">These are credentials you declare from another issuer. CertiVault does not contact or verify the issuer.</p>
        </div>
        <div class="page-head-actions"><a class="btn btn-secondary" href="student_dashboard.php"><?= $ec_icon('back') ?>Back</a></div>
    </div>
    <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <?php if ($success): ?><div class="alert alert-info"><?= htmlspecialchars($success) ?></div><?php endif; ?>

    <div class="stu-ext-grid">
        <form method="POST" enctype="multipart/form-data" class="card stu-ext-form" data-reveal>
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <div class="stu-panel-head">
                <span class="stu-panel-icon"><?= $ec_icon('plus') ?></span>
                <h2>Add an external credential</h2>
            </div>
            <div class="form-row">
                <div class="form-group"><label for="issuer">Issuer</label><select id="issuer" name="issuer" required><?php foreach ($issuers as $slug=>$issuerInfo): ?><option value="<?= htmlspecialchars($slug) ?>"><?= htmlspecialchars($issuerInfo['label']) ?></option><?php endforeach; ?></select></div>
                <div class="form-group"><label for="title">Credential title</label><input id="title" name="title" maxlength="200" data-validate="required|min:3|max:200" required></div>
            </div>
            <div class="form-row">
                <div class="form-group"><label for="issuer_code">Credential code (optional if URL supplied)</label><input id="issuer_code" name="issuer_code" maxlength="255"></div>
                <div class="form-group"><label for="issue_date">Issue date</label><input type="date" id="issue_date" name="issue_date" data-validate="required|daterange" required></div>
            </div>
            <div class="form-group"><label for="verification_url">Official verification URL (optional if code supplied)</label><input type="url" id="verification_url" name="verification_url" maxlength="2048" placeholder="https://..."><small>Only exact allow-listed HTTPS issuer hosts are accepted. No issuer site is contacted.</small></div>
            <div class="form-group"><label for="credential_pdf">Optional supporting PDF (max 5 MB)</label><input type="file" id="credential_pdf" name="credential_pdf" accept="application/pdf,.pdf" data-filename-target="credential_pdf_name"><small class="file-name-display" id="credential_pdf_name" aria-live="polite"></small></div>
            <div class="stu-ext-submit">
                <button class="btn btn-primary" type="submit"><?= $ec_icon('plus') ?>Add as self-declared</button>
            </div>
        </form>

        <aside class="card stu-panel stu-ext-how" aria-labelledby="extHowTitle" data-reveal data-reveal-delay="1">
            <div class="stu-panel-head">
                <span class="stu-panel-icon stu-icon-cyan"><?= $ec_icon('info') ?></span>
                <h2 id="extHowTitle">How attestation works</h2>
            </div>
            <ol class="stu-steps">
                <li><strong>You declare it.</strong> The record starts as <span class="badge-status badge-pending">SELF_DECLARED</span>.</li>
                <li><strong>An approved institution checks it.</strong> If it attests the record, the status becomes <span class="badge-status badge-info">ATTESTED</span> and is signed.</li>
                <li><strong>You share it.</strong> Each record has a public page and QR code anyone can open.</li>
            </ol>
            <p class="stu-panel-note">External credentials are never shown as VALID &mdash; only CertiVault-issued certificates can be.</p>
        </aside>
    </div>

    <section class="stu-section" aria-labelledby="extRecordsTitle">
        <div class="stu-section-head">
            <h2 id="extRecordsTitle">Credential records</h2>
            <?php if ($credentials): ?><span class="pill"><?= count($credentials) ?> total</span><?php endif; ?>
        </div>
        <?php if (!$credentials): ?>
            <div class="empty-state" data-reveal="zoom">
                <span class="empty-state-icon"><?= $ec_icon('stack') ?></span>
                <h3>No external credentials yet</h3>
                <p>No external credentials added yet. Add one with the form above to get a shareable public page and QR code.</p>
            </div>
        <?php else: ?>
        <div class="stu-cert-grid"><?php foreach ($credentials as $ec_i => $credential): ?>
            <?php $score = TrustScoreService::computeExternalCredential($db, $credential); $ec_score = max(0, min(70, (int)$score['score'])); ?>
            <div class="stu-reveal" data-reveal data-reveal-delay="<?= ($ec_i % 3) + 1 ?>"><article class="card card-hover stu-cert-card stu-ext-card">
                <div class="stu-cert-top">
                    <span class="stu-cert-icon"><?= $ec_icon('globe') ?></span>
                    <span class="badge-status badge-<?= htmlspecialchars($ec_badge((string)$credential['verdict'])) ?>"><?= htmlspecialchars($credential['verdict']) ?></span>
                </div>
                <h3 class="card-title"><?= htmlspecialchars($credential['title']) ?></h3>
                <p class="stu-cert-inst"><?= $ec_icon('building') ?><span><?= htmlspecialchars($credential['issuer_label']) ?><?= $credential['issuer_code'] ? ' — ' . htmlspecialchars($credential['issuer_code']) : '' ?></span></p>
                <p class="stu-cert-inst"><?= $ec_icon('calendar') ?><span>Issued <?= htmlspecialchars($credential['issue_date']) ?></span></p>
                <p class="stu-ext-status"><strong>Status:</strong> <?= htmlspecialchars($credential['verdict']) ?> (never VALID)</p>
                <div class="stu-meter">
                    <div class="stu-meter-label"><span>Attestation score</span><span><?= (int)$score['score'] ?>/70</span></div>
                    <svg class="stu-meter-bar" viewBox="0 0 70 8" preserveAspectRatio="none" aria-hidden="true" focusable="false">
                        <rect class="stu-meter-track" width="70" height="8" rx="4"/>
                        <rect class="stu-meter-fill" width="<?= $ec_score ?>" height="8" rx="4"/>
                    </svg>
                </div>
                <?php if (is_file(__DIR__ . '/qrcodes/' . $credential['public_token'] . '.png')): ?><div class="qr-hero stu-ext-qr"><img src="qrcodes/<?= htmlspecialchars($credential['public_token']) ?>.png" alt="Public external credential QR" width="140" height="140"></div><?php endif; ?>
                <div class="card-actions">
                    <a class="btn btn-secondary btn-sm" href="external_credential.php?token=<?= rawurlencode($credential['public_token']) ?>"><?= $ec_icon('qr') ?>Public share page / QR</a>
                </div>
            </article></div>
        <?php endforeach; ?></div><?php endif; ?>
    </section>
</div></main>
<script src="assets/js/validation.js"></script>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
