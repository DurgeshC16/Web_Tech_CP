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
<?php $page_title = 'External Credentials - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main"><div class="container shell-wide">
    <div class="page-head"><h2>My external credentials</h2><a class="btn btn-secondary" href="student_dashboard.php">Back</a></div>
    <p>These are credentials you declare from another issuer. CertiVault does not contact or verify the issuer.</p>
    <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>
    <?php if ($success): ?><div class="alert alert-info"><?= htmlspecialchars($success) ?></div><?php endif; ?>
    <form method="POST" enctype="multipart/form-data" class="card">
        <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
        <h3>Add an external credential</h3>
        <div class="form-row">
            <div class="form-group"><label for="issuer">Issuer</label><select id="issuer" name="issuer" required><?php foreach ($issuers as $slug=>$issuerInfo): ?><option value="<?= htmlspecialchars($slug) ?>"><?= htmlspecialchars($issuerInfo['label']) ?></option><?php endforeach; ?></select></div>
            <div class="form-group"><label for="title">Credential title</label><input id="title" name="title" maxlength="200" data-validate="required|min:3|max:200" required></div>
        </div>
        <div class="form-row">
            <div class="form-group"><label for="issuer_code">Credential code (optional if URL supplied)</label><input id="issuer_code" name="issuer_code" maxlength="255"></div>
            <div class="form-group"><label for="issue_date">Issue date</label><input type="date" id="issue_date" name="issue_date" data-validate="required|daterange" required></div>
        </div>
        <div class="form-group"><label for="verification_url">Official verification URL (optional if code supplied)</label><input type="url" id="verification_url" name="verification_url" maxlength="2048" placeholder="https://..."><small>Only exact allow-listed HTTPS issuer hosts are accepted. No issuer site is contacted.</small></div>
        <div class="form-group"><label for="credential_pdf">Optional supporting PDF (max 5 MB)</label><input type="file" id="credential_pdf" name="credential_pdf" accept="application/pdf,.pdf"></div>
        <button class="btn btn-primary" type="submit">Add as self-declared</button>
    </form>
    <h3 style="margin-top:24px;">Credential records</h3>
    <?php if (!$credentials): ?><p>No external credentials added yet.</p><?php else: ?>
    <div class="grid-container"><?php foreach ($credentials as $credential): ?>
        <article class="card"><h3><?= htmlspecialchars($credential['title']) ?></h3>
            <p><?= htmlspecialchars($credential['issuer_label']) ?><?= $credential['issuer_code'] ? ' — ' . htmlspecialchars($credential['issuer_code']) : '' ?></p>
            <p>Issued <?= htmlspecialchars($credential['issue_date']) ?></p>
            <p><strong>Status:</strong> <?= htmlspecialchars($credential['verdict']) ?> (never VALID)</p>
            <?php $score = TrustScoreService::computeExternalCredential($db, $credential); ?><p>Attestation score: <?= (int)$score['score'] ?>/70</p>
            <a class="btn btn-secondary" href="external_credential.php?token=<?= rawurlencode($credential['public_token']) ?>">Public share page / QR</a>
            <?php if (is_file(__DIR__ . '/qrcodes/' . $credential['public_token'] . '.png')): ?><div class="qr-hero"><img src="qrcodes/<?= htmlspecialchars($credential['public_token']) ?>.png" alt="Public external credential QR"></div><?php endif; ?>
        </article>
    <?php endforeach; ?></div><?php endif; ?>
</div></main>
<script src="assets/js/validation.js"></script>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
