<?php
// public/bulk_issue.php — issue many certificates from one CSV file.
//
// Flow: upload CSV → preview (every row validated, nothing written) →
// confirm → each valid row is issued through IssuanceService with a
// generated certificate PDF (CertificatePdfService, QR embedded), one
// transaction per row → results table + results CSV download.
// Students without an activated account receive the activation email and
// are reported as "pending activation" (same gate as single issuance).
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/utils/validators.php';
require_once __DIR__ . '/../src/services/IssuanceService.php';
require_once __DIR__ . '/../src/services/CertificatePdfService.php';
require_once __DIR__ . '/../src/services/BulkIssueService.php';

require_role('admin');
require_approved_institution();

const BULK_TTL = 1800; // preview validity (seconds)

$db = Database::getInstance();
$inst = $db->prepare('SELECT id, name FROM institutions WHERE user_id = :u LIMIT 1');
$inst->execute(['u' => $_SESSION['user_id']]);
$institution = $inst->fetch();
if (!$institution) {
    show_error_page('Error', 'Institution profile not found.');
}

// ── Downloads: template / last results ────────────────────────────────
if (($_GET['download'] ?? '') === 'template') {
    BulkIssueService::sendCsv('certivault-bulk-template.csv', array_merge(BulkIssueService::REQUIRED, BulkIssueService::OPTIONAL), [
        ['student@example.com', 'Asha Verma', 'Web Technology Course Completion', date('Y-m-d'), '', ''],
    ]);
}
if (($_GET['download'] ?? '') === 'results' && !empty($_SESSION['bulk_results'])) {
    BulkIssueService::sendCsv('certivault-bulk-results.csv', ['row', 'status', 'certificate_id', 'student_email', 'title', 'verify_url', 'message'],
        array_map(fn($r) => [$r['line'], $r['status'], $r['certificate_id'] ?? '', $r['student_email'], $r['title'], $r['verify_url'] ?? '', $r['message'] ?? ''],
            $_SESSION['bulk_results']));
}

$error = '';
$preview = null;
$results = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    $action = $_POST['action'] ?? '';

    if (!CertificatePdfService::available()) {
        $error = 'Bulk issuance generates the certificate PDFs and needs dompdf. Ask the administrator to run "composer install".';
    } elseif ($action === 'preview') {
        $f = $_FILES['csv'] ?? [];
        if (($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK || !is_uploaded_file($f['tmp_name'] ?? '')) {
            [$rows, $fatal] = [[], 'Choose a CSV file to upload.'];
        } else {
            [$rows, $fatal] = BulkIssueService::parseCsv($db, $f['tmp_name'], (string)$f['name'], (int)$f['size']);
        }
        if ($fatal !== null) {
            $error = $fatal;
        } else {
            $batch = bin2hex(random_bytes(16));
            $_SESSION['bulk_batch'] = ['id' => $batch, 'rows' => $rows, 'created' => time(), 'institution' => (int)$institution['id']];
            $preview = $rows;
        }
    } elseif ($action === 'issue') {
        $b = $_SESSION['bulk_batch'] ?? null;
        if (!$b || !hash_equals($b['id'], (string)($_POST['batch_id'] ?? '')) || time() - $b['created'] > BULK_TTL
            || $b['institution'] !== (int)$institution['id']) {
            $error = 'This preview has expired. Upload the CSV again.';
        } else {
            unset($_SESSION['bulk_batch']); // one-shot: a refresh cannot issue twice
            @set_time_limit(600);
            $results = [];
            foreach ($b['rows'] as $r) {
                $res = ['line' => $r['line'], 'student_email' => $r['student_email'], 'title' => $r['title']];
                if ($r['errors']) {
                    $results[] = $res + ['status' => 'skipped', 'message' => implode(' ', $r['errors'])];
                    continue;
                }
                try {
                    $student = IssuanceService::resolveStudent($db, $r['student_email'], $r['student_name']);
                    if ($student['status'] !== 'ok') {
                        $results[] = $res + ['status' => 'pending_activation', 'message' => $student['message']];
                        continue;
                    }
                    $issued = IssuanceService::issue($db, (int)$institution['id'], $student['student_id'], [
                        'title' => $r['title'], 'issue_date' => $r['issue_date'],
                        'expiry_date' => $r['expiry_date'], 'custom_id' => $r['certificate_id'],
                    ], 'pdf', function ($certId, $qrToken, $verifyUrl, $qrPath, $destination) use ($institution, $r) {
                        $pdf = CertificatePdfService::render([
                            'institution' => $institution['name'], 'student' => $r['student_name'], 'title' => $r['title'],
                            'certificate_id' => $certId, 'issue_date' => $r['issue_date'],
                            'expiry_date' => $r['expiry_date'] ?: null, 'verify_url' => $verifyUrl,
                        ], $qrPath);
                        if (file_put_contents($destination, $pdf) === false) {
                            throw new Exception('The certificate PDF could not be saved.');
                        }
                    });
                    $notified = IssuanceService::notifyStudent($r['student_email'], $issued['certificate_id'], $r['title'], $institution['name'], $issued['verify_url']);
                    $results[] = $res + ['status' => 'issued', 'certificate_id' => $issued['certificate_id'], 'verify_url' => $issued['verify_url'],
                                         'message' => $notified ? 'student emailed' : 'email not sent'];
                } catch (PDOException $e) {
                    error_log('[CertiVault] Bulk issue DB error (row ' . $r['line'] . '): ' . $e->getMessage());
                    $results[] = $res + ['status' => 'error', 'message' => $e->getCode() === '23000' ? 'Certificate ID already in use.' : 'Database error.'];
                } catch (Throwable $e) {
                    $results[] = $res + ['status' => 'error', 'message' => $e->getMessage()];
                }
            }
            $_SESSION['bulk_results'] = $results;
        }
    }
}

$validCount = $preview ? count(array_filter($preview, fn($r) => !$r['errors'])) : 0;
$counts = $results ? array_count_values(array_column($results, 'status')) : [];
require_once __DIR__ . '/../src/utils/admin_ui.php';
$bulk_step = $results !== null ? 3 : ($preview !== null ? 2 : 1);
$page_title = 'Bulk Issue - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main">
    <div class="admin-shell">
        <header class="admin-head">
            <div class="admin-head-row">
                <span class="admin-head-icon" aria-hidden="true"><?= cv_icon('layers') ?></span>
                <div class="admin-head-text">
                    <ol class="crumbs" aria-label="Breadcrumb"><li><a href="admin_dashboard.php">Dashboard</a></li><li aria-current="page">Bulk issue</li></ol>
                    <h1>Bulk issue from CSV</h1>
                    <p class="admin-head-sub">One row per certificate. Every row is checked first — nothing is issued until you confirm the preview.</p>
                </div>
                <div class="admin-head-actions">
                    <a href="admin_dashboard.php" class="btn btn-light"><?= cv_icon('arrow-left') ?> Back to Dashboard</a>
                </div>
            </div>
        </header>

        <div class="card bulk-progress">
            <ol class="stepper" aria-label="Bulk issuance progress">
                <li class="<?= $bulk_step > 1 ? 'is-done' : 'is-current' ?>"<?= $bulk_step === 1 ? ' aria-current="step"' : '' ?>>Upload CSV</li>
                <li class="<?= $bulk_step > 2 ? 'is-done' : ($bulk_step === 2 ? 'is-current' : '') ?>"<?= $bulk_step === 2 ? ' aria-current="step"' : '' ?>>Review preview</li>
                <li class="<?= $bulk_step === 3 ? 'is-current' : '' ?>"<?= $bulk_step === 3 ? ' aria-current="step"' : '' ?>>Issued</li>
            </ol>
        </div>

        <?php if ($error): ?><div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div><?php endif; ?>

        <?php if ($results !== null): ?>
            <div class="mini-stats" aria-label="Batch summary">
                <div class="mini-stat mini-stat-valid" data-reveal data-reveal-delay="1"><span class="mini-stat-num" data-count-to="<?= (int)($counts['issued'] ?? 0) ?>"><?= (int)($counts['issued'] ?? 0) ?></span><span class="mini-stat-label">Issued</span></div>
                <div class="mini-stat mini-stat-warn" data-reveal data-reveal-delay="2"><span class="mini-stat-num"><?= (int)($counts['pending_activation'] ?? 0) ?></span><span class="mini-stat-label">Pending activation</span></div>
                <div class="mini-stat mini-stat-info" data-reveal data-reveal-delay="3"><span class="mini-stat-num"><?= (int)($counts['skipped'] ?? 0) ?></span><span class="mini-stat-label">Skipped</span></div>
                <div class="mini-stat mini-stat-danger" data-reveal data-reveal-delay="4"><span class="mini-stat-num"><?= (int)($counts['error'] ?? 0) ?></span><span class="mini-stat-label">Errors</span></div>
            </div>
            <div class="alert alert-success" id="bulkSummary" role="status">
                Issued <?= (int)($counts['issued'] ?? 0) ?> ·
                pending activation <?= (int)($counts['pending_activation'] ?? 0) ?> ·
                skipped <?= (int)($counts['skipped'] ?? 0) ?> ·
                errors <?= (int)($counts['error'] ?? 0) ?>
            </div>
            <section class="card data-card" aria-labelledby="resultsTitle">
                <div class="card-head">
                    <div class="card-head-text">
                        <h2 id="resultsTitle">Batch results</h2>
                        <p>Keep the results CSV — it lists every certificate ID and verification link.</p>
                    </div>
                    <div class="cluster">
                        <a class="btn btn-primary btn-sm" href="bulk_issue.php?download=results"><?= cv_icon('download') ?> Download results (CSV)</a>
                        <a class="btn btn-secondary btn-sm" href="bulk_issue.php"><?= cv_icon('plus') ?> Issue another batch</a>
                    </div>
                </div>
                <div class="table-wrap">
                    <table class="data-table table admin-table" id="bulkResults">
                        <thead><tr><th scope="col">Row</th><th scope="col">Student</th><th scope="col">Title</th><th scope="col">Status</th><th scope="col">Certificate / message</th></tr></thead>
                        <tbody>
                        <?php foreach ($results as $r): ?>
                            <tr data-status="<?= htmlspecialchars($r['status']) ?>">
                                <td data-label="Row"><?= (int)$r['line'] ?></td>
                                <td data-label="Student" class="wrap-anywhere"><?= htmlspecialchars($r['student_email']) ?></td>
                                <td data-label="Title"><?= htmlspecialchars($r['title']) ?></td>
                                <td data-label="Status"><span class="badge-status badge-<?= htmlspecialchars(cv_status_badge($r['status'])) ?>"><?= htmlspecialchars(str_replace('_', ' ', $r['status'])) ?></span></td>
                                <td data-label="Certificate / message">
                                    <?php if ($r['status'] === 'issued'): ?>
                                        <a href="verify.php?certificate_id=<?= rawurlencode($r['certificate_id']) ?>" class="id-chip"><?= htmlspecialchars($r['certificate_id']) ?></a>
                                    <?php else: ?>
                                        <span class="cell-sub"><?= htmlspecialchars($r['message'] ?? '') ?></span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </section>

        <?php elseif ($preview !== null): ?>
            <div class="mini-stats" aria-label="Preview summary">
                <div class="mini-stat mini-stat-brand" data-reveal data-reveal-delay="1"><span class="mini-stat-num"><?= count($preview) ?></span><span class="mini-stat-label">Rows read</span></div>
                <div class="mini-stat mini-stat-valid" data-reveal data-reveal-delay="2"><span class="mini-stat-num"><?= $validCount ?></span><span class="mini-stat-label">Ready to issue</span></div>
                <div class="mini-stat mini-stat-danger" data-reveal data-reveal-delay="3"><span class="mini-stat-num"><?= count($preview) - $validCount ?></span><span class="mini-stat-label">With problems (skipped)</span></div>
            </div>
            <section class="card data-card" aria-labelledby="previewTitle">
                <div class="card-head">
                    <div class="card-head-text">
                        <h2 id="previewTitle">Preview</h2>
                        <p><?= count($preview) ?> row(s) read — <strong><?= $validCount ?></strong> ready to issue,
                           <?= count($preview) - $validCount ?> with problems (they will be skipped). Nothing has been issued yet.</p>
                    </div>
                </div>
                <div class="table-wrap">
                    <table class="data-table table admin-table" id="bulkPreview">
                        <thead><tr><th scope="col">Row</th><th scope="col">Student</th><th scope="col">Title</th><th scope="col">Issue / expiry</th><th scope="col">Check</th></tr></thead>
                        <tbody>
                        <?php foreach ($preview as $r): ?>
                            <tr data-ok="<?= $r['errors'] ? '0' : '1' ?>">
                                <td data-label="Row"><?= (int)$r['line'] ?></td>
                                <td data-label="Student">
                                    <span class="cell-main">
                                        <span class="avatar avatar-<?= cv_avatar_hue($r['student_name']) ?>" aria-hidden="true"><?= htmlspecialchars(cv_initials($r['student_name'])) ?></span>
                                        <span class="cell-stack"><span class="cell-title"><?= htmlspecialchars($r['student_name']) ?></span><span class="cell-sub wrap-anywhere"><?= htmlspecialchars($r['student_email']) ?></span></span>
                                    </span>
                                </td>
                                <td data-label="Title"><span class="cell-stack"><span class="cell-title"><?= htmlspecialchars($r['title']) ?></span><?= $r['certificate_id'] !== '' ? '<span class="id-chip">' . htmlspecialchars($r['certificate_id']) . '</span>' : '' ?></span></td>
                                <td data-label="Issue / expiry" class="nowrap"><?= htmlspecialchars($r['issue_date']) ?><?= $r['expiry_date'] !== '' ? ' → ' . htmlspecialchars($r['expiry_date']) : '' ?></td>
                                <td data-label="Check">
                                    <?php if ($r['errors']): ?>
                                        <span class="check-cell"><span class="badge-status badge-rejected">problem</span><small><?= htmlspecialchars(implode(' ', $r['errors'])) ?></small></span>
                                    <?php else: ?>
                                        <span class="badge-status badge-valid">ready</span>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            </section>
            <div class="card confirm-bar">
                <?php if ($validCount > 0): ?>
                    <p><strong><?= $validCount ?> certificate(s)</strong> will be generated as PDFs, signed and emailed.</p>
                    <form method="POST" data-confirm="Issue <?= $validCount ?> signed certificate(s) now?" data-loading>
                        <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                        <input type="hidden" name="action" value="issue">
                        <input type="hidden" name="batch_id" value="<?= htmlspecialchars($_SESSION['bulk_batch']['id']) ?>">
                        <button type="submit" class="btn btn-primary"><?= cv_icon('award') ?> Issue <?= $validCount ?> certificate(s)</button>
                        <a class="btn btn-secondary" href="bulk_issue.php">Cancel</a>
                    </form>
                <?php else: ?>
                    <p>No row is ready to issue. Fix the problems in your file and upload it again.</p>
                    <a class="btn btn-primary" href="bulk_issue.php"><?= cv_icon('upload') ?> Upload again</a>
                <?php endif; ?>
            </div>

        <?php else: ?>
            <div class="bulk-layout">
                <section class="card form-card" aria-labelledby="uploadTitle">
                    <div class="card-head">
                        <div class="card-head-text">
                            <h2 id="uploadTitle">Upload your CSV</h2>
                            <p>CertiVault generates each certificate as a PDF with its QR code, signs it with your institution's key and issues it — exactly like a single issuance.</p>
                        </div>
                    </div>
                    <form method="POST" enctype="multipart/form-data" id="bulkForm" data-loading>
                        <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                        <input type="hidden" name="action" value="preview">
                        <div class="form-group">
                            <label for="csv">CSV file</label>
                            <div class="upload-zone">
                                <span class="upload-zone-icon" aria-hidden="true"><?= cv_icon('file') ?></span>
                                <span class="upload-zone-title" aria-hidden="true">Drag &amp; drop your CSV here, or <span class="link-like">browse</span></span>
                                <span class="upload-zone-hint" aria-hidden="true">.csv · up to <?= BulkIssueService::MAX_ROWS ?> rows and 1 MB</span>
                                <small class="file-name-display" id="csvFileName" aria-live="polite"></small>
                                <input type="file" id="csv" name="csv" accept=".csv,text/csv" data-filename-target="csvFileName" required>
                            </div>
                        </div>
                        <div class="form-actions">
                            <p class="form-actions-note"><?= cv_icon('eye') ?> You will see a preview before anything is issued.</p>
                            <button type="submit" class="btn btn-primary"><?= cv_icon('arrow-right') ?> Preview</button>
                        </div>
                    </form>
                </section>

                <aside class="card" aria-labelledby="formatTitle">
                    <h2 id="formatTitle" class="aside-title">CSV format</h2>
                    <p class="text-sm text-muted mb-1">Required columns</p>
                    <div class="col-list">
                        <code class="col-chip">student_email</code><code class="col-chip">student_name</code><code class="col-chip">title</code><code class="col-chip">issue_date</code>
                    </div>
                    <p class="text-sm text-muted mb-1">Optional columns</p>
                    <div class="col-list">
                        <code class="col-chip col-chip-optional">expiry_date</code><code class="col-chip col-chip-optional">certificate_id</code>
                    </div>
                    <ul class="tips-list">
                        <li><?= cv_icon('calendar') ?><span>Dates use <code>YYYY-MM-DD</code>. A blank <code>certificate_id</code> becomes an automatic CV-YYYY-NNNNNN.</span></li>
                        <li><?= cv_icon('layers') ?><span>At most <?= BulkIssueService::MAX_ROWS ?> rows and 1 MB. You will see a preview before anything is issued.</span></li>
                        <li><?= cv_icon('mail') ?><span>Students without an activated account get an activation email and are listed as pending.</span></li>
                    </ul>
                    <a class="btn btn-secondary btn-block mt-4" href="bulk_issue.php?download=template"><?= cv_icon('download') ?> Download the CSV template</a>
                </aside>
            </div>
        <?php endif; ?>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/admin-ui.js" defer></script>
</body>
</html>
