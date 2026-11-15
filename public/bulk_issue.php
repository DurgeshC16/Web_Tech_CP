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
$page_title = 'Bulk Issue - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main">
    <div class="container shell-wide">
        <div class="page-head">
            <h2>Bulk issue from CSV</h2>
            <a href="admin_dashboard.php" class="btn btn-secondary">Back to Dashboard</a>
        </div>

        <?php if ($error): ?><div class="alert alert-danger"><?= htmlspecialchars($error) ?></div><?php endif; ?>

        <?php if ($results !== null): ?>
            <div class="alert alert-success" id="bulkSummary">
                Issued <?= (int)($counts['issued'] ?? 0) ?> ·
                pending activation <?= (int)($counts['pending_activation'] ?? 0) ?> ·
                skipped <?= (int)($counts['skipped'] ?? 0) ?> ·
                errors <?= (int)($counts['error'] ?? 0) ?>
            </div>
            <p><a class="btn btn-secondary" href="bulk_issue.php?download=results">⬇ Download results (CSV)</a>
               <a class="btn btn-secondary" href="bulk_issue.php">Issue another batch</a></p>
            <div class="table-wrap">
                <table class="data-table" id="bulkResults">
                    <thead><tr><th>Row</th><th>Student</th><th>Title</th><th>Status</th><th>Certificate / message</th></tr></thead>
                    <tbody>
                    <?php foreach ($results as $r): ?>
                        <tr data-status="<?= htmlspecialchars($r['status']) ?>">
                            <td data-label="Row"><?= (int)$r['line'] ?></td>
                            <td data-label="Student"><?= htmlspecialchars($r['student_email']) ?></td>
                            <td data-label="Title"><?= htmlspecialchars($r['title']) ?></td>
                            <td data-label="Status"><?= htmlspecialchars(str_replace('_', ' ', $r['status'])) ?></td>
                            <td data-label="Certificate / message">
                                <?php if ($r['status'] === 'issued'): ?>
                                    <a href="verify.php?certificate_id=<?= rawurlencode($r['certificate_id']) ?>"><?= htmlspecialchars($r['certificate_id']) ?></a>
                                <?php else: ?>
                                    <?= htmlspecialchars($r['message'] ?? '') ?>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

        <?php elseif ($preview !== null): ?>
            <p><?= count($preview) ?> row(s) read — <strong><?= $validCount ?></strong> ready to issue,
               <?= count($preview) - $validCount ?> with problems (they will be skipped). Nothing has been issued yet.</p>
            <div class="table-wrap">
                <table class="data-table" id="bulkPreview">
                    <thead><tr><th>Row</th><th>Student</th><th>Title</th><th>Issue / expiry</th><th>Check</th></tr></thead>
                    <tbody>
                    <?php foreach ($preview as $r): ?>
                        <tr data-ok="<?= $r['errors'] ? '0' : '1' ?>">
                            <td data-label="Row"><?= (int)$r['line'] ?></td>
                            <td data-label="Student"><?= htmlspecialchars($r['student_name']) ?><br><small><?= htmlspecialchars($r['student_email']) ?></small></td>
                            <td data-label="Title"><?= htmlspecialchars($r['title']) ?><?= $r['certificate_id'] !== '' ? '<br><small>' . htmlspecialchars($r['certificate_id']) . '</small>' : '' ?></td>
                            <td data-label="Issue / expiry"><?= htmlspecialchars($r['issue_date']) ?><?= $r['expiry_date'] !== '' ? ' → ' . htmlspecialchars($r['expiry_date']) : '' ?></td>
                            <td data-label="Check"><?= $r['errors'] ? '✗ ' . htmlspecialchars(implode(' ', $r['errors'])) : '✓ ready' ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php if ($validCount > 0): ?>
                <form method="POST" data-confirm="Issue <?= $validCount ?> signed certificate(s) now?">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                    <input type="hidden" name="action" value="issue">
                    <input type="hidden" name="batch_id" value="<?= htmlspecialchars($_SESSION['bulk_batch']['id']) ?>">
                    <button type="submit" class="btn btn-primary">Issue <?= $validCount ?> certificate(s)</button>
                    <a class="btn btn-secondary" href="bulk_issue.php">Cancel</a>
                </form>
            <?php endif; ?>

        <?php else: ?>
            <div class="card">
                <p>Upload a CSV with one certificate per row. CertiVault generates each certificate as a PDF with its
                   QR code, signs it with your institution's key and issues it — exactly like a single issuance.</p>
                <ul>
                    <li>Required columns: <code>student_email</code>, <code>student_name</code>, <code>title</code>, <code>issue_date</code> (YYYY-MM-DD)</li>
                    <li>Optional: <code>expiry_date</code>, <code>certificate_id</code> (blank = automatic CV-YYYY-NNNNNN)</li>
                    <li>At most <?= BulkIssueService::MAX_ROWS ?> rows and 1 MB. You will see a preview before anything is issued.</li>
                    <li>Students without an activated account get an activation email and are listed as pending.</li>
                </ul>
                <p><a class="btn btn-secondary" href="bulk_issue.php?download=template">⬇ Download the CSV template</a></p>
                <form method="POST" enctype="multipart/form-data" id="bulkForm">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                    <input type="hidden" name="action" value="preview">
                    <div class="form-group">
                        <label for="csv">CSV file</label>
                        <input type="file" id="csv" name="csv" accept=".csv,text/csv" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Preview</button>
                </form>
            </div>
        <?php endif; ?>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
