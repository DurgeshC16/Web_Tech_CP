<?php
// tests/test_bulk_issuance.php
// IssuanceService (shared by single + bulk issuance), CertificatePdfService
// (generated certificate PDFs) and BulkIssueService (CSV parsing/export).

require_once __DIR__ . '/bootstrap.php';
define('MAIL_TRANSPORT', 'file');
define('MAIL_FILE_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cv_bulk_mail_' . getmypid());
require_once __DIR__ . '/../src/services/IssuanceService.php';
require_once __DIR__ . '/../src/services/CertificatePdfService.php';
require_once __DIR__ . '/../src/services/BulkIssueService.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/CredentialService.php';
require_once __DIR__ . '/../src/services/FileVerifyService.php';

$db = test_db();
$tag = bin2hex(random_bytes(4));
$uploads = __DIR__ . '/../private_data/uploads/';
$qrDir = __DIR__ . '/../public/qrcodes/';
$filesBefore = array_merge(glob($uploads . '*') ?: [], glob($qrDir . '*') ?: []);
$created = [];

// ── Fixture: approved institution with a key, one verified student ─────
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "admin", 1)')->execute(['e' => "bulk-admin-$tag@example.com"]);
$adminUid = (int)$db->lastInsertId();
$db->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:u, :n, "approved")')->execute(['u' => $adminUid, 'n' => "Bulk Uni $tag"]);
$instId = (int)$db->lastInsertId();
$keys = CryptoService::generateRSAKeyPair();
test_insert_institution_key($db, $instId, $keys['public_key'], CryptoService::encryptPrivateKey($keys['private_key']));
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "student", 1)')->execute(['e' => "bulk-stu-$tag@example.com"]);
$stuUid = (int)$db->lastInsertId();
$db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "Bulk Student")')->execute(['u' => $stuUid]);

try {
    // ── resolveStudent ────────────────────────────────────────────────
    $r = IssuanceService::resolveStudent($db, "bulk-stu-$tag@example.com", 'Bulk Student');
    t_check('verified student resolves', $r['status'] === 'ok' && $r['student_id'] > 0);
    $sid = $r['student_id'];
    $p = IssuanceService::resolveStudent($db, "bulk-new-$tag@example.com", 'New Person');
    t_check('unknown student -> pending activation (account created, code sent)', $p['status'] === 'pending_activation' && str_contains($p['message'], 'activation code was sent'));
    $created[] = $p['user_id'];
    $spool = glob(MAIL_FILE_DIR . DIRECTORY_SEPARATOR . '*.eml') ?: [];
    t_check('activation email written to the dev spool', count($spool) === 1);
    $p2 = IssuanceService::resolveStudent($db, "bulk-new-$tag@example.com", 'New Person');
    t_check('same pending student again -> still pending (no duplicate account)', $p2['status'] === 'pending_activation' && $p2['user_id'] === $p['user_id']);

    // ── Issue with a generated PDF ────────────────────────────────────
    t_check('dompdf available for certificate PDFs', CertificatePdfService::available());
    $render = function ($certId, $qrToken, $verifyUrl, $qrPath, $destination) use ($tag) {
        file_put_contents($destination, CertificatePdfService::render([
            'institution' => "Bulk Uni $tag", 'student' => 'Bulk Stüdent', 'title' => 'Données Avancées',
            'certificate_id' => $certId, 'issue_date' => '2025-06-01', 'expiry_date' => '2099-06-01', 'verify_url' => $verifyUrl,
        ], $qrPath));
    };
    $issued = IssuanceService::issue($db, $instId, $sid, ['title' => 'Données Avancées', 'issue_date' => '2025-06-01', 'expiry_date' => '2099-06-01', 'custom_id' => ''], 'pdf', $render);
    $cert = VerificationService::findByCertificateId($db, $issued['certificate_id']);
    t_check('generated certificate issued with auto CV-YYYY-NNNNNN id', (bool)preg_match('/^CV-\d{4}-\d{6}$/', $issued['certificate_id']));
    $path = $uploads . $cert['file_path'];
    t_check('stored file is a real PDF', strncmp((string)file_get_contents($path, false, null, 0, 4), '%PDF', 4) === 0 && filesize($path) > 2000);
    t_check('file_sha256 stored = hash of the generated PDF', $cert['file_sha256'] === hash_file('sha256', $path));
    t_check('generated certificate verifies VALID', VerificationService::verify($db, $cert)['verdict'] === 'VALID');
    t_check('QR image written', is_file($qrDir . $issued['qr_token'] . '.png'));
    t_check('exact upload of the generated PDF resolves (byte hash)', (FileVerifyService::findLocalByContentHash($db, hash_file('sha256', $path))[0]['certificate_id'] ?? '') === $issued['certificate_id']);
    $cred = CredentialService::build($db, $cert);
    t_check('credential of a generated certificate verifies offline', $cred !== null && CredentialService::verifyOffline($cred)['valid'] === true);
    if (FileVerifyService::pdfParserAvailable()) {
        $copy = tempnam(sys_get_temp_dir(), 'cvbulk');
        file_put_contents($copy, file_get_contents($path) . "\n% re-saved copy\n"); // different bytes, same text
        $out = FileVerifyService::pipelineFromTemp($db, $copy, 'application/pdf');
        t_check('altered copy still resolves via the text in the generated PDF', ($out['__cert']['certificate_id'] ?? '') === $issued['certificate_id']);
        @unlink($copy);
    } else {
        t_check('pdfparser unavailable: text-stage check skipped', true);
    }

    // ── Custom ID + duplicate rejection ───────────────────────────────
    $customId = "BULK/$tag/1";
    $c1 = IssuanceService::issue($db, $instId, $sid, ['title' => 'Custom ID Course', 'issue_date' => '2025-06-01', 'expiry_date' => '', 'custom_id' => $customId], 'pdf', $render);
    t_check('custom certificate id stored verbatim', $c1['certificate_id'] === $customId);
    $dupThrown = false;
    try {
        IssuanceService::issue($db, $instId, $sid, ['title' => 'Dup', 'issue_date' => '2025-06-01', 'expiry_date' => '', 'custom_id' => strtolower($customId)], 'pdf', $render);
    } catch (Throwable $e) {
        $dupThrown = true;
    }
    t_check('case-variant duplicate custom id rejected', $dupThrown);

    // ── Failure inside the pipeline rolls everything back ─────────────
    $countBefore = (int)$db->query('SELECT COUNT(*) FROM certificates WHERE institution_id = ' . $instId)->fetchColumn();
    $filesNow = array_merge(glob($uploads . '*') ?: [], glob($qrDir . '*') ?: []);
    $failed = false;
    try {
        IssuanceService::issue($db, $instId, $sid, ['title' => 'Will Fail', 'issue_date' => '2025-06-01', 'expiry_date' => '', 'custom_id' => ''], 'pdf',
            function ($certId, $qrToken, $verifyUrl, $qrPath, $destination) {
                file_put_contents($destination, 'partial');
                throw new RuntimeException('renderer exploded');
            });
    } catch (RuntimeException $e) {
        $failed = $e->getMessage() === 'renderer exploded';
    }
    t_check('renderer failure propagates', $failed);
    t_check('…no certificate row was written', (int)$db->query('SELECT COUNT(*) FROM certificates WHERE institution_id = ' . $instId)->fetchColumn() === $countBefore);
    t_check('…and no file or QR image was left behind', array_diff(array_merge(glob($uploads . '*') ?: [], glob($qrDir . '*') ?: []), $filesNow) === []);

    // ── CSV parsing ───────────────────────────────────────────────────
    $csv = function (string $content, string $name = 'batch.csv') use ($db) {
        $f = tempnam(sys_get_temp_dir(), 'cvcsv');
        file_put_contents($f, $content);
        $r = BulkIssueService::parseCsv($db, $f, $name, filesize($f));
        @unlink($f);
        return $r;
    };
    [$rows, $fatal] = $csv("\xEF\xBB\xBFStudent_Email,student_name,title,issue_date,expiry_date,certificate_id\n"
        . "a@example.com,Asha Verma,Web Technology,2025-01-10,,\n"
        . "\n"
        . "not-an-email,Bob,Course,2025-01-10,,\n"
        . "c@example.com,Chen Li,Course,2025-01-10,2024-01-01,\n"
        . "d@example.com,Dee,Course,2025-01-10,,DUP-1\n"
        . "e@example.com,Eve,Course,2025-01-10,,dup-1\n"
        . "f@example.com,Fay,\"Course, with comma\",2025-01-10,,\n");
    t_check('CSV: BOM + header case handled, blank line skipped', $fatal === null && count($rows) === 6);
    $ok = array_values(array_filter($rows, fn($r) => !$r['errors']));
    t_check('CSV: valid rows recognised (incl. quoted comma)', count($ok) === 3 && $ok[2]['title'] === 'Course, with comma');
    t_check('CSV: invalid email flagged', !empty($rows[1]['errors']));
    t_check('CSV: expiry before issue flagged', !empty($rows[2]['errors']));
    t_check('CSV: duplicate certificate id within the file flagged', str_contains(implode(' ', $rows[4]['errors']), 'repeats row'));
    t_check('CSV: line numbers refer to the file', $rows[1]['line'] === 4);
    [, $fatal] = $csv("email,name\nx@example.com,X\n");
    t_check('CSV: missing required columns -> clear error', str_contains((string)$fatal, 'Missing column(s)'));
    [, $fatal] = $csv("student_email,student_name,title,issue_date\n", 'batch.csv');
    t_check('CSV: header only -> no data rows', str_contains((string)$fatal, 'no data rows'));
    [, $fatal] = $csv("student_email,student_name,title,issue_date\nx@example.com,X Y,T T T,2025-01-01\n", 'batch.xlsx');
    t_check('CSV: wrong extension rejected', str_contains((string)$fatal, '.csv'));
    [, $fatal] = $csv("%PDF-1.4\n" . random_bytes(300), 'batch.csv');
    t_check('CSV: non-text content rejected', $fatal !== null);
    $many = "student_email,student_name,title,issue_date\n" . str_repeat("x@example.com,Xavier,Some Course,2025-01-01\n", BulkIssueService::MAX_ROWS + 1);
    [, $fatal] = $csv($many);
    t_check('CSV: more than MAX_ROWS rejected', str_contains((string)$fatal, 'Too many rows'));
    t_check('CSV export: formula injection neutralised', BulkIssueService::csvCell('=HYPERLINK("x")') === "'=HYPERLINK(\"x\")"
        && BulkIssueService::csvCell('+1') === "'+1" && BulkIssueService::csvCell('normal') === 'normal');
} finally {
    $ids = $db->query('SELECT id, file_path, qr_token FROM certificates WHERE institution_id = ' . $instId)->fetchAll();
    foreach ($ids as $c) {
        @unlink($uploads . $c['file_path']);
        @unlink($qrDir . $c['qr_token'] . '.png');
    }
    $db->exec('DELETE FROM tlog_entries WHERE certificate_id IN (SELECT certificate_id FROM certificates WHERE institution_id = ' . $instId . ')');
    $db->exec('DELETE FROM certificates WHERE institution_id = ' . $instId);
    $db->exec('DELETE FROM institution_keys WHERE institution_id = ' . $instId);
    $db->exec('DELETE FROM institutions WHERE id = ' . $instId);
    $db->prepare('DELETE FROM students WHERE user_id = :u')->execute(['u' => $stuUid]);
    foreach (array_merge([$adminUid, $stuUid], $created) as $u) {
        $db->prepare('DELETE FROM otp_codes WHERE user_id = :u')->execute(['u' => $u]);
        $db->prepare('DELETE FROM students WHERE user_id = :u')->execute(['u' => $u]);
        $db->prepare('DELETE FROM users WHERE id = :u')->execute(['u' => $u]);
    }
    array_map('unlink', glob(MAIL_FILE_DIR . DIRECTORY_SEPARATOR . '*') ?: []);
    @rmdir(MAIL_FILE_DIR);
}
$leftover = array_diff(array_merge(glob($uploads . '*') ?: [], glob($qrDir . '*') ?: []), $filesBefore);
t_check('cleanup: no files left behind by this suite', $leftover === []);

exit(t_summary('test_bulk_issuance') ? 0 : 1);
