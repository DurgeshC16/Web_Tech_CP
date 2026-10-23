<?php
// public/report.php
// ─────────────────────────────────────────────────────────────────────
// Phase 2 — "Download verification report" endpoint. Streams a dompdf
// PDF containing ONLY the public verify-page facts (verdict, trust
// score + checks, certificate fields, live-verify QR). No tokens,
// private keys, internal file paths or anything not already public.
//
// Rate limited: max 5 report downloads per IP / 10 minutes (verified
// against verification_logs). Every generated report is itself logged
// with a 'verification report' detail marker.
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/TrustScoreService.php';
require_once __DIR__ . '/../src/services/ReportService.php';
require_once __DIR__ . '/../src/utils/helpers.php';

send_security_headers();
send_no_store_headers();

$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
try {
    $db = Database::getInstance();
} catch (Throwable $dbError) {
    error_log("[CertiVault] report.php DB connect failed: " . $dbError->getMessage());
    http_response_code(503);
    die('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Service Unavailable</title></head><body style="font-family:sans-serif;text-align:center;margin-top:60px;"><h2>Database unavailable</h2><p><a href="verify.php">Back to Verification</a></p></body></html>');
}

try {
    $rateStmt = $db->prepare('
        SELECT COUNT(*) FROM verification_logs
        WHERE verifier_ip = :ip
          AND detail LIKE "verification report%"
          AND verified_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
    ');
    $rateStmt->execute(['ip' => $ip]);
    if ((int)$rateStmt->fetchColumn() >= 5) {
        error_log("[CertiVault] Report rate limit exceeded for IP $ip on report.php — returned 429.");
        http_response_code(429);
        die('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Too Many Requests</title></head><body style="font-family:sans-serif;text-align:center;margin-top:60px;"><h2>429 — Too Many Requests</h2><p>Too many report downloads. Please wait a few minutes.</p><p><a href="verify.php">Back to Verification</a></p></body></html>');
    }
} catch (Throwable $rateError) {
    error_log("[CertiVault] Report rate-limit check failed (report.php): " . $rateError->getMessage());
    // Fail closed: obstacle to abuse must not be skipped silently.
    http_response_code(429);
    die('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Too Many Requests</title></head><body style="font-family:sans-serif;text-align:center;margin-top:60px;"><h2>429 — Too Many Requests</h2><p>Report service is temporarily unavailable.</p></body></html>');
}

$certParam = trim((string)($_GET['cert'] ?? $_GET['certificate_id'] ?? ''));
if ($certParam === '' || mb_strlen($certParam) > 64
    || !preg_match('/^[A-Za-z0-9\-_\/. ]+$/', $certParam)) {
    http_response_code(400);
    die('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Not Found</title></head><body style="font-family:sans-serif;text-align:center;margin-top:60px;"><h2>400 — Missing certificate identifier</h2><p><a href="verify.php">Verify a certificate first</a>, then download its report.</p></body></html>');
}

try {
    $cert = VerificationService::findByFlexibleCertificateId($db, $certParam);
} catch (Throwable $dbError) {
    error_log("[CertiVault] report.php lookup failed: " . $dbError->getMessage());
    $cert = null;
}

if (!$cert) {
    http_response_code(404);
    die('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Not Found</title></head><body style="font-family:sans-serif;text-align:center;margin-top:60px;"><h2>404 — Certificate not found</h2><p><a href="verify.php">Back to Verification</a></p></body></html>');
}

try {
    $result = VerificationService::verify($db, $cert);
} catch (Throwable $verifyError) {
    error_log("[CertiVault] report.php verify failed: " . $verifyError->getMessage());
    http_response_code(500);
    die('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Error</title></head><body style="font-family:sans-serif;text-align:center;margin-top:60px;"><h2>500 — Verification engine error</h2><p><a href="verify.php">Back to Verification</a></p></body></html>');
}

// Pass 1: fetch verdict + score + certificate facts.
$verdict       = $result['verdict'];
$detail        = $result['detail'];
$superseded_by = $result['superseded_by'];
try {
    $trusted = TrustScoreService::compute($db, $cert);
} catch (Throwable $scoreError) {
    error_log("[CertiVault] report.php trust score failed: " . $scoreError->getMessage());
    $trusted = ['score' => null, 'verdict' => $verdict, 'checks' => []];
}

// Audit log marker so rate limiting can find this IP's report downloads.
try {
    $logStmt = $db->prepare('
        INSERT INTO verification_logs
            (query_type, query_value, certificate_id_found, result, detail, verifier_ip)
        VALUES
            ("certificate_id", :qv, :cid, :res, :det, :ip)
    ');
    $logStmt->execute([
        'qv'  => mb_substr(log_safe_text('(report download OK)'), 0, 255),
        'cid' => $cert['certificate_id'],
        'res' => $verdict,
        'det' => 'verification report download',
        'ip'  => $ip,
    ]);
} catch (Throwable $logError) {
    error_log("[CertiVault] report.php audit log failed: " . $logError->getMessage());
}

$pdf = ReportService::buildReportPdf($cert, $detail, $trusted, $superseded_by ?: null);

if ($pdf === '' || strncmp($pdf, '%PDF', 4) !== 0) {
    // PDF engine not available (dompdf missing/failed): degrade to a page
    // with the same public facts instead of serving garbage.
    http_response_code(503);
    $e = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Verification Report</title></head><body style="font-family:sans-serif;max-width:600px;margin:40px auto;">';
    echo '<h2>CertiVault — Verification Report</h2>';
    echo '<p><strong>Verdict:</strong> ' . $e($trusted['verdict'] ?? $verdict) . '</p>';
    echo '<p><strong>Trust score:</strong> ' . ($trusted['score'] === null ? 'n/a' : (int)$trusted['score'] . ' / 100') . '</p>';
    echo '<ul>';
    foreach (($trusted['checks'] ?? []) as $c) {
        echo '<li>' . ($c['pass'] ? '&#10003;' : '&#10007;') . ' ' . $e($c['label']) . '</li>';
    }
    echo '</ul><p>' . $e(TrustScoreService::DISCLAIMER) . '</p>';
    echo '<p><a href="verify.php">Back to Verification</a></p></body></html>';
    exit;
}

header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="certivault-report-' . preg_replace('/[^A-Za-z0-9]+/', '-', (string)$cert['certificate_id']) . '.pdf"');
header('Content-Length: ' . strlen($pdf));
header('Cache-Control: no-store');
echo $pdf;
exit;
