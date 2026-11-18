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
require_once __DIR__ . '/../src/services/GuestQuotaService.php';
require_once __DIR__ . '/../src/utils/helpers.php';

/**
 * HTML page for the error / fallback exits below, wrapped in the shared
 * head/header/footer partials. Presentation only: design system classes, no
 * inline styles. $bodyHtml must already be escaped by the caller.
 */
function report_page(string $title, string $heading, string $bodyHtml, string $tone = 'warn'): string {
    $e = static fn($v) => htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
    $theme = function_exists('current_theme') ? current_theme() : 'light';
    $icon = $tone === 'danger'
        ? '<path d="M12 8v5M12 17h.01"/><path d="M10.3 3.9 2.6 17.4A2 2 0 0 0 4.3 20.4h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>'
        : ($tone === 'info'
            ? '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/>'
            : '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>');
    $card = '<main id="main"><div class="container verify-shell sv-notice-page"><div class="sv-body text-center">'
        . '<span class="sv-notice-icon sv-tone-' . $e($tone) . '" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false">' . $icon . '</svg></span>'
        . '<h1 class="sv-notice-title">' . $e($heading) . '</h1>' . $bodyHtml
        . '</div></div></main>';
    // Same chrome as every other page (head, header, footer). Falls back to a
    // bare stylesheet-only page if a partial cannot render.
    try {
        ob_start();
        $page_title = $title . ' - CertiVault';
        require __DIR__ . '/../src/partials/head.php';
        require __DIR__ . '/../src/partials/header.php';
        echo $card;
        require __DIR__ . '/../src/partials/footer.php';
        echo "\n</body>\n</html>";
        return (string)ob_get_clean();
    } catch (Throwable $chromeError) {
        ob_end_clean();
        error_log('[CertiVault] report.php page chrome failed: ' . $chromeError->getMessage());
    }
    return '<!DOCTYPE html><html lang="en" data-theme="' . $e($theme) . '"><head><meta charset="UTF-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>' . $e($title) . '</title>'
        . '<link rel="stylesheet" href="assets/css/style.css"><link rel="stylesheet" href="assets/css/components.css">'
        . '<link rel="stylesheet" href="assets/css/features.css"><link rel="stylesheet" href="assets/css/pages/verify.css"></head>'
        . '<body class="page-report">' . $card . '</body></html>';
}

send_security_headers();
send_no_store_headers();

$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
try {
    $db = Database::getInstance();
} catch (Throwable $dbError) {
    error_log("[CertiVault] report.php DB connect failed: " . $dbError->getMessage());
    http_response_code(503);
    die(report_page('Service Unavailable', 'Database unavailable', '<p class="sv-notice-text"><a class="btn btn-primary" href="verify.php">Back to Verification</a></p>', 'danger'));
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
        die(report_page('Too Many Requests', '429 — Too Many Requests', '<p class="sv-notice-text">Too many report downloads. Please wait a few minutes.</p><p><a class="btn btn-primary" href="verify.php">Back to Verification</a></p>'));
    }
} catch (Throwable $rateError) {
    error_log("[CertiVault] Report rate-limit check failed (report.php): " . $rateError->getMessage());
    // Fail closed: obstacle to abuse must not be skipped silently.
    http_response_code(429);
    die(report_page('Too Many Requests', '429 — Too Many Requests', '<p class="sv-notice-text">Report service is temporarily unavailable.</p>'));
}

$certParam = trim((string)($_GET['cert'] ?? $_GET['certificate_id'] ?? ''));
if ($certParam === '' || mb_strlen($certParam) > 64
    || !preg_match('/^[A-Za-z0-9\-_\/. ]+$/', $certParam)) {
    http_response_code(400);
    die(report_page('Not Found', '400 — Missing certificate identifier', '<p class="sv-notice-text"><a href="verify.php">Verify a certificate first</a>, then download its report.</p>', 'info'));
}

// ── Guest verification quota (GuestQuotaService) ─────────────────────
// A report is a verification too, but NOT a second one for a certificate
// the guest has just verified on verify.php: that page records a free
// "cert:<id>" alias, so the report link (which carries the canonical ID)
// is a repeat and costs nothing. A report for a certificate the guest
// never verified costs one credit. Exhausted guests get the login/register
// page and no lookup runs. Logged-in users are never counted.
$gq_keys = [GuestQuotaService::certAlias($certParam), 'id:' . mb_strtolower($certParam)];
$gq = GuestQuotaService::check($db, $ip, $_SESSION, $gq_keys);
if (!$gq['allowed']) {
    GuestQuotaService::sendLimitHeaders($gq);
    $page_title = 'Free verification limit reached - CertiVault';
    require __DIR__ . '/../src/partials/head.php';
    require __DIR__ . '/../src/partials/header.php';
    echo '<main id="main"><div class="container verify-shell sv-limit-shell"><div class="sv-body"><div class="sv-limit">'
        . '<span class="sv-limit-badge" aria-hidden="true"><svg class="sv-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg></span>'
        . GuestQuotaService::renderLimitNotice($gq) . '</div></div></div></main>';
    require __DIR__ . '/../src/partials/footer.php';
    echo '</body></html>';
    exit;
}

try {
    $cert = VerificationService::findByFlexibleCertificateId($db, $certParam);
} catch (Throwable $dbError) {
    error_log("[CertiVault] report.php lookup failed: " . $dbError->getMessage());
    $cert = null;
}

// The lookup ran: record it. The canonical certificate alias comes first,
// so a certificate the guest already verified is a free repeat.
GuestQuotaService::record($db, $ip, $_SESSION, $cert
    ? [GuestQuotaService::certAlias((string)$cert['certificate_id']), GuestQuotaService::certAlias($certParam)]
    : $gq_keys);

if (!$cert) {
    http_response_code(404);
    die(report_page('Not Found', '404 — Certificate not found', '<p class="sv-notice-text"><a class="btn btn-primary" href="verify.php">Back to Verification</a></p>', 'info'));
}

try {
    $result = VerificationService::verify($db, $cert);
} catch (Throwable $verifyError) {
    error_log("[CertiVault] report.php verify failed: " . $verifyError->getMessage());
    http_response_code(500);
    die(report_page('Error', '500 — Verification engine error', '<p class="sv-notice-text"><a class="btn btn-primary" href="verify.php">Back to Verification</a></p>', 'danger'));
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
    $fbVerdict = (string)($trusted['verdict'] ?? $verdict);
    $fbBody = '<p class="sv-notice-text">The PDF engine is unavailable, so here are the same public facts.</p>'
        . '<dl class="sv-facts sv-report-facts">'
        . '<div><dt>Verdict</dt><dd><span class="badge-status badge-' . $e(strtolower($fbVerdict)) . '">' . $e($fbVerdict) . '</span></dd></div>'
        . '<div><dt>Trust score</dt><dd>' . ($trusted['score'] === null ? 'n/a' : (int)$trusted['score'] . ' / 100') . '</dd></div>'
        . '</dl><ul class="check-list sv-checks text-left">';
    foreach (($trusted['checks'] ?? []) as $c) {
        $fbBody .= '<li class="check ' . ($c['pass'] ? 'check-pass' : 'check-fail') . '"><span class="sv-check-icon" aria-hidden="true">'
            . ($c['pass'] ? '&#10003;' : '&#10007;') . '</span> <span class="sv-check-label">' . $e($c['label']) . '</span></li>';
    }
    $fbBody .= '</ul><p class="sv-disclaimer">' . $e(TrustScoreService::DISCLAIMER) . '</p>'
        . '<p><a class="btn btn-primary" href="verify.php">Back to Verification</a></p>';
    echo report_page('Verification Report', 'CertiVault — Verification Report', $fbBody, 'info');
    exit;
}

header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="certivault-report-' . preg_replace('/[^A-Za-z0-9]+/', '-', (string)$cert['certificate_id']) . '.pdf"');
header('Content-Length: ' . strlen($pdf));
header('Cache-Control: no-store');
echo $pdf;
exit;
