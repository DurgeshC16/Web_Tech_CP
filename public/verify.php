<?php
// public/verify.php — Public Verification Engine (no login required)
// Phase: Smart Verify — one panel accepting a Certificate ID in ANY format,
// a QR token, a full self-verification URL, an external issuer code, a
// certificate file (byte-hash match / QR decode / text extraction) or a
// client-side-hashed file. Local verdicts ALWAYS come from CertiVault's
// own DB via VerificationService; external candidates are rendered only
// as "Not verified by CertiVault" reference cards.
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/ExternalSourceService.php';
require_once __DIR__ . '/../src/services/SmartVerifyService.php';
require_once __DIR__ . '/../src/services/FileVerifyService.php';
require_once __DIR__ . '/../src/services/TrustScoreService.php';
require_once __DIR__ . '/../src/services/TransparencyLogService.php';
require_once __DIR__ . '/../src/services/GuestQuotaService.php';
require_once __DIR__ . '/../src/utils/validators.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/utils/qrdecoder/autoload.php';

// ── Presentation helpers (markup only — no lookups) ────────────────────
/** Decorative inline SVG icon (aria-hidden); unknown names give ''. */
function sv_icon(string $name): string {
    static $paths = [
        'id'       => '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/><path d="M6.5 16c.6-1.4 1.5-2 2.5-2s1.9.6 2.5 2M14 10h4M14 13h3"/>',
        'link'     => '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
        'file'     => '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M12 18v-6M9.5 14.5 12 12l2.5 2.5"/>',
        'qr'       => '<path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3"/><rect x="8" y="8" width="3" height="3"/><rect x="13" y="8" width="3" height="3"/><rect x="8" y="13" width="3" height="3"/><path d="M13 13h3v3"/>',
        'lock'     => '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
        'shield'   => '<path d="M12 3 5 6v5c0 4.4 3 8.3 7 10 4-1.7 7-5.6 7-10V6z"/><path d="m9 12 2 2 4-4"/>',
        'copy'     => '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>',
        'download' => '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
        'refresh'  => '<path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/>',
        'key'      => '<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l3 3M14 9l2 2"/>',
        'external' => '<path d="M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/>',
        'info'     => '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
        'log'      => '<path d="M4 6h16M4 12h16M4 18h10"/><circle cx="19" cy="18" r="2"/>',
        'camera'   => '<path d="M4 8h3l2-3h6l2 3h3a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z"/><circle cx="12" cy="13.5" r="3.5"/>',
        'check'    => '<path d="M5 13l4 4L19 7"/>',
        'cross'    => '<path d="M7 7l10 10M17 7 7 17"/>',
        'json'     => '<path d="M8 4H7a2 2 0 0 0-2 2v4l-2 2 2 2v4a2 2 0 0 0 2 2h1M16 4h1a2 2 0 0 1 2 2v4l2 2-2 2v4a2 2 0 0 1-2 2h-1"/>',
    ];
    if (!isset($paths[$name])) {
        return '';
    }
    return '<svg class="sv-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'
        . $paths[$name] . '</svg>';
}

/** Guest-quota "limit reached" notice wrapped as a call-to-action card. */
function sv_limit_notice(array $quota): string {
    return '<div class="sv-limit">'
        . '<span class="sv-limit-badge" aria-hidden="true">' . sv_icon('lock') . '</span>'
        . GuestQuotaService::renderLimitNotice($quota)
        . '<ul class="sv-limit-perks" aria-label="Why create an account">'
        . '<li>' . sv_icon('check') . 'No daily limit when signed in</li>'
        . '<li>' . sv_icon('check') . 'Free to create</li>'
        . '<li>' . sv_icon('check') . 'Same instant verification</li>'
        . '</ul></div>';
}

$db = Database::getInstance();

// ── Rate limiting — BEFORE any certificate lookup ─────────────────────
// At most 30 distinct lookups per IP per 10 minutes; the 31st distinct
// one gets HTTP 429 and no certificate query, hash, QR decode or RSA check
// runs. The key is derived from the RAW request inputs (token, typed ID,
// browser hash, uploaded file bytes), so repeating the same lookup is free.
/** Lookup key for the limiter, or null when the request looks nothing up. */
function verify_rate_key(): ?string {
    if (!empty($_GET['token'])) {
        return 'token:' . (string)$_GET['token'];
    }
    $getId = trim((string)($_GET['certificate_id'] ?? ($_GET['id'] ?? '')));
    if ($getId !== '' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {
        return 'id:' . mb_strtolower(mb_substr($getId, 0, 255));
    }
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        return null;
    }
    $parts = [];
    foreach (['smart_id', 'certificate_id', 'smart_hash', 'smart_qr_text', 'issuer', 'other_url'] as $field) {
        $v = trim((string)($_POST[$field] ?? ''));
        if ($v !== '') {
            // NO truncation: the text pipelines read up to 1–2 KB of these
            // fields (a URL/ID can sit after char 512), so a truncated key
            // would let different lookups share one key and count as free
            // "repeats" — for this limiter and the guest quota alike. Long
            // values are folded to a digest instead (bounded key size).
            $v = mb_strtolower($v);
            $parts[$field] = mb_strlen($v) > 512 ? 'sha256:' . hash('sha256', $v) : $v;
        }
    }
    foreach (['smart_file', 'qr_image'] as $field) {
        $tmp = $_FILES[$field]['tmp_name'] ?? '';
        if (is_string($tmp) && $tmp !== '' && is_uploaded_file($tmp)) {
            $parts[$field] = (string)hash_file('sha256', $tmp);
        }
    }
    return $parts ? 'post:' . json_encode($parts) : null;
}

$sv_rate_key = verify_rate_key();
$sv_rate_count = 0;
if ($sv_rate_key !== null) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $gate = VerificationService::checkAndRecordLookup($db, $ip, $sv_rate_key);
    $sv_rate_count = $gate['count'];
    if ($gate['limited']) {
        error_log("[CertiVault] Rate limit exceeded for IP $ip on verify.php — returned 429.");
        http_response_code(429);
        header('Retry-After: ' . (VerificationService::VERIFY_RATE_WINDOW_MINUTES * 60));
        send_security_headers(); // this exit path never reaches head.php
        die('<!DOCTYPE html><html lang="en" data-theme="' . htmlspecialchars(current_theme()) . '"><head><meta charset="UTF-8">'
            . '<meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Too Many Requests</title>'
            . '<link rel="stylesheet" href="assets/css/style.css"><link rel="stylesheet" href="assets/css/components.css">'
            . '<link rel="stylesheet" href="assets/css/features.css"><link rel="stylesheet" href="assets/css/pages/verify.css"></head>'
            . '<body class="page-verify"><main id="main"><div class="container verify-shell sv-notice-page"><div class="sv-body text-center">'
            . '<span class="sv-notice-icon sv-tone-warn" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span>'
            . '<h1 class="sv-notice-title">429 — Too Many Requests</h1><p class="sv-notice-text">You have made too many verification lookups. Please wait a few minutes and try again.</p>'
            . '<a href="verify.php" class="btn btn-primary">Back to Verification</a></div></div></main></body></html>');
    }
}

// ── Guest verification quota — also BEFORE any certificate lookup ─────
// Visitors who are not logged in get GUEST_VERIFY_LIMIT free verifications
// per window (GuestQuotaService). The key is the limiter key above, so a
// refresh / the same QR link again is free. Here it is only CHECKED; the
// credit is recorded after the pipeline, once we know the request really
// reached a lookup (malformed input never costs a credit). An exhausted
// guest gets the "log in or register" page and NO lookup runs.
$sv_guest_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$sv_quota = GuestQuotaService::check($db, $sv_guest_ip, $_SESSION, $sv_rate_key !== null ? [$sv_rate_key] : []);
if ($sv_rate_key !== null && !$sv_quota['allowed']) {
    GuestQuotaService::sendLimitHeaders($sv_quota);
    $page_title = 'Free verification limit reached - CertiVault';
    require __DIR__ . '/../src/partials/head.php';
    require __DIR__ . '/../src/partials/header.php';
    echo '<main id="main"><div class="container verify-shell sv-limit-shell"><div class="sv-body">' . sv_limit_notice($sv_quota) . '</div></div></main>';
    require __DIR__ . '/../src/partials/footer.php';
    echo '</body></html>';
    exit;
}
$sv_no_lookup = false; // set by the paths that end before any certificate query
const SV_NOT_FOUND_TIPS = 'A re-saved, cropped or screenshot copy will not match the original file — '
    . 'that changes its bytes. Try the Certificate ID or scan the QR code instead. You can also '
    . 'select your issuer above (Coursera, Credly, or a public link) to open their own verification page.';

// ── Resolve lookup method ──────────────────────────────────────────────
$query_type   = null;   // 'token' | 'certificate_id' | 'file' | 'qr_image' | 'text' | 'external_ref'
$query_value  = null;
$cert         = null;
$verdict      = null;   // VALID | TAMPERED | EXPIRED | REVOKED | SUPERSEDED | INVALID
$detail       = null;   // human-readable sub-reason
$superseded_by = null;
$trusted       = null;   // trust score (computed for local verdicts only)
$external_ref  = null;  // informational card data for external references
$sv_tips       = false; // show the NOT FOUND tips paragraph
$sv_old_upload = false; // legacy qr_image upload path

// (a) QR scan arrives as ?token=...
if (!empty($_GET['token'])) {
    $query_type  = 'token';
    $query_value = $_GET['token'];
}

// (b) Shareable direct link by ID: verify.php?certificate_id=… (alias ?id=).
//     Same layered lookup and pre-flight format check as a typed ID.
if ($query_type === null && $_SERVER['REQUEST_METHOD'] === 'GET') {
    $sv_get_id = trim((string)($_GET['certificate_id'] ?? ($_GET['id'] ?? '')));
    if ($sv_get_id !== '') {
        $query_type  = 'certificate_id';
        $query_value = mb_substr($sv_get_id, 0, 255);
    }
}

// (c) QR text decoded in the visitor's browser (smart-verify.js renders PDF
//     pages / images locally). Used only as a FALLBACK after the exact file
//     hash; resolves local tokens / certificate IDs only.
$sv_qr_text = (SMART_VERIFY_ENABLED && $_SERVER['REQUEST_METHOD'] === 'POST')
    ? trim(mb_substr((string)($_POST['smart_qr_text'] ?? ''), 0, 1024)) : '';
$sv_via_browser_qr = false;
function sv_cert_from_qr_text($db, string $text) {
    if ($text === '') {
        return null;
    }
    foreach (SmartVerifyService::extractCandidates($text) as $cand) {
        $value = (string)($cand['value'] ?? '');
        if ($value === '' || strlen($value) > 255) {
            continue;
        }
        $type = $cand['type'] ?? '';
        $cert = $type === 'token' ? VerificationService::findByToken($db, $value)
            : ($type === 'certificate_id' ? VerificationService::findByFlexibleCertificateId($db, $value) : null);
        if ($cert) {
            return $cert;
        }
    }
    return null;
}

// ── Smart Verify input normalization — either/or, at least one input ──
// The ID box and the file field are ALTERNATIVES: exactly one, or both
// (in which case the file counts first and the ID becomes the fallback).
// Neither provided ⇒ one shared message, no red errors, no lookups.
$sv_id_raw         = '';
$sv_has_file       = FileVerifyService::fileProvided($_FILES['smart_file'] ?? null) && SMART_VERIFY_ENABLED;
$sv_has_hash       = false;
$sv_either_or      = null;   // set when NEITHER input was provided
$sv_both_note      = null;   // set when BOTH ID and file/hash were provided
$sv_fallback_to_id = false;  // set when the file stage was inconclusive
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['csrf_token']) && !isset($_FILES['qr_image'])) {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    $sv_id_raw = trim((string)($_POST['smart_id'] ?? ''));
    if ($sv_id_raw === '' && isset($_POST['certificate_id'])) {
        // Legacy/quick-verify POST key — treated as the same ID input.
        $sv_id_raw = trim((string)$_POST['certificate_id']);
    }
    $sv_has_hash = SMART_VERIFY_ENABLED && !empty($_POST['smart_hash']);
    $plan = SmartVerifyService::planVerifyInput($sv_id_raw, $sv_has_file, $sv_has_hash);
    if ($plan['action'] === 'either_or') {
        $sv_either_or = $plan['message'];
    } elseif ($plan['fallback_to_id']) {
        $sv_both_note = $plan['note'];
    }
}

// ── Smart Verify text pipeline (single input: ID, token, self-URL, issuer code) ──
// Legacy identifiers keep working: certificate_id (index quick-verify) posts
// straight through the same text pipeline below.
function sv_run_text_candidates($db, string $raw, string &$query_type, &$query_value, &$cert, &$external_ref): ?string
{
    // Returns a status: 'cert' (hit), 'external' (external card rendered),
    // 'unresolved' (no hit; caller decides INVALID), 'malformed' candidates skip.
    $qualityCandidates = SmartVerifyService::extractCandidates($raw);
    if (empty($qualityCandidates)) {
        // Nothing recognisable: fall back to a plain certificate-ID attempt
        // (the pre-flight + layered lookup turn garbage into INVALID).
        $query_type  = 'certificate_id';
        $query_value = trim($raw);
        $cert = VerificationService::findByFlexibleCertificateId($db, $query_value);
        return $cert ? 'cert' : 'unresolved';
    }

    $local_misses_ids = false;
    foreach ($qualityCandidates as $cand) {
        if (($cand['type'] ?? '') === 'unsafe_link') {
            $external_ref = ['issuer_label' => (string)$cand['label'], 'url' => '', 'code' => '', 'unsafe' => true];
            $query_type = 'external_ref';
            return 'external';
        }
    }
    foreach ($qualityCandidates as $cand) {
        if (($cand['type'] ?? '') === 'external_ref') {
            continue; // handled after local candidates per spec order
        }
        $value = (string)($cand['value'] ?? '');
        if ($value === '' || mb_strlen($value) > 255) {
            continue;
        }
        if (($cand['type'] ?? '') === 'token') {
            $query_type  = $query_type ?: 'token';
            $query_value = substr($value, 0, 255);
            $cert = VerificationService::findByToken($db, $value);
            if ($cert) {
                return 'cert';
            }
        } else {
            $query_type  = $query_type ?: 'certificate_id';
            $query_value = substr($value, 0, 255);
            $cert = VerificationService::findByFlexibleCertificateId($db, $value);
            if ($cert) {
                return 'cert';
            }
            $local_misses_ids = true;
        }
    }

    // External references (allow-listed issuer URLs/codes from the text).
    foreach ($qualityCandidates as $cand) {
        if (($cand['type'] ?? '') !== 'external_ref') {
            continue;
        }
        if (($cand['issuer'] ?? '') === 'credly') {
            // Credly IDs are sent through the normal local-first verification
            // pipeline, then looked up through the managed external registry.
            $query_type = 'certificate_id';
            $query_value = (string)$cand['value'];
            return 'unresolved';
        }
        $link = SmartVerifyService::buildIssuerLink($cand['issuer'], $cand['value']);
        $url  = is_array($link) ? $link['url'] : null;
        if ($url === null && ($cand['url'] ?? '') !== '') {
            $other = SmartVerifyService::validateOtherLink($cand['url']);
            $url = is_array($other) && is_array($link) && $link['url'] === $cand['url'] ? $cand['url'] : ($other['url'] ?? null);
        }
        if ($url === null) {
            continue;
        }
        $query_type   = 'external_ref';
        $query_value  = substr($value, 0, 255);
        $external_ref = [
            'issuer_label' => $cand['label'],
            'url' => $url,
            'code' => $cand['value'],
        ];
        return 'external';
    }

    return $local_misses_ids ? 'unresolved' : 'unresolved';
}

// (The Smart Verify ID pipeline lives BELOW the file/hash stages so the
// "both provided" order — file first, then ID — is enforced physically.)

// ── Privacy-first client-side hash lookup (the FILE never leaves the device) ──
$sv_via_hash = false;
if ($query_type === null && $sv_has_hash
    && $_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    $query_value = (string)$_POST['smart_hash'];
    if (preg_match('/^[a-f0-9]{64}$/i', $query_value)) {
        $sv_via_hash = true;
        $query_type = 'file';
        $found = FileVerifyService::findLocalByContentHash($db, $query_value);
        if ($found) {
            $cert = $found[0];
        } elseif (($qrCert = sv_cert_from_qr_text($db, $sv_qr_text)) !== null) {
            $cert = $qrCert;                // no byte match, but the QR inside it resolved
            $sv_via_browser_qr = true;
            $query_type = 'qr_image';
        }
    } else {
        $query_value = '(malformed hash)';
    }
    if ($sv_both_note && $cert === null) {
        // "Both provided" and the hash came up empty → the ID is the
        // fallback. Reset the trail so the ID pipeline starts fresh.
        $sv_fallback_to_id = true;
        $sv_via_hash = false;
        $query_type  = null;
        $query_value = null;
    }
}

// ── Smart Verify file pipeline (PDF/PNG/JPG/PNG-QR, max 5 MB) ──
$sv_file_error = null;
if ($query_type === null && $_SERVER['REQUEST_METHOD'] === 'POST'
    && $sv_has_file && SMART_VERIFY_ENABLED) {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    $query_type = 'file';
    $query_value = '(file upload: ' . strtolower(pathinfo($_FILES['smart_file']['name'] ?? '', PATHINFO_EXTENSION)) . ')';
    $outcome = FileVerifyService::run($db, $_FILES['smart_file']);
    if (empty($outcome['__cert']) && !isset($outcome['__upload_error'])
        && ($qrCert = sv_cert_from_qr_text($db, $sv_qr_text)) !== null) {
        $outcome['__cert'] = $qrCert;
        $outcome['__resolved'] = ['query_type' => 'qr_image', 'stage' => 'QR code read in your browser — your file is not a byte-exact copy of the issued original, so compare the details below with your copy'];
    }

    if (isset($outcome['__upload_error']) && $outcome['__upload_error'] !== true) {
        $sv_no_lookup = true; // rejected upload: no certificate query ran
        $sv_file_error = $outcome['__upload_error'];
        $verdict = 'INVALID';
        $detail = $sv_file_error;
        $query_value = '(file upload: rejected)';
    } elseif (!empty($outcome['__cert'])) {
        $cert = $outcome['__cert'];
        $result = VerificationService::verify($db, $cert);
        $verdict       = $result['verdict'];
        $detail        = $result['detail'];
        $superseded_by = $result['superseded_by'];
        if (!empty($outcome['__resolved'])) {
            $query_type = $outcome['__resolved']['query_type'];
            $detail = ($detail ?: '') . ' [' . $outcome['__resolved']['stage'] . ']';
        }
    } elseif (isset($outcome['__upload_error'])) {
        $sv_no_lookup = true;
        $sv_file_error = $outcome['__upload_error'];
        $verdict = 'INVALID';
        $detail = $sv_file_error;
        $query_value = '(file upload: rejected)';
    } elseif (!empty($outcome['__candidates']) && SMART_EXTERNAL_LINKS) {
        $cand = $outcome['__candidates'][0];
        $link = SmartVerifyService::buildIssuerLink($cand['issuer'] ?? '', $cand['value'] ?? '');
        if (is_array($link)) {
            $external_ref = ['issuer_label' => $link['label'], 'url' => $link['url'], 'code' => $cand['value']];
            $query_type = 'external_ref';
            $verdict = 'INVALID';
            $detail = 'Not found in CertiVault. External reference found inside the file.';
            $sv_tips = true;
        } elseif ($sv_both_note) {
            // "Both provided": candidates found but inconclusive → the ID
            // is the fallback (reset the trail for the ID pipeline).
            $sv_fallback_to_id = true;
            $sv_tips = false;
            $query_type  = null;
            $query_value = null;
        } else {
            $verdict = 'INVALID';
            $detail = 'No certificate found matching this file.';
            $sv_tips = true;
        }
    } elseif ($sv_both_note) {
        // "Both provided": file could NOT be resolved (no byte match,
        // no QR decode, no usable text scan) → the ID is the fallback.
        // Reset the trail so the ID pipeline starts fresh.
        $sv_fallback_to_id = true;
        $sv_tips = false;
        $query_type  = null;
        $query_value = null;
    } else {
        $verdict = 'INVALID';
        $detail = 'No certificate found matching this file.';
        $sv_tips = true;
    }
}

// ── Smart Verify ID pipeline (ID, token, self-URL, issuer code) ──
// Runs when the ID box carries the request. In the "both provided" case
// this is the FALLBACK after an inconclusive file/hash stage: the file
// result already ran first (see the file pipeline above) and came back
// without a conclusion.
if ($sv_id_raw !== '' && SMART_VERIFY_ENABLED
    && ($query_type === null || $sv_fallback_to_id)) {
    if ($sv_fallback_to_id) {
        // Defensive reset of the inconclusive file/hash trail.
        $query_type  = null;
        $query_value = null;
        $cert        = null;
        $verdict     = null;
        $detail      = null;
        $sv_tips     = false;
    }
    $query_type   = $query_type ?: 'text';
    $query_value  = substr($sv_id_raw, 0, 2048);
    $chosenIssuer = (string)($_POST['issuer'] ?? '');
    $otherUrl     = (string)($_POST['other_url'] ?? '');

    $status = sv_run_text_candidates($db, $query_value, $query_type, $query_value, $cert, $external_ref);

    // Explicit issuer dropdown: when the user selected an issuer and the
    // text looks like their code, build the allow-listed public link.
    if ($status === 'unresolved' && $query_type !== 'certificate_id' && SMART_EXTERNAL_LINKS && $chosenIssuer !== '' && $chosenIssuer !== 'certivault') {
        $link = null;
        if ($chosenIssuer !== 'other') {
            $code = trim($query_value);
            $link = SmartVerifyService::buildIssuerLink($chosenIssuer, $code);
        } else {
            $link = SmartVerifyService::validateOtherLink($otherUrl !== '' ? $otherUrl : $query_value);
            if ($link === null) {
                $spoofIssuer = SmartVerifyService::suspiciousIssuerUrl($otherUrl !== '' ? $otherUrl : $query_value);
                if ($spoofIssuer !== null) {
                    $external_ref = ['issuer_label' => $spoofIssuer, 'url' => '', 'code' => '', 'unsafe' => true];
                    $query_type = 'external_ref';
                    $status = 'external';
                }
            }
        }
        if (is_array($link)) {
            $issuers = SmartVerifyService::externalIssuers();
            $external_ref = [
                'issuer_label' => ($link['label'] ?? null) ?: ($chosenIssuer === 'other' ? 'Other issuer link' : ($issuers[$chosenIssuer]['label'] ?? 'Issuer')),
                'url' => $link['url'],
                'code' => $chosenIssuer === 'other' ? '' : trim($query_value),
            ];
            $query_type = 'external_ref';
            $status = 'external';
        }
    }

    if ($status === 'cert') {
        $result = VerificationService::verify($db, $cert);
        $verdict       = $result['verdict'];
        $detail        = $result['detail'];
        $superseded_by = $result['superseded_by'];
    } else {
        $verdict = 'INVALID';
        $external_ref !== null
            ? ($detail = 'Not found in CertiVault. The external reference below is provided as a convenience only — CertiVault has not verified it.')
            : ($detail = 'No certificate found matching the provided identifier.');
        $sv_tips = true;
    }
}

// (c) No-JS legacy fallback: QR image upload — kept for old links, decodes
// from the PHP temp file (never stored — temp deleted immediately).
if ($query_type === null
    && $_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_FILES['qr_image'])
    && ($_FILES['qr_image']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    $sv_old_upload = true;
    $img_check = v_qr_image($_FILES['qr_image']);
    if ($img_check !== true) {
        $sv_no_lookup = true;
        $query_type  = 'token';
        $query_value = '(qr image: invalid upload)';
        $verdict     = 'INVALID';
        $detail      = $img_check;
    } else {
        $tmp = $_FILES['qr_image']['tmp_name'];
        try {
            $qr_reader = new Zxing\QrReader($tmp);
            $decoded = trim((string)$qr_reader->text());
        } catch (Throwable $e) {
            error_log('[CertiVault] QR image decode failed: ' . get_class($e));
            $decoded = '';
        }
        @unlink($tmp); // never stored on the server
        if ($decoded === '') {
            $sv_no_lookup = true;
            $query_type  = 'token';
            $query_value = '(qr image: no code)';
            $verdict     = 'INVALID';
            $detail      = 'No QR code found in this image. Please upload a clear photo of the QR code.';
        } elseif (preg_match('/[?&]token=([A-Za-z0-9_\-]+)/', $decoded, $m)) {
            $query_type  = 'token';
            $query_value = $m[1];
        } elseif (preg_match('/^[A-Za-z0-9_\-]{43}$/', $decoded)) {
            $query_type  = 'token';
            $query_value = $decoded;
        } else {
            // Not a CertiVault QR URL/token: pass the scanned text to the
            // server as a certificate-ID candidate in ANY format. The
            // shared lookup (exact → normalized → compact) decides; the
            // pre-flight charset check turns real garbage into INVALID.
            $query_type  = 'certificate_id';
            $query_value = trim($decoded);
        }
    }
}

// ── Pre-flight format check ────────────────────────────────────────────
// Reject malformed identifiers BEFORE hitting the database. Certificate
// IDs accept the flexible set (letters, digits, spaces, - _ / .; the
// lookup normalizes CV-style input); anything else is malformed.
if ($query_type !== null && $verdict === null && $cert === null) {
    $well_formed = true;
    if ($query_type === 'token') {
        $well_formed = (bool)preg_match('/^[A-Za-z0-9_-]{43}$/', $query_value);
    } elseif ($query_type === 'certificate_id') {
        // Certificate IDs are the shorter primary identifiers: 3–40
        // chars in the flexible set (letters, digits, spaces, - _ / .).
        $t = trim((string)$query_value);
        $well_formed = $t !== '' && mb_strlen($t) >= 3 && mb_strlen($t) <= 40
            && (bool)preg_match('/^[A-Za-z0-9\-_\/. ]+$/', $t);
    } elseif ($query_type === 'text') {
        // Free-pasted Smart Verify text (single input box): same charset,
        // still capped at 64 like before; unresolved URL-ish garbage
        // fails the charset and reads as malformed.
        $t = trim((string)$query_value);
        $well_formed = $t !== '' && mb_strlen($t) <= 64
            && (bool)preg_match('/^[A-Za-z0-9\-_\/. ]+$/', $t);
    }
    if (!$well_formed) {
        $sv_no_lookup = true; // malformed: rejected before the database
        $verdict = 'INVALID';
        $detail  = 'The provided identifier is malformed. Expected format: '
            . ($query_type === 'token'
                ? 'a 43-character QR token.'
                : ($query_type === 'certificate_id'
                    ? 'a certificate ID (letters, digits, spaces and - _ / ., 3 to 40 chars).'
                    : 'a certificate ID (letters, digits, spaces and - _ / ., max 64 chars).'));
    }
}

// ── Verification Engine (local lookups not yet run) ────────────────────
$external = null; // optional external-source record (Phase: external sources)
$transparency = null;
if ($query_type !== null && $verdict === null) {
    if ($cert === null) {
        if ($query_type === 'token') {
            $cert = VerificationService::findByToken($db, $query_value);
        } else {
            $cert = VerificationService::findByFlexibleCertificateId($db, $query_value);
        }
    }

    if (!$cert) {
        $verdict = 'INVALID';
        $detail  = $sv_old_upload
            ? 'QR code not recognized. No certificate matches the code in this image.'
            : ($sv_via_hash
                ? 'No certificate on record matches this file fingerprint.'
                : 'No certificate found matching the provided identifier.');
        $sv_tips = (bool)($sv_tips || $sv_via_hash);

        // ── Optional external source (feature is OFF by default) ──
        if ($query_type === 'certificate_id' && ((defined('EXT_SOURCE_ENABLED') && EXT_SOURCE_ENABLED)
            || (defined('EXT_REGISTRY_ENABLED') && EXT_REGISTRY_ENABLED))) {
            $xres = ExternalSourceService::lookup($db, $query_value);
            if ($xres['hit'] !== null) {
                $external = ['fields' => $xres['hit'], 'source' => $xres['source']];
                // The local verdict stays INVALID — the external record is
                // information only, never CertiVault-verified.
                $detail = 'No matching certificate in CertiVault. See the external source result below.';
            }
        }
    } else {
        $result = VerificationService::verify($db, $cert);
        $verdict       = $result['verdict'];
        $detail        = $result['detail'];
        $superseded_by = $result['superseded_by'];
        if ($sv_via_browser_qr) {
            $detail .= ' [QR code read in your browser — your file is not a byte-exact copy of the issued original, so compare the details below with your copy]';
        }
    }
    if ($cert && defined('CERTIFICATE_TRANSPARENCY_ENABLED') && CERTIFICATE_TRANSPARENCY_ENABLED) $transparency = TransparencyLogService::certificateStatus($db, $cert);
}

// ── Guest quota: record the credit (only lookups that really ran) ─────
// The resolved certificate is added as a free alias so the PDF report
// (report.php) and the same certificate entered another way are repeats.
if ($query_type !== null && !$sv_no_lookup) {
    $sv_quota_keys = [$sv_rate_key ?? ('q:' . $query_type . ':' . mb_strtolower((string)$query_value))];
    if ($cert && !empty($cert['certificate_id'])) {
        $sv_quota_keys[] = GuestQuotaService::certAlias((string)$cert['certificate_id']);
    }
    $sv_quota = GuestQuotaService::record($db, $sv_guest_ip, $_SESSION, $sv_quota_keys);
}

// ── Audit Logging ─────────────────────────────────────────────────
if ($query_type !== null) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    // Verification outcome rows: locals log their verdict; the smart-file
    // pipeline logs under 'file'/'qr_image'/'text'/'external_ref' (ENUM
    // widened by migration 009; legacy servers fall back gracefully below).
    $log_query_type = in_array($query_type, ['token', 'certificate_id', 'file', 'qr_image', 'text', 'external_ref'], true)
        ? $query_type : 'token';
    $logStmt = $db->prepare('
        INSERT INTO verification_logs
            (query_type, query_value, certificate_id_found, result, detail, verifier_ip)
        VALUES
            (:qt, :qv, :cid, :res, :det, :ip)
    ');
    try {
        $logStmt->execute([
            'qt'  => $sv_old_upload ? 'token' : $log_query_type,
            // Truncate to 255 so long/hostile input cannot overflow the column
            'qv'  => mb_substr(log_safe_text((string)$query_value), 0, 255),
            'cid' => $cert ? $cert['certificate_id'] : null,
            'res' => $verdict,
            // detail is VARCHAR(255): truncate, or strict SQL drops the audit row
            'det' => mb_substr(log_safe_text(($detail ?: '') . ($sv_old_upload ? ' (via QR image upload)' : ($sv_via_hash ? ' (privacy hash lookup)' : ''))), 0, 255),
            'ip'  => $ip,
        ]);
    } catch (PDOException $e) {
        // ENUM not widened yet (migration 009 pending on this install) —
        // re-log with the historical 'token' type so nothing is lost.
        try {
            $logStmt->execute([
                'qt'  => 'token',
                'qv'  => mb_substr(log_safe_text((string)$query_value), 0, 255),
                'cid' => $cert ? $cert['certificate_id'] : null,
                'res' => $verdict,
                'det' => mb_substr(log_safe_text(('[' . $log_query_type . '] ' . $detail)), 0, 255),
                'ip'  => $ip,
            ]);
        } catch (Throwable $ignored) {
        }
    }

    // ── Anti-Enumeration Awareness ────────────────────────────────────
    // Count comes from the pre-lookup gate above (no extra query).
    if ($sv_rate_count > VerificationService::VERIFY_ENUM_WARN) {
        error_log("[CertiVault RATE WARNING] IP $ip has made $sv_rate_count distinct verification lookups in the last 10 minutes — possible enumeration attempt.");
    }
}
?>
<?php $page_title = 'Verify Certificate - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<?php
// ── View helpers (presentation only) ──────────────────────────────────
$sv_verdict_icons = [
    'VALID' => '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true" focusable="false"><path d="M5 13l4 4L19 7"/></svg>',
    'TAMPERED' => '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true" focusable="false"><path d="M6 6l12 12M18 6L6 18"/></svg>',
    'EXPIRED' => '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>',
    'REVOKED' => '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"/><path d="M6 6l12 12"/></svg>',
    'SUPERSEDED' => '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true" focusable="false"><path d="M4 16l4-4-4-4M12 16l4-4-4-4"/></svg>',
    'INVALID' => '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" aria-hidden="true" focusable="false"><circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/></svg>',
];
$sv_headlines = [
    'VALID'      => 'Authentic certificate',
    'TAMPERED'   => 'Tampering detected',
    'EXPIRED'    => 'Authentic, but expired',
    'REVOKED'    => 'Certificate revoked',
    'SUPERSEDED' => 'Replaced by a newer version',
    'INVALID'    => 'Could not be verified',
];
?>
<main id="main" class="sv-main">
    <div class="container verify-shell<?= $verdict === null ? ' sv-shell-form' : ' sv-shell-result' ?>">

        <?php if ($verdict === null): ?>
        <!-- ── Hero ─────────────────────────────────────────────────── -->
        <header class="sv-hero">
            <p class="sv-eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span> Public verification · no login needed</p>
            <h1 class="sv-hero-title">Verify any certificate <span class="hero-highlight">in seconds</span></h1>
            <p class="sv-hero-sub">Paste an ID or link, drop the certificate file, or scan its QR code. CertiVault checks the issuer’s digital signature and the certificate fingerprint for you.</p>
            <ul class="sv-trust-chips">
                <li><?= sv_icon('shield') ?>RSA-signed</li>
                <li><?= sv_icon('key') ?>SHA-256 fingerprint</li>
                <li><?= sv_icon('lock') ?>Private by design</li>
            </ul>
            <svg class="sv-hero-art" viewBox="0 0 120 120" aria-hidden="true" focusable="false"><path d="M60 8 20 24v30c0 26 17 47 40 58 23-11 40-32 40-58V24z" fill="none" stroke="currentColor" stroke-width="3"/><path d="m42 60 13 13 25-26" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </header>

        <div class="sv-body">
            <?php if (!empty($sv_quota['enabled']) && empty($sv_quota['exempt']) && (int)$sv_quota['remaining'] === 0): ?>
            <!-- Guest has used every free verification: say so before the form. -->
            <?= sv_limit_notice($sv_quota) ?>
            <?php endif; ?>

            <?php if (is_post_overflow()): ?>
                <p class="field-error sv-form-error" role="alert">The upload is larger than the server allows (post_max_size). Please use a smaller file.</p>
            <?php endif; ?>
            <?php if ($sv_file_error !== null): ?>
                <p class="field-error sv-form-error" role="alert"><?= htmlspecialchars($sv_file_error) ?></p>
            <?php endif; ?>
            <?php if ($sv_either_or !== null): ?>
                <p class="field-error sv-form-error" role="alert"><?= htmlspecialchars($sv_either_or) ?></p>
            <?php endif; ?>

            <!-- ── Smart Verify panel ───────────────────────────────── -->
            <form method="POST" action="" class="sv-form" id="smartVerifyForm" enctype="multipart/form-data" data-loading
                  data-pdf-lib="assets/js/vendor/pdf.min.js" data-pdf-worker="assets/js/vendor/pdf.worker.min.js"
                  data-pdf-max-pages="10" data-scan-max-ms="20000" data-render-max-width="1600">
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <input type="hidden" name="MAX_FILE_SIZE" value="5242880">

                <!-- Method picker: shown by smart-verify.js; without JS every
                     section below is simply visible. -->
                <div class="tablist sv-tabs" id="svTabs" role="tablist" aria-label="How do you want to verify?" hidden>
                    <button type="button" class="tab" role="tab" id="svTabId" data-sv-tab="id" aria-controls="svPanelText" aria-selected="true"><?= sv_icon('id') ?><span>ID</span></button>
                    <button type="button" class="tab" role="tab" id="svTabLink" data-sv-tab="link" aria-controls="svPanelText" aria-selected="false" tabindex="-1"><?= sv_icon('link') ?><span>Link</span></button>
                    <button type="button" class="tab" role="tab" id="svTabFile" data-sv-tab="file" aria-controls="svPanelFile" aria-selected="false" tabindex="-1"><?= sv_icon('file') ?><span>File</span></button>
                    <button type="button" class="tab" role="tab" id="svTabScan" data-sv-tab="scan" aria-controls="svPanelScan" aria-selected="false" tabindex="-1"><?= sv_icon('qr') ?><span>Scan QR</span></button>
                </div>

                <!-- ID / token / link -->
                <section class="sv-pane tabpanel" id="svPanelText" aria-labelledby="svTabId">
                    <h2 class="sv-pane-title"><?= sv_icon('id') ?>Certificate ID or link</h2>
                    <div class="form-group">
                        <label for="smart_id" id="smartIdLabel"
                               data-sv-label-id="Certificate ID or QR token"
                               data-sv-label-link="Verification link">Certificate ID, QR token or verification link (optional if you upload a file)</label>
                        <div class="sv-input-icon">
                            <?= str_replace('class="sv-ico"', 'class="sv-ico sv-ico-id"', sv_icon('id')) ?>
                            <?= str_replace('class="sv-ico"', 'class="sv-ico sv-ico-link"', sv_icon('link')) ?>
                            <input type="text" id="smart_id" name="smart_id" placeholder="Paste an ID (any format), a QR token, or a verification URL" autocomplete="off" spellcheck="false"
                                   data-sv-ph-id="e.g. CV-2026-000001"
                                   data-sv-ph-link="https://…/verify.php?token=…">
                        </div>
                        <small id="smartIdHint"
                               data-sv-hint-id="Any format works: CV-2026-000001, cv20260001, CV 2026 000001 or the QR token printed under the code."
                               data-sv-hint-link="Paste the full verification URL from a QR code, an e-mail or a shared post.">Any format works, e.g. CV-2026-000001, cv20260001, a 43-character QR token, or a full verify link. Enter at least one: the ID or the file below.</small>
                    </div>

                    <details class="sv-advanced">
                        <summary>Issued on Coursera, Credly or another platform?</summary>
                        <div class="form-group">
                            <label for="issuer">Issuer (optional)</label>
                            <select id="issuer" name="issuer">
                                <option value="certivault" selected>CertiVault (default)</option>
                                <option value="coursera">Coursera</option>
                                <option value="credly">Credly</option>
                                <option value="other">Other (public link)</option>
                            </select>
                        </div>
                        <div class="form-group" id="otherUrlGroup" hidden>
                            <label for="other_url">Public verification link</label>
                            <input type="text" id="other_url" name="other_url" placeholder="https://…">
                            <small>Only https links to public pages. CertiVault never opens or scrapes it for you.</small>
                        </div>
                    </details>
                </section>

                <!-- Certificate file -->
                <section class="sv-pane tabpanel" id="svPanelFile" aria-labelledby="svTabFile">
                    <h2 class="sv-pane-title"><?= sv_icon('file') ?>Certificate file</h2>
                    <div class="form-group">
                        <label for="smart_file">Certificate file (optional if you entered an ID — PDF, PNG or JPG, max 5 MB)</label>
                        <div class="sv-dropzone" id="svDropzone">
                            <span class="sv-drop-icon" aria-hidden="true"><?= sv_icon('file') ?></span>
                            <span class="sv-drop-title">Drop your certificate here</span>
                            <span class="sv-drop-sub">or <span class="sv-drop-link">browse your files</span> · PDF, PNG, JPG up to 5 MB</span>
                            <input type="file" id="smart_file" name="smart_file" accept=".pdf,.png,.jpg,.jpeg" data-validate="upload_optional">
                            <span class="sv-drop-file" id="svFileName" aria-live="polite" hidden></span>
                        </div>
                        <small>We try the exact file fingerprint first, then the QR code inside it (read in your browser, PDFs included), then a text scan.</small>
                    </div>

                    <button type="button" class="privacy-toggle" id="privacyHashToggle" aria-pressed="false">
                        <span class="sv-switch" aria-hidden="true"><span class="sv-switch-thumb"></span></span>
                        <span class="sv-switch-text">
                            <strong><?= sv_icon('lock') ?>Hash in my browser</strong>
                            <span>The file never leaves your device — only its SHA-256 fingerprint is sent.</span>
                        </span>
                    </button>
                </section>

                <!-- QR camera scan (progressive enhancement; manual entry always works) -->
                <section class="sv-pane tabpanel" id="svPanelScan" aria-labelledby="svTabScan">
                    <h2 class="sv-pane-title"><?= sv_icon('qr') ?>Scan the QR code</h2>
                    <div class="sv-scan">
                        <div class="sv-scan-art" aria-hidden="true">
                            <span class="sv-scan-corners"></span>
                            <?= sv_icon('qr') ?>
                            <span class="sv-scan-line"></span>
                        </div>
                        <p class="sv-scan-text">Point your camera at the QR code printed on the certificate. Your browser asks for camera permission first; nothing is recorded.</p>
                        <button type="button" class="btn btn-primary" id="scanQrBtn"><?= sv_icon('camera') ?>Scan QR with camera</button>
                    </div>
                    <div id="qrScanner" class="qr-scanner" hidden>
                        <div id="qrReader" class="sv-qr-reader"></div>
                        <p class="field-error" id="qrError" role="alert" hidden></p>
                        <div class="text-center mt-2">
                            <button type="button" class="btn btn-ghost btn-sm" id="qrStopBtn">Stop camera</button>
                        </div>
                    </div>
                </section>

                <button type="submit" class="btn btn-primary btn-block btn-lg sv-submit"><?= sv_icon('shield') ?><span>Smart Verify</span></button>
                <p id="svStatus" class="sv-status" role="status" aria-live="polite" hidden></p>
            </form>

            <?php if ((int)($sv_quota['remaining'] ?? 0) > 0): ?>
            <?= GuestQuotaService::renderCounter($sv_quota) ?>
            <?php endif; ?>

            <ol class="sv-how" aria-label="How verification works">
                <li data-reveal data-reveal-delay="1"><span class="sv-how-num">1</span><strong>Enter or scan</strong><span>ID, link, file or QR code — any format.</span></li>
                <li data-reveal data-reveal-delay="2"><span class="sv-how-num">2</span><strong>We check the proof</strong><span>Issuer signature, fingerprint and live status.</span></li>
                <li data-reveal data-reveal-delay="3"><span class="sv-how-num">3</span><strong>Instant verdict</strong><span>Valid, expired, revoked or tampered — explained.</span></li>
            </ol>
            <p class="sv-more-links">
                <a href="offline_verify.php"><?= sv_icon('json') ?>Verify a credential file offline</a>
                <a href="institutions.php"><?= sv_icon('key') ?>Institution public keys</a>
            </p>
        </div>

        <?php else: ?>
        <?php
        // ── Phase 2: rule-based trust score for local verdicts ──
        // Read-only replay of VerificationService's own checks; the score
        // can never contradict the verdict above.
        $trusted = null;
        if ($verdict !== 'INVALID') {
            try {
                $trusted = TrustScoreService::compute($db, $cert);
            } catch (Throwable $trustError) {
                error_log('[CertiVault] Trust score computation failed: ' . $trustError->getMessage());
                $trusted = null;
            }
        }
        $sv_v = strtolower($verdict);
        ?>
        <!-- ── Verdict Display ───────────────────────────────────── -->
        <section class="verdict-wrap sv-verdict sv-v-<?= htmlspecialchars($sv_v) ?>" aria-labelledby="svVerdictTitle">
            <p class="sv-eyebrow">Verification result</p>
            <div class="sv-seal-stage">
                <?php if ($verdict === 'VALID'): ?>
                <span class="sv-confetti" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></span>
                <?php endif; ?>
                <div class="verdict-seal verdict-seal-<?= strtolower($verdict) ?>">
                    <?= $sv_verdict_icons[$verdict] ?? '' ?>
                    <?= $verdict ?>
                </div>
            </div>
            <h1 class="sv-verdict-title" id="svVerdictTitle"><?= htmlspecialchars($sv_headlines[$verdict] ?? 'Verification result') ?></h1>
            <p class="verdict-detail"><?= htmlspecialchars($detail) ?></p>
            <?php if ($cert && !empty($cert['public_key']) && defined('CERTIFICATE_TRANSPARENCY_ENABLED') && CERTIFICATE_TRANSPARENCY_ENABLED): ?>
                <?php $certFingerprint = CryptoService::fingerprintPublicKey((string)$cert['public_key']); $fingerprintPrefix = implode(':', array_slice(explode(':', $certFingerprint), 0, 6)); ?>
                <p class="sv-signer"><?= sv_icon('key') ?><strong>Signed by key <?= htmlspecialchars($fingerprintPrefix) ?>:… v<?= (int)($cert['key_id'] ?? 1) ?></strong>
                    <a href="institutions.php#institution-<?= (int)$cert['institution_id'] ?>">Compare full fingerprint</a></p>
            <?php endif; ?>
            <?php if ($sv_both_note !== null): ?>
            <p class="sv-note"><?= sv_icon('info') ?><?= htmlspecialchars($sv_both_note) ?></p>
            <?php endif; ?>
        </section>

        <div class="sv-body sv-result-body">
            <?php if ($sv_tips && $verdict === 'INVALID' && $external_ref === null): ?>
            <div class="panel-muted sv-tips">
                <strong><?= sv_icon('info') ?>Why not found?</strong>
                <ul>
                    <li><?= htmlspecialchars('A re-saved, cropped or screenshot copy will not match the original file. Try the ID or QR code.') ?></li>
                    <li>Check for typos, or use QR / ID formats shown above.</li>
                </ul>
            </div>
            <?php endif; ?>

            <?php if ($external_ref !== null): ?>
            <!-- ── External reference card: NEVER a CertiVault verdict ── -->
            <div class="card card-accent-brand external-ref-card sv-ext">
                <p class="sv-ext-title"><?= sv_icon('external') ?>EXTERNAL REFERENCE FOUND
                    <?= $external_ref['code'] !== '' ? '— ' . htmlspecialchars($external_ref['code']) : '' ?></p>
                <p class="sv-ext-warn">
                    <?php if (!empty($external_ref['unsafe'])): ?>
                    This link is NOT the official <?= htmlspecialchars($external_ref['issuer_label']) ?> domain. Do not open it.
                    <?php else: ?>
                    Not verified by CertiVault. This is an issuer self-verification link
                    generated from an allow-listed map; opening it takes you to the
                    issuer's own public page.
                    <?php endif; ?>
                </p>
                <?php if (empty($external_ref['unsafe'])): ?>
                <div>
                    <a href="<?= htmlspecialchars($external_ref['url']) ?>" target="_blank" rel="noopener noreferrer" class="btn btn-secondary">
                        Open at <?= htmlspecialchars($external_ref['issuer_label']) ?> →
                    </a>
                </div>
                <?php endif; ?>
            </div>
            <?php endif; ?>

            <?php if ($external !== null && $verdict === 'INVALID' && $external_ref === null): ?>
            <!-- ── External source result: informational, NEVER a CertiVault verdict ── -->
            <div class="card card-accent-brand external-source-card sv-ext">
                <p class="sv-ext-title"><?= sv_icon('external') ?>
                    Found in external source: <?= htmlspecialchars($external['source']) ?>.
                </p>
                <p class="sv-ext-warn">
                    CertiVault has not verified this record's signature or contents. Treat it as
                    unverified information from the source named above, not as a CertiVault result.
                </p>
                <dl class="cert-details">
                    <dt>Certificate ID</dt><dd><?= htmlspecialchars($query_value) ?></dd>
                    <dt>Awarded To</dt><dd><?= htmlspecialchars($external['fields']['holder']) ?></dd>
                    <dt>Title</dt><dd><?= htmlspecialchars($external['fields']['title']) ?></dd>
                    <dt>Issued By</dt><dd><?= htmlspecialchars($external['fields']['issuer']) ?></dd>
                    <dt>Issue Date</dt><dd><?= htmlspecialchars($external['fields']['issue_date']) ?></dd>
                    <dt>Status (per source)</dt>
                    <dd><span class="badge-status badge-<?= ($external['fields']['status'] ?? '') === 'active' ? 'valid' : htmlspecialchars((string)($external['fields']['status'] ?? 'unknown')) ?>">
                        <?= htmlspecialchars($external['fields']['status']) ?>
                    </span></dd>
                    <?php if (!empty($external['fields']['source_url'])): ?>
                        <dt>Source</dt>
                        <dd><a href="<?= htmlspecialchars($external['fields']['source_url']) ?>" target="_blank" rel="noopener noreferrer">Open record at source</a></dd>
                    <?php endif; ?>
                </dl>
            </div>
            <?php endif; ?>

            <?php if (in_array($verdict, ['VALID', 'EXPIRED'])): ?>
            <!-- Show certificate details only for VALID / EXPIRED -->
            <?php $sv_link = rtrim(BASE_URL, '/') . '/verify.php?certificate_id=' . rawurlencode((string)$cert['certificate_id']); ?>
            <article class="card diploma sv-cert" aria-labelledby="svCertTitle">
                <header class="sv-cert-head">
                    <span class="sv-cert-mark" aria-hidden="true"><?= sv_icon('shield') ?></span>
                    <div class="sv-cert-heading">
                        <p class="sv-cert-kicker">Issued by <?= htmlspecialchars($cert['institution_name']) ?></p>
                        <h2 class="cert-details-title" id="svCertTitle"><?= htmlspecialchars($cert['title']) ?></h2>
                    </div>
                </header>
                <p class="sv-cert-awarded"><span>Awarded to</span> <strong><?= htmlspecialchars($cert['student_name']) ?></strong></p>
                <dl class="sv-facts">
                    <div><dt>Issue Date</dt><dd><?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></dd></div>
                    <?php if ($cert['expiry_date']): ?>
                    <div><dt>Expiry Date</dt><dd><?= htmlspecialchars(date('F j, Y', strtotime($cert['expiry_date']))) ?></dd></div>
                    <?php else: ?>
                    <div><dt>Expiry Date</dt><dd>Does not expire</dd></div>
                    <?php endif; ?>
                    <?php $sv_status_shown = VerificationService::effectiveStatus($cert); // display only: an active record past its expiry date reads "expired" ?>
                    <div><dt>Status</dt><dd><span class="badge-status badge-<?= $sv_status_shown === 'active' ? 'valid' : htmlspecialchars((string)$sv_status_shown) ?>"><?= htmlspecialchars((string)$sv_status_shown) ?></span></dd></div>
                </dl>
                <div class="sv-copy-row">
                    <span class="sv-copy-label">Certificate ID</span>
                    <code class="sv-copy-value" id="svCertId"><?= htmlspecialchars($cert['certificate_id']) ?></code>
                    <button type="button" class="btn btn-ghost btn-sm sv-copy" data-copy-target="svCertId" data-copy-message="Certificate ID copied" aria-label="Copy certificate ID"><?= sv_icon('copy') ?><span>Copy</span></button>
                </div>
                <?php if (!empty($cert['sha256_hash'])): ?>
                <div class="sv-copy-row">
                    <span class="sv-copy-label">Content fingerprint (SHA-256)</span>
                    <code class="sv-copy-value sv-hash" id="svCertHash"><?= htmlspecialchars((string)$cert['sha256_hash']) ?></code>
                    <button type="button" class="btn btn-ghost btn-sm sv-copy" data-copy-target="svCertHash" data-copy-message="Fingerprint copied" aria-label="Copy content fingerprint"><?= sv_icon('copy') ?><span>Copy</span></button>
                </div>
                <?php endif; ?>
                <div class="sv-cert-actions">
                    <button type="button" class="btn btn-secondary btn-sm" data-copy="<?= htmlspecialchars($sv_link) ?>" data-copy-message="Verification link copied"><?= sv_icon('link') ?>Copy verification link</button>
                </div>
            </article>

            <?php elseif ($verdict === 'REVOKED'): ?>
            <!-- For REVOKED show only the cert ID so the verifier knows which record -->
            <div class="card card-accent-danger sv-state-card">
                <p><strong>Certificate ID:</strong> <code><?= htmlspecialchars($cert['certificate_id']) ?></code></p>
                <p class="text-danger">This certificate has been revoked and is no longer valid. Contact the issuing institution for details.</p>
            </div>

            <?php elseif ($verdict === 'SUPERSEDED'): ?>
            <!-- For SUPERSEDED show details + link to current version -->
            <article class="card card-accent-info sv-state-card">
                <h2 class="cert-details-title"><?= htmlspecialchars($cert['title']) ?></h2>
                <dl class="cert-details">
                    <dt>Certificate ID</dt><dd><?= htmlspecialchars($cert['certificate_id']) ?> (v<?= $cert['version'] ?>)</dd>
                    <dt>Awarded To</dt><dd><?= htmlspecialchars($cert['student_name']) ?></dd>
                    <dt>Issued By</dt><dd><?= htmlspecialchars($cert['institution_name']) ?></dd>
                </dl>
                <p class="text-warn mt-3">This version has been superseded by a corrected certificate.</p>
                <?php if ($superseded_by): ?>
                    <div>
                        <a href="verify.php?token=<?= urlencode($superseded_by['qr_token']) ?>" class="btn btn-primary">Verify Current Version (<?= htmlspecialchars($superseded_by['certificate_id']) ?>) →</a>
                    </div>
                <?php endif; ?>
            </article>
            <?php endif; ?>

            <?php if ($trusted && ($trusted['score'] ?? null) !== null): ?>
            <?php
            $score_int  = max(0, min(100, (int)$trusted['score']));
            $score_band = $score_int >= 80 ? 'high' : ($score_int >= 50 ? 'mid' : 'low');
            ?>
            <section class="card trust-panel sv-trust sv-band-<?= $score_band ?>" aria-labelledby="svTrustTitle" data-reveal>
                <div class="sv-trust-top">
                    <div class="sv-gauge">
                        <svg viewBox="0 0 200 116" role="img" aria-label="Trust score gauge: <?= $score_int ?> out of 100" focusable="false">
                            <defs>
                                <linearGradient id="svGaugeGrad" x1="0" y1="0" x2="1" y2="0">
                                    <stop offset="0" class="sv-stop-a"/>
                                    <stop offset="1" class="sv-stop-b"/>
                                </linearGradient>
                            </defs>
                            <path class="sv-gauge-track" d="M16 100 A84 84 0 0 1 184 100" pathLength="100"/>
                            <path class="sv-gauge-value" d="M16 100 A84 84 0 0 1 184 100" pathLength="100" stroke="url(#svGaugeGrad)" stroke-dasharray="100 100" stroke-dashoffset="<?= 100 - $score_int ?>"/>
                        </svg>
                        <div class="sv-gauge-num"><strong data-count-to="<?= $score_int ?>" data-count-duration="1200"><?= $score_int ?></strong><span>/ 100</span></div>
                    </div>
                    <div class="sv-trust-copy">
                        <h2 class="sv-card-title" id="svTrustTitle">Trust score</h2>
                        <p class="text-muted text-sm m-0">Rule-based score from CertiVault's existing checks.</p>
                    </div>
                </div>
                <ul class="check-list sv-checks">
                    <?php foreach (($trusted['checks'] ?? []) as $check_row): ?>
                    <li class="check <?= $check_row['pass'] ? 'check-pass' : 'check-fail' ?>">
                        <span class="sv-check-icon" aria-hidden="true"><?= $check_row['pass'] ? '&#10003;' : '&#10007;' ?></span>
                        <span class="sv-check-label"><span class="visually-hidden"><?= $check_row['pass'] ? 'Passed:' : 'Failed:' ?> </span><?= htmlspecialchars((string)$check_row['label']) ?></span>
                        <span class="sv-check-pts">(<?= $check_row['pass'] ? '+' . (int)$check_row['points'] : 0 ?> / <?= (int)$check_row['points'] ?>)</span>
                    </li>
                    <?php endforeach; ?>
                </ul>
                <p class="sv-disclaimer"><?= htmlspecialchars(TrustScoreService::DISCLAIMER) ?></p>
                <p class="btn-row sv-downloads">
                    <a class="btn btn-secondary" href="report.php?cert=<?= rawurlencode((string)$cert['certificate_id']) ?>">
                        <?= sv_icon('download') ?>Download verification report (PDF)
                    </a>
                    <a class="btn btn-secondary" href="credential.php?certificate_id=<?= rawurlencode((string)$cert['certificate_id']) ?>">
                        <?= sv_icon('json') ?>Signed credential (JSON)
                    </a>
                </p>
                <p class="text-muted small text-center m-0">The JSON file can be re-checked in any browser — no trust in this server needed:
                    <a href="offline_verify.php">verify a credential file</a>.</p>
            </section>
            <?php endif; ?>

            <?php if ($cert && is_array($transparency)): ?>
            <?php $sv_tlog_ok = !empty($transparency['reconciled']) && !empty($transparency['proof']); ?>
            <section class="card sv-tlog <?= !empty($transparency['reconciled']) ? 'card-accent-valid' : 'card-accent-warn' ?>" aria-labelledby="svTlogTitle" data-reveal>
                <div class="card-head">
                    <h2 class="sv-card-title" id="svTlogTitle"><?= sv_icon('log') ?>Transparency log</h2>
                    <span class="badge-status <?= $sv_tlog_ok ? 'badge-valid' : 'badge-warn' ?>"><?= $sv_tlog_ok ? 'Included' : 'Warning' ?></span>
                </div>
                <?php if ($sv_tlog_ok): ?>
                    <p>Certificate is included at sequence <?= (int)$transparency['proof']['seq'] ?> in a checkpoint signed by CertiVault’s platform key.</p>
                    <details class="sv-disclosure">
                        <summary>Merkle root</summary>
                        <p><small>Merkle root: <code class="break-all"><?= htmlspecialchars($transparency['proof']['root_hash']) ?></code></small></p>
                    </details>
                    <details class="sv-disclosure"><summary>Inclusion proof</summary><pre class="sv-pre"><?= htmlspecialchars(json_encode($transparency['proof'], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)) ?></pre></details>
                <?php else: ?>
                    <p class="text-warn"><?= htmlspecialchars((string)($transparency['warning'] ?? 'WARNING: transparency log could not be reconciled.')) ?></p>
                <?php endif; ?>
                <p class="m-0"><a href="checkpoints/latest.json">Latest public checkpoint</a></p>
            </section>
            <?php endif; ?>

            <?= GuestQuotaService::renderCounter($sv_quota) ?>
            <div class="sv-again">
                <a href="verify.php" class="btn btn-primary"><?= sv_icon('refresh') ?>Verify Another Certificate</a>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <script src="assets/js/validation.js"></script>
    <?php if ($verdict === null): ?>
    <script src="assets/js/html5-qrcode.min.js"></script>
    <?php endif; ?>
    <script src="assets/js/smart-verify.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
