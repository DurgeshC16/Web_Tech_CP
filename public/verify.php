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
require_once __DIR__ . '/../src/utils/validators.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/utils/qrdecoder/autoload.php';

$db = Database::getInstance();

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
$external_ref  = null;  // informational card data for external references
$sv_tips       = false; // show the NOT FOUND tips paragraph
$sv_old_upload = false; // legacy qr_image upload path

// (a) QR scan arrives as ?token=...
if (!empty($_GET['token'])) {
    $query_type  = 'token';
    $query_value = $_GET['token'];
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

    if (isset($outcome['__upload_error']) && $outcome['__upload_error'] !== true) {
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
        $sv_file_error = $outcome['__upload_error'];
        $verdict = 'INVALID';
        $detail = $sv_file_error;
        $query_value = '(file upload: rejected)';
    } elseif (!empty($outcome['__candidates']) && SMART_EXTERNAL_LINKS) {
        $cand = $outcome['_candidates'][0];
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
    }
    if ($cert && defined('CERTIFICATE_TRANSPARENCY_ENABLED') && CERTIFICATE_TRANSPARENCY_ENABLED) $transparency = TransparencyLogService::certificateStatus($db, $cert);
}

// ── Rate limiting ─────────────────────────────────────────────────────
// More than 30 distinct lookups from one IP in 10 minutes → HTTP 429.
// Logged, and NO certificate query runs for that request.
$rate_limited = false;
if ($query_type !== null) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $rateStmt = $db->prepare('
        SELECT COUNT(DISTINCT query_value) as cnt
        FROM verification_logs
        WHERE verifier_ip = :ip AND verified_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
    ');
    $rateStmt->execute(['ip' => $ip]);
    if ((int)$rateStmt->fetchColumn() > 30) {
        $rate_limited = true;
        error_log("[CertiVault] Rate limit exceeded for IP $ip on verify.php — returned 429.");
        http_response_code(429);
        send_security_headers(); // this exit path never reaches head.php
        die('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Too Many Requests</title><link rel="stylesheet" href="assets/css/style.css"></head><body><div class="container" style="max-width:500px;text-align:center;margin-top:60px;"><h2>429 — Too Many Requests</h2><p>You have made too many verification lookups. Please wait a few minutes and try again.</p><a href="verify.php" class="btn">Back to Verification</a></div></body></html>');
    }
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
            'det' => log_safe_text(($detail ?: '') . ($sv_old_upload ? ' (via QR image upload)' : ($sv_via_hash ? ' (privacy hash lookup)' : ''))),
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
                'det' => log_safe_text(('[' . $log_query_type . '] ' . $detail)),
                'ip'  => $ip,
            ]);
        } catch (Throwable $ignored) {
        }
    }

    // ── Anti-Enumeration Awareness ────────────────────────────────────
    $rateStmt = $db->prepare('
        SELECT COUNT(DISTINCT query_value) as cnt
        FROM verification_logs
        WHERE verifier_ip = :ip AND verified_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
    ');
    $rateStmt->execute(['ip' => $ip]);
    $recent_attempts = $rateStmt->fetchColumn();
    if ($recent_attempts > 20) {
        error_log("[CertiVault RATE WARNING] IP $ip has made $recent_attempts distinct verification lookups in the last 10 minutes — possible enumeration attempt.");
    }
}
?>
<?php $page_title = 'Verify Certificate - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="container shell-narrow">
        <h2 style="text-align:center;">CertiVault — Smart Certificate Verification</h2>

        <?php if ($verdict === null): ?>
        <!-- ── Smart Verify panel ───────────────────────────────── -->
        <form method="POST" action="" class="card" id="smartVerifyForm" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <input type="hidden" name="MAX_FILE_SIZE" value="5242880">

            <div class="form-group">
                <label for="smart_id">Certificate ID, QR token or verification link (optional if you upload a file)</label>
                <input type="text" id="smart_id" name="smart_id" placeholder="Paste an ID (any format), a QR token, or a verification URL">
                <small>Any format works, e.g. CV-2026-000001, cv20260001, a 43-character QR token, or a full verify link. Enter at least one: the ID or the file below.</small>
            </div>

            <div class="form-group">
                <label for="issuer">Issuer (optional)</label>
                <select id="issuer" name="issuer">
                    <option value="certivault" selected>CertiVault (default)</option>
                    <option value="coursera">Coursera</option>
                    <option value="credly">Credly</option>
                    <option value="other">Other (public link)</option>
                </select>
            </div>
            <div class="form-group" id="otherUrlGroup" style="display:none;">
                <label for="other_url">Public verification link</label>
                <input type="text" id="other_url" name="other_url" placeholder="https://…">
                <small>Only https links to public pages. CertiVault never opens or scrapes it for you.</small>
            </div>

            <div class="form-group">
                <label for="smart_file">Certificate file (optional if you entered an ID — PDF, PNG or JPG, max 5 MB)</label>
                <input type="file" id="smart_file" name="smart_file" accept=".pdf,.png,.jpg,.jpeg" data-validate="upload_optional">
                <small>Drop the certificate file here or pick it. We try byte match → QR decode → text scan, in that order.</small>
            </div>

            <button type="button" class="btn btn-ghost btn-sm" id="privacyHashToggle" aria-pressed="false" style="margin-bottom:10px;">
                🔒 Hash in my browser (the file never leaves your device)
            </button>

            <button type="submit" class="btn btn-primary" style="width:100%;">Smart Verify</button>
        </form>

        <?php if (is_post_overflow()): ?>
            <p class="field-error" role="alert">The upload is larger than the server allows (post_max_size). Please use a smaller file.</p>
        <?php endif; ?>
        <?php if ($sv_file_error !== null): ?>
            <p class="field-error" role="alert"><?= htmlspecialchars($sv_file_error) ?></p>
        <?php endif; ?>
        <?php if ($sv_either_or !== null): ?>
            <p class="field-error" role="alert" style="text-align:center;"><?= htmlspecialchars($sv_either_or) ?></p>
        <?php endif; ?>

        <!-- ── QR camera scan (progressive enhancement; manual entry above always works) ── -->
        <div style="text-align:center; margin-top:16px;">
            <button type="button" class="btn btn-secondary" id="scanQrBtn">Scan QR with camera</button>
        </div>
        <div id="qrScanner" style="display:none; margin-top:16px;">
            <div id="qrReader" style="max-width:400px; margin:0 auto;"></div>
            <p class="field-error" id="qrError" role="alert" style="display:none;"></p>
            <div style="text-align:center; margin-top:8px;">
                <button type="button" class="btn btn-ghost btn-sm" id="qrStopBtn">Stop camera</button>
            </div>
        </div>
        <script src="assets/js/html5-qrcode.min.js"></script>
        <script>
        (function () {
            var btn = document.getElementById('scanQrBtn');
            var wrap = document.getElementById('qrScanner');
            var err = document.getElementById('qrError');
            var stopBtn = document.getElementById('qrStopBtn');
            var scanner = null;
            var running = false;

            function showError(msg) { err.textContent = msg; err.style.display = 'block'; }
            function hideError() { err.textContent = ''; err.style.display = 'none'; }

            // Accept what our QR codes encode (a verify.php URL or a bare
            // token); ANY other scanned text is passed to the server as a
            // candidate in any format — the layered server lookup decides.
            function routeScanText(text) {
                text = (text || '').trim();
                if (!text) return null;
                var m = text.match(/[?&]token=([A-Za-z0-9_\-]+)/);
                if (m) return { type: 'token', value: m[1] };
                if (/^[A-Za-z0-9_\-]{43}$/.test(text)) return { type: 'token', value: text };
                return { type: 'id', value: text };
            }

            function submitAsCertificateId(value) {
                var idInput = document.getElementById('smart_id');
                if (idInput && idInput.form) {
                    idInput.value = value;
                    idInput.form.submit();
                    return true;
                }
                return false;
            }

            function stop() {
                btn.disabled = false;
                if (scanner && running) {
                    running = false;
                    scanner.stop().then(function () { scanner.clear(); wrap.style.display = 'none'; })
                        .catch(function () { wrap.style.display = 'none'; });
                } else {
                    wrap.style.display = 'none';
                }
            }

            // Camera permission is requested only here, on explicit click.
            btn.addEventListener('click', function () {
                if (typeof Html5Qrcode === 'undefined') {
                    showError('Scanner unavailable right now — please type the Certificate ID instead.');
                    return;
                }
                hideError();
                wrap.style.display = 'block';
                btn.disabled = true;
                scanner = new Html5Qrcode('qrReader');
                scanner.start(
                    { facingMode: 'environment' },
                    { fps: 10, qrbox: { width: 250, height: 250 } },
                    function (decodedText) {
                        var route = routeScanText(decodedText);
                        if (route && route.type === 'token') {
                            stop();
                            window.location.href = 'verify.php?token=' + encodeURIComponent(route.value);
                        } else if (route && route.type === 'id' && submitAsCertificateId(route.value)) {
                            stop();
                        } else {
                            showError('That QR code is not a CertiVault code — try again or type the Certificate ID.');
                        }
                    },
                    function () { /* per-frame misses are normal; stay silent */ }
                ).then(function () { running = true; })
                .catch(function (e) {
                    running = false;
                    var name = (e && e.name) || '';
                    if (name === 'NotAllowedError') showError('Camera permission was denied. Allow camera access, or type the Certificate ID instead.');
                    else if (name === 'NotFoundError' || name === 'OverconstrainedError') showError('No camera was found on this device — please type the Certificate ID instead.');
                    else if (name === 'NotReadableError') showError('The camera is busy in another app — close it and try again.');
                    else showError('Could not start the camera (' + ((e && e.message) ? e.message : 'unknown error') + '). You can still type the Certificate ID.');
                });
            });
            stopBtn.addEventListener('click', stop);
        })();
        </script>

        <!-- ── Privacy-first hashing: SHA-256 via Web Crypto, then lookup by hash ── -->
        <script>
        (function () {
            var form = document.getElementById('smartVerifyForm');
            var input = document.getElementById('smart_file');
            var toggle = document.getElementById('privacyHashToggle');
            var issuerSel = document.getElementById('issuer');
            var otherGroup = document.getElementById('otherUrlGroup');

            issuerSel.addEventListener('change', function () {
                otherGroup.style.display = issuerSel.value === 'other' ? 'block' : 'none';
            });

            var privacy = false;
            toggle.addEventListener('click', function () {
                privacy = !privacy;
                toggle.setAttribute('aria-pressed', privacy ? 'true' : 'false');
                toggle.style.textDecoration = privacy ? 'underline' : 'none';
            });

            form.addEventListener('submit', function (e) {
                if (!privacy) return;                                 // normal upload path
                var f = input.files && input.files[0];
                if (!f) return;                                       // hashing not applicable
                if (!(window.crypto && crypto.subtle && crypto.subtle.digest && f.arrayBuffer)) {
                    return;                                           // fallback: upload normally
                }
                e.preventDefault();
                hashAndSubmit(f, form, input);
                async function hashAndSubmit(file, targetForm, fileInput) {
                    try {
                        var buf = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
                        var view = new Uint8Array(buf);
                        var hex = '';
                        for (var i = 0; i < view.length; i++) hex += ('0' + view[i].toString(16)).slice(-2);
                        var hidden = document.createElement('input');
                        hidden.type = 'hidden';
                        hidden.name = 'smart_hash';
                        hidden.value = hex;
                        targetForm.appendChild(hidden);
                        fileInput.disabled = true;                    // never uploaded
                        targetForm.submit();
                    } catch (ex) {
                        fileInput.disabled = false;
                        targetForm.submit();                          // fallback: upload normally
                    }
                }
            });
        })();
        </script>

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
        ?>
        <!-- ── Verdict Display ───────────────────────────────────── -->
        <div class="verdict-wrap" style="text-align:center; margin-top:20px;">
            <?php
            $verdict_icons = [
                'VALID' => '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M5 13l4 4L19 7"/></svg>',
                'TAMPERED' => '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M6 6l12 12M18 6L6 18"/></svg>',
                'EXPIRED' => '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>',
                'REVOKED' => '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="9"/><path d="M6 6l12 12"/></svg>',
                'SUPERSEDED' => '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M4 16l4-4-4-4M12 16l4-4-4-4"/></svg>',
                'INVALID' => '<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/></svg>',
            ];
            ?>
            <div class="verdict-seal verdict-seal-<?= strtolower($verdict) ?>">
                <?= $verdict_icons[$verdict] ?? '' ?>
                <?= $verdict ?>
            </div>
            <p class="verdict-detail" style="text-align:center;"><?= htmlspecialchars($detail) ?></p>
            <?php if ($cert && !empty($cert['public_key']) && defined('CERTIFICATE_TRANSPARENCY_ENABLED') && CERTIFICATE_TRANSPARENCY_ENABLED): ?>
                <?php $certFingerprint = CryptoService::fingerprintPublicKey((string)$cert['public_key']); $fingerprintPrefix = implode(':', array_slice(explode(':', $certFingerprint), 0, 6)); ?>
                <p style="text-align:center;font-size:0.9em;"><strong>Signed by key <?= htmlspecialchars($fingerprintPrefix) ?>:… v<?= (int)($cert['key_id'] ?? 1) ?></strong>
                    <a href="institutions.php#institution-<?= (int)$cert['institution_id'] ?>">Compare full fingerprint</a></p>
            <?php endif; ?>
            <?php if ($sv_both_note !== null): ?>
            <p style="text-align:center;color:var(--muted);font-size:0.9em;margin-top:6px;"><?= htmlspecialchars($sv_both_note) ?></p>
            <?php endif; ?>
            <?php if ($sv_tips && $verdict === 'INVALID' && $external_ref === null): ?>
            <div style="max-width:480px;margin:14px auto 0;text-align:left;background:rgba(0,0,0,0.06);border-radius:8px;padding:12px 16px;">
                <strong>Why not found?</strong>
                <ul style="margin:8px 0 0 18px;color:var(--muted);">
                    <li><?= htmlspecialchars('A re-saved, cropped or screenshot copy will not match the original file. Try the ID or QR code.') ?></li>
                    <li>Check for typos, or use QR / ID formats shown above.</li>
                </ul>
            </div>
            <?php endif; ?>
        </div>

        <?php if ($cert && is_array($transparency)): ?>
        <div class="card" style="margin-top:14px;border-left:4px solid <?= !empty($transparency['reconciled']) ? 'var(--verified)' : 'var(--warn)' ?>;">
            <strong>Transparency log</strong>
            <?php if (!empty($transparency['reconciled']) && !empty($transparency['proof'])): ?>
                <p>Certificate is included at sequence <?= (int)$transparency['proof']['seq'] ?> in a checkpoint signed by CertiVault’s platform key.</p>
                <p><small>Merkle root: <code class="break-all"><?= htmlspecialchars($transparency['proof']['root_hash']) ?></code></small></p>
                <details><summary>Inclusion proof</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere;"><?= htmlspecialchars(json_encode($transparency['proof'], JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES)) ?></pre></details>
            <?php else: ?>
                <p class="text-warn"><?= htmlspecialchars((string)($transparency['warning'] ?? 'WARNING: transparency log could not be reconciled.')) ?></p>
            <?php endif; ?>
            <a href="checkpoints/latest.json">Latest public checkpoint</a>
        </div>
        <?php endif; ?>

        <?php if ($external_ref !== null): ?>
        <!-- ── External reference card: NEVER a CertiVault verdict ── -->
        <div class="card external-ref-card" style="margin-top:16px; border-left:4px solid #8a72c9;">
            <p style="font-weight:600; margin-bottom:4px;">EXTERNAL REFERENCE FOUND
                <?= $external_ref['code'] !== '' ? '— ' . htmlspecialchars($external_ref['code']) : '' ?></p>
            <p style="color:var(--warn); font-size:0.92em; margin-bottom:10px;">
                <?php if (!empty($external_ref['unsafe'])): ?>
                This link is NOT the official <?= htmlspecialchars($external_ref['issuer_label']) ?> domain. Do not open it.
                <?php else: ?>
                Not verified by CertiVault. This is an issuer self-verification link
                generated from an allow-listed map; opening it takes you to the
                issuer's own public page.
                <?php endif; ?>
            </p>
            <?php if (empty($external_ref['unsafe'])): ?>
            <a href="<?= htmlspecialchars($external_ref['url']) ?>" target="_blank" rel="noopener noreferrer" class="btn btn-secondary">
                Open at <?= htmlspecialchars($external_ref['issuer_label']) ?> →
            </a>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <?php if ($external !== null && $verdict === 'INVALID' && $external_ref === null): ?>
        <!-- ── External source result: informational, NEVER a CertiVault verdict ── -->
        <div class="card external-source-card" style="margin-top:16px; border-left:4px solid #8a72c9;">
            <p style="font-weight:600; margin-bottom:4px;">
                Found in external source: <?= htmlspecialchars($external['source']) ?>.
            </p>
            <p style="color:var(--warn); font-size:0.92em; margin-bottom:10px;">
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
        <div class="card diploma" style="margin-top:25px;">
            <h3 class="cert-details-title"><?= htmlspecialchars($cert['title']) ?></h3>
            <dl class="cert-details">
                <dt>Certificate ID</dt><dd><?= htmlspecialchars($cert['certificate_id']) ?></dd>
                <dt>Awarded To</dt><dd><?= htmlspecialchars($cert['student_name']) ?></dd>
                <dt>Issued By</dt><dd><?= htmlspecialchars($cert['institution_name']) ?></dd>
                <dt>Issue Date</dt><dd><?= htmlspecialchars(date('F j, Y', strtotime($cert['issue_date']))) ?></dd>
                <?php if ($cert['expiry_date']): ?>
                    <dt>Expiry Date</dt><dd><?= htmlspecialchars(date('F j, Y', strtotime($cert['expiry_date']))) ?></dd>
                <?php endif; ?>
                <dt>Status</dt>
                <dd>
                    <span class="badge-status badge-<?= $cert['status'] === 'active' ? 'valid' : htmlspecialchars($cert['status']) ?>">
                        <?= htmlspecialchars($cert['status']) ?>
                    </span>
                </dd>
            </dl>
        </div>

        <?php elseif ($verdict === 'REVOKED'): ?>
        <!-- For REVOKED show only the cert ID so the verifier knows which record -->
        <div class="card" style="margin-top:25px;">
            <p><strong>Certificate ID:</strong> <?= htmlspecialchars($cert['certificate_id']) ?></p>
            <p style="color:var(--danger);">This certificate has been revoked and is no longer valid. Contact the issuing institution for details.</p>
        </div>

        <?php elseif ($verdict === 'SUPERSEDED'): ?>
        <!-- For SUPERSEDED show details + link to current version -->
        <div class="card" style="margin-top:25px;">
            <h3 class="cert-details-title"><?= htmlspecialchars($cert['title']) ?></h3>
            <dl class="cert-details">
                <dt>Certificate ID</dt><dd><?= htmlspecialchars($cert['certificate_id']) ?> (v<?= $cert['version'] ?>)</dd>
                <dt>Awarded To</dt><dd><?= htmlspecialchars($cert['student_name']) ?></dd>
                <dt>Issued By</dt><dd><?= htmlspecialchars($cert['institution_name']) ?></dd>
            </dl>
            <p style="color:var(--warn); margin-top:12px;">This version has been superseded by a corrected certificate.</p>
            <?php if ($superseded_by): ?>
                <a href="verify.php?token=<?= urlencode($superseded_by['qr_token']) ?>" class="btn btn-primary">Verify Current Version (<?= htmlspecialchars($superseded_by['certificate_id']) ?>) →</a>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <div style="text-align:center; margin-top:25px;">
            <a href="verify.php" class="btn">Verify Another Certificate</a>
        </div>
            <?php endif; ?>
        </div>

        <?php if ($trusted && ($trusted['score'] ?? null) !== null): ?>
        <?php
        $score_int   = (int)$trusted['score'];
        $gauge_angle = max(0, min(100, $score_int)) / 100.0 * 180.0;
        $gauge_rad   = deg2rad(180.0 - $gauge_angle);
        $gauge_x     = 55.0 + 47.0 * cos($gauge_rad);
        $gauge_y     = 58.0 - 47.0 * sin($gauge_rad);
        ?>
        <div class="card trust-panel" style="margin-top:16px;">
            <div style="display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap;">
                <svg width="110" height="66" viewBox="0 0 110 66" role="img" aria-label="Trust score gauge">
                    <path d="M8 58 A47 47 0 0 1 102 58" fill="none" stroke="#e0e0e0" stroke-width="10"/>
                    <path d="M8 58 A47 47 0 0 1 <?= number_format($gauge_x, 1, '.', '') ?> <?= number_format($gauge_y, 1, '.', '') ?>"
                          fill="none" stroke="#c9a227" stroke-width="10"/>
                </svg>
                <div>
                    <strong style="font-size:1.6em;"><?= $score_int ?></strong> / 100
                    <p style="color:var(--muted); font-size:0.9em; margin-top:4px;">
                        Rule-based score from CertiVault's existing checks.
                    </p>
                </div>
            </div>
            <ul style="margin:10px 0 0 20px; color:var(--muted);">
                <?php foreach (($trusted['checks'] ?? []) as $check_row): ?>
                <li style="margin-top:4px;">
                    <span style="color:<?= $check_row['pass'] ? 'var(--verified)' : 'var(--danger)' ?>; font-weight:600;">
                        <?= $check_row['pass'] ? '&#10003;' : '&#10007;' ?>
                    </span>
                    <?= htmlspecialchars((string)$check_row['label']) ?>
                    <span>(<?= $check_row['pass'] ? '+' . (int)$check_row['points'] : 0 ?> / <?= (int)$check_row['points'] ?>)</span>
                </li>
                <?php endforeach; ?>
            </ul>
            <p style="color:var(--muted); font-size:0.85em; margin-top:10px;">
                <?= htmlspecialchars(TrustScoreService::DISCLAIMER) ?>
            </p>
            <p style="margin-top:8px;">
                <a class="btn btn-secondary" href="report.php?cert=<?= rawurlencode((string)$cert['certificate_id']) ?>">
                    ⬇ Download verification report (PDF)
                </a>
            </p>
        </div>
        <?php endif; ?>

    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
