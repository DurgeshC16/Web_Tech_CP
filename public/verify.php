<?php
// public/verify.php — Public Verification Engine (no login required)
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/utils/validators.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/utils/qrdecoder/autoload.php';

$db = Database::getInstance();

// ── Resolve lookup method ──────────────────────────────────────────────
$query_type  = null;   // 'token' | 'certificate_id'
$query_value = null;
$cert        = null;
$verdict     = null;   // VALID | TAMPERED | EXPIRED | REVOKED | SUPERSEDED | INVALID
$detail      = null;   // human-readable sub-reason
$superseded_by = null; // if superseded, the new certificate row

// (a) QR scan arrives as ?token=...
if (!empty($_GET['token'])) {
    $query_type  = 'token';
    $query_value = $_GET['token'];
}

// (b) Manual form POST with a Certificate ID
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['certificate_id'])) {
    $query_type  = 'certificate_id';
    $query_value = trim($_POST['certificate_id']);
}

// (c) No-JS fallback: QR image upload. The image is validated, decoded
// from the PHP temp file (never stored — temp deleted immediately), and
// the extracted identifier flows through the SAME pipeline below, so an
// uploaded image alone is never "valid": only VerificationService decides.
$via_qr_upload = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_FILES['qr_image'])
    && ($_FILES['qr_image']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    $via_qr_upload = true;
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
        } elseif (($norm_id = normalize_certificate_id($decoded)) !== null) {
            $query_type  = 'certificate_id';
            $query_value = $norm_id;
        } elseif (v_certificate_id_flexible($decoded) === true) {
            // Format-only check (no DB): custom IDs, looked up flexibly below.
            $query_type  = 'certificate_id';
            $query_value = trim($decoded);
        } else {
            $query_type  = 'token';
            $query_value = '(qr image: unrecognized)';
            $verdict     = 'INVALID';
            $detail      = 'QR code not recognized. No certificate matches the code in this image.';
        }
    }
}

// ── Pre-flight format check ────────────────────────────────────────────
// Reject malformed identifiers BEFORE hitting the database. Certificate
// IDs accept the flexible set (letters, digits, spaces, - _ / .; the
// lookup normalizes CV-style input); anything else is malformed.
if ($query_type !== null && $verdict === null) {
    $well_formed = true;
    if ($query_type === 'token') {
        $well_formed = (bool)preg_match('/^[A-Za-z0-9_-]{43}$/', $query_value);
    } else {
        $t = trim((string)$query_value);
        $well_formed = $t !== '' && strlen($t) <= 64
            && (bool)preg_match('/^[A-Za-z0-9\-_\/. ]+$/', $t);
    }
    if (!$well_formed) {
        $verdict = 'INVALID';
        $detail  = 'The provided identifier is malformed. Expected format: '
            . ($query_type === 'token' ? 'a 43-character QR token.' : 'a certificate ID (letters, digits, spaces and - _ / ., max 64 chars).');
    }
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

// ── Verification Engine ────────────────────────────────────────────────
if ($query_type !== null && $verdict === null) {
    $cert = $query_type === 'token'
        ? VerificationService::findByToken($db, $query_value)
        : VerificationService::findByFlexibleCertificateId($db, $query_value);

    if (!$cert) {
        $verdict = 'INVALID';
        $detail  = $via_qr_upload
            ? 'QR code not recognized. No certificate matches the code in this image.'
            : 'No certificate found matching the provided identifier.';
    } else {
        $result = VerificationService::verify($db, $cert);
        $verdict       = $result['verdict'];
        $detail        = $result['detail'];
        $superseded_by = $result['superseded_by'];
    }
}

// ── Audit Logging ─────────────────────────────────────────────────
if ($query_type !== null) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $logStmt = $db->prepare('
        INSERT INTO verification_logs
            (query_type, query_value, certificate_id_found, result, detail, verifier_ip)
        VALUES
            (:qt, :qv, :cid, :res, :det, :ip)
    ');
    $logStmt->execute([
        'qt'  => $via_qr_upload ? 'token' : $query_type,
        // Truncate to 255 so long/hostile input cannot overflow the column
        'qv'  => mb_substr(log_safe_text((string)$query_value), 0, 255),
        'cid' => $cert ? $cert['certificate_id'] : null,
        'res' => $verdict,
        'det' => log_safe_text($detail . ($via_qr_upload ? ' (via QR image upload)' : '')),
        'ip'  => $ip,
    ]);

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
        <h2 style="text-align:center;">CertiVault — Certificate Verification</h2>

        <?php if ($verdict === null): ?>
        <!-- ── Landing / Search Form ─────────────────────────────── -->
        <p style="text-align:center; color:var(--muted);">
            Enter a Certificate ID below, or scan the QR code printed on the certificate.
        </p>
        <form method="POST" action="" style="margin-top:20px;" class="card">
            <div class="form-group">
                <label for="certificate_id">Certificate ID</label>
                <input type="text" id="certificate_id" name="certificate_id" placeholder="CV-YYYY-NNNNNN" data-validate="required|certid" required>
                <small>Tip: "cv-2026-1" or "CV 2026 000001" work too — IDs are matched leniently.</small>
            </div>
            <button type="submit" class="btn btn-primary" style="width:100%;">Verify</button>
        </form>

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

            // Accept what our QR codes encode (a verify.php URL) or a bare token.
            function tokenFromText(text) {
                text = (text || '').trim();
                var m = text.match(/[?&]token=([A-Za-z0-9_\-]+)/);
                if (m) return m[1];
                if (/^[A-Za-z0-9_\-]{43}$/.test(text)) return text;
                return null;
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
                        var token = tokenFromText(decodedText);
                        if (token) {
                            stop();
                            window.location.href = 'verify.php?token=' + encodeURIComponent(token);
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

        <!-- ── QR image upload: client decode first, server fallback without JS ── -->
        <div class="card" style="margin-top:16px;">
            <h3 style="text-align:center;">Or upload a QR image</h3>
            <p style="text-align:center; color:var(--muted); font-size:0.9em;">PNG, JPG or WEBP, max 3 MB. You can also drag &amp; drop or paste an image.</p>
            <form id="qrUploadForm" method="POST" action="" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <input type="hidden" name="MAX_FILE_SIZE" value="3145728">
                <div id="qrDrop" style="border:2px dashed var(--border); border-radius:8px; padding:20px; text-align:center; cursor:pointer;">
                    <label for="qr_image" style="cursor:pointer; font-weight:600;">Choose an image
                        <input type="file" id="qr_image" name="qr_image" accept=".png,.jpg,.jpeg,.webp" style="display:none;">
                    </label>
                    <div style="color:var(--muted); font-size:0.85em; margin-top:6px;">…or drop / paste it here</div>
                </div>
                <div style="text-align:center;">
                    <img id="qrPreview" alt="Uploaded QR preview" style="display:none; max-width:220px; margin:12px auto 0; border:1px solid var(--border); border-radius:6px;">
                </div>
                <p class="field-error" id="qrUploadError" role="alert" style="display:none;"></p>
                <button type="submit" class="btn btn-primary" style="width:100%; margin-top:12px;">Verify QR image</button>
            </form>
            <div id="qrFileReader" style="display:none;"></div>
        </div>
        <script>
        (function () {
            var form = document.getElementById('qrUploadForm');
            var input = document.getElementById('qr_image');
            var drop = document.getElementById('qrDrop');
            var err = document.getElementById('qrUploadError');
            var preview = document.getElementById('qrPreview');
            var QR_MAX = 3 * 1024 * 1024;
            var QR_EXT = ['png', 'jpg', 'jpeg', 'webp'];
            var QR_MIME = ['image/png', 'image/jpeg', 'image/webp'];
            var pending = null;

            function showError(msg) { err.textContent = msg; err.style.display = 'block'; }
            function hideError() { err.textContent = ''; err.style.display = 'none'; }

            function checkFile(f) {
                if (!f) return 'Please choose a QR image first.';
                var ext = (f.name.split('.').pop() || '').toLowerCase();
                if (QR_EXT.indexOf(ext) === -1) return 'Only PNG, JPG, and WEBP images are allowed.';
                if (f.type && QR_MIME.indexOf(f.type) === -1) return 'That file is not a PNG, JPG, or WEBP image.';
                if (f.size > QR_MAX) return 'Image exceeds the 3 MB limit — please use a smaller one.';
                if (f.size < 100) return 'That file looks empty — please choose a real image.';
                return true;
            }

            function takeFile(f) {
                hideError();
                var ok = checkFile(f);
                if (ok !== true) { pending = null; preview.style.display = 'none'; showError(ok); return; }
                pending = f;
                // Mirror into the real input so the no-JS server fallback gets it.
                try {
                    var dt = new DataTransfer();
                    dt.items.add(f);
                    input.files = dt.files;
                } catch (e) { /* older browsers: native submit still works from picker */ }
                if (preview.src) URL.revokeObjectURL(preview.src);
                preview.src = URL.createObjectURL(f);
                preview.style.display = 'block';
            }

            input.addEventListener('change', function () { if (input.files[0]) takeFile(input.files[0]); });
            ['dragenter', 'dragover'].forEach(function (ev) {
                drop.addEventListener(ev, function (e) { e.preventDefault(); drop.style.borderColor = 'var(--seal)'; });
            });
            ['dragleave', 'drop'].forEach(function (ev) {
                drop.addEventListener(ev, function (e) { e.preventDefault(); drop.style.borderColor = 'var(--border)'; });
            });
            drop.addEventListener('drop', function (e) {
                var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
                if (f) takeFile(f);
            });
            document.addEventListener('paste', function (e) {
                var items = (e.clipboardData && e.clipboardData.files) || [];
                for (var i = 0; i < items.length; i++) {
                    if (items[i].type.indexOf('image/') === 0) { takeFile(items[i]); break; }
                }
            });

            function routeText(text) {
                text = (text || '').trim();
                var m = text.match(/[?&]token=([A-Za-z0-9_\-]+)/);
                if (m) { window.location.href = 'verify.php?token=' + encodeURIComponent(m[1]); return; }
                if (/^[A-Za-z0-9_\-]{43}$/.test(text)) { window.location.href = 'verify.php?token=' + encodeURIComponent(text); return; }
                if (/^CV-\d{4}-\d{6}$/.test(text)) {
                    var idInput = document.getElementById('certificate_id');
                    if (idInput && idInput.form) { idInput.value = text; idInput.form.submit(); return; }
                }
                showError('That QR code is not a CertiVault code — try another image or type the Certificate ID.');
            }

            form.addEventListener('submit', function (e) {
                var f = (input.files && input.files[0]) || pending;
                if (!f) { e.preventDefault(); showError('Please choose a QR image first.'); return; }
                var ok = checkFile(f);
                if (ok !== true) { e.preventDefault(); showError(ok); return; }
                // No decode library (or very old browser): let the form post
                // to the server-side fallback, which decodes with PHP.
                if (typeof Html5Qrcode === 'undefined') return;
                e.preventDefault();
                hideError();
                try {
                    new Html5Qrcode('qrFileReader').scanFile(f, false).then(routeText, function () {
                        // Client could not decode it — hand to the server fallback.
                        form.submit();
                    });
                } catch (ex) {
                    form.submit();
                }
            });
        })();
        </script>

        <?php else: ?>
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
        </div>

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
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
