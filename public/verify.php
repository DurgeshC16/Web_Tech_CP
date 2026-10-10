<?php
// public/verify.php — Public Verification Engine (no login required)
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/utils/validators.php';
require_once __DIR__ . '/../src/utils/helpers.php';

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

// ── Pre-flight format check ────────────────────────────────────────────
// Reject malformed identifiers BEFORE hitting the database.
if ($query_type !== null) {
    $well_formed = true;
    if ($query_type === 'token') {
        $well_formed = (bool)preg_match('/^[A-Za-z0-9_-]{43}$/', $query_value);
    } else {
        $well_formed = (v_certificate_id($query_value) === true);
    }
    if (!$well_formed) {
        $verdict = 'INVALID';
        $detail  = 'The provided identifier is malformed. Expected format: '
            . ($query_type === 'token' ? 'a 43-character QR token.' : 'CV-YYYY-NNNNNN.');
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
        : VerificationService::findByCertificateId($db, $query_value);

    if (!$cert) {
        $verdict = 'INVALID';
        $detail  = 'No certificate found matching the provided identifier.';
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
        'qt'  => $query_type,
        // Truncate to 255 so long/hostile input cannot overflow the column
        'qv'  => mb_substr((string)$query_value, 0, 255),
        'cid' => $cert ? $cert['certificate_id'] : null,
        'res' => $verdict,
        'det' => $detail,
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
