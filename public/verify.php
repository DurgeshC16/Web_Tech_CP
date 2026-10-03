<?php
// public/verify.php — Public Verification Engine (no login required)
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/services/CryptoService.php';

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

// ── Verification Engine ────────────────────────────────────────────────
if ($query_type !== null) {

    // Step 1 – Existence check
    if ($query_type === 'token') {
        $stmt = $db->prepare('
            SELECT c.*, i.name AS institution_name, i.public_key,
                   s.full_name AS student_name
            FROM certificates c
            JOIN institutions i ON c.institution_id = i.id
            JOIN students     s ON c.student_id     = s.id
            WHERE c.qr_token = :val
            LIMIT 1
        ');
        $stmt->execute(['val' => $query_value]);
    } else {
        $stmt = $db->prepare('
            SELECT c.*, i.name AS institution_name, i.public_key,
                   s.full_name AS student_name
            FROM certificates c
            JOIN institutions i ON c.institution_id = i.id
            JOIN students     s ON c.student_id     = s.id
            WHERE c.certificate_id = :val
            LIMIT 1
        ');
        $stmt->execute(['val' => $query_value]);
    }

    $cert = $stmt->fetch();

    if (!$cert) {
        // ──────────────────────── INVALID ────────────────────────
        $verdict = 'INVALID';
        $detail  = 'No certificate found matching the provided identifier.';
    } else {
        // Step 2 – Integrity: recompute SHA-256 hash and compare
        $filePath = __DIR__ . '/../private_data/uploads/' . $cert['file_path'];
        $hashOK   = false;

        if (file_exists($filePath) && !empty($cert['sha256_hash'])) {
            $certData = [
                'certificate_id' => $cert['certificate_id'],
                'institution_id' => $cert['institution_id'],
                'student_id'     => $cert['student_id'],
                'title'          => $cert['title'],
                'issue_date'     => $cert['issue_date'],
                'expiry_date'    => $cert['expiry_date'],
            ];
            $recomputedHash = CryptoService::computeCertificateHash($certData, $filePath);
            $hashOK = hash_equals($cert['sha256_hash'], $recomputedHash);
        }

        if (!$hashOK) {
            // ──────────────────── TAMPERED (hash) ────────────────────
            $verdict = 'TAMPERED';
            $detail  = 'Data integrity check failed — the certificate data or file has been altered since issuance.';
        } else {
            // Step 3 – Authenticity: verify RSA signature
            $sigOK = false;
            if (!empty($cert['digital_signature']) && !empty($cert['public_key'])) {
                $sigOK = CryptoService::verifyCertificateSignature(
                    $recomputedHash,
                    $cert['digital_signature'],
                    $cert['public_key']
                );
            }

            if (!$sigOK) {
                // ──────────────── TAMPERED (signature) ────────────────
                $verdict = 'TAMPERED';
                $detail  = 'Digital signature verification failed — the certificate may be forged or the issuing institution\'s key does not match.';
            } else {
                // Step 4 – Expiry check
                if (!empty($cert['expiry_date']) && strtotime($cert['expiry_date']) < strtotime('today')) {
                    // ──────────────────── EXPIRED ─────────────────────
                    $verdict = 'EXPIRED';
                    $detail  = 'This certificate expired on ' . date('F j, Y', strtotime($cert['expiry_date'])) . '.';
                } elseif ($cert['status'] === 'revoked') {
                    // Step 5 – Revocation check
                    // ──────────────────── REVOKED ─────────────────────
                    $verdict = 'REVOKED';
                    $detail  = 'This certificate has been revoked by the issuing institution.';
                } elseif ($cert['status'] === 'superseded') {
                    // Step 6 – Supersession check
                    // ──────────────────── SUPERSEDED ──────────────────
                    $verdict = 'SUPERSEDED';
                    $detail  = 'This certificate has been superseded by a newer corrected version.';
                    if (!empty($cert['superseded_by_id'])) {
                        $sbStmt = $db->prepare('SELECT certificate_id, qr_token FROM certificates WHERE id = :id');
                        $sbStmt->execute(['id' => $cert['superseded_by_id']]);
                        $superseded_by = $sbStmt->fetch();
                    }
                } else {
                    // ──────────────────── VALID ───────────────────────
                    $verdict = 'VALID';
                    $detail  = 'All integrity, authenticity, expiry, and status checks passed.';
                }
            }
        }
    }

    // ── Audit Logging ─────────────────────────────────────────────────
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $logStmt = $db->prepare('
        INSERT INTO verification_logs
            (query_type, query_value, certificate_id_found, result, detail, verifier_ip)
        VALUES
            (:qt, :qv, :cid, :res, :det, :ip)
    ');
    $logStmt->execute([
        'qt'  => $query_type,
        'qv'  => $query_value,
        'cid' => $cert ? $cert['certificate_id'] : null,
        'res' => $verdict,
        'det' => $detail,
        'ip'  => $ip,
    ]);
    
    // ── Anti-Enumeration Awareness ────────────────────────────────────
    // Log a server-side warning if this IP has made many distinct lookups
    // recently. This is awareness/forensics, not a blocker — sufficient
    // for a college project, would need a proper rate limiter in production.
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
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Certificate - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <?php require_once __DIR__ . '/../src/partials/head_fonts.php'; ?>
</head>
<body>
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
                <input type="text" id="certificate_id" name="certificate_id" placeholder="CV-YYYY-NNNNNN" required>
            </div>
            <button type="submit" class="btn btn-primary" style="width:100%;">Verify</button>
        </form>

        <?php else: ?>
        <!-- ── Verdict Display ───────────────────────────────────── -->
        <div style="text-align:center; margin-top:20px;">
            <div class="verdict-seal verdict-seal-<?= strtolower($verdict) ?>">
                <?= $verdict ?>
            </div>
            <p class="verdict-detail" style="text-align:center;"><?= htmlspecialchars($detail) ?></p>
        </div>

        <?php if (in_array($verdict, ['VALID', 'EXPIRED'])): ?>
        <!-- Show certificate details only for VALID / EXPIRED -->
        <div class="card" style="margin-top:25px;">
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
</body>
</html>
