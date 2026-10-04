<?php
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/utils/validators.php';

// If already signed in, send the user straight to their area.
if (isset($_SESSION['user_id']) && isset($_SESSION['role'])) {
    redirect_to_dashboard($_SESSION['role']);
}

$page_title = 'CertiVault — Verifiable digital certificates';
?>
<?php require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">

    <section class="hero">
        <div class="container">
            <p class="eyebrow">Trusted digital credentials</p>
            <h1>Issue, sign, and verify certificates in seconds</h1>
            <p class="hero-sub">CertiVault lets institutions issue tamper-evident digital certificates and lets anyone verify authenticity with a QR code or certificate ID — no account needed.</p>
            <div class="hero-cta">
                <a href="verify.php" class="btn btn-primary">Verify a certificate</a>
                <a href="register_institution.php" class="btn btn-secondary">Register your institution</a>
            </div>
        </div>
    </section>

    <section class="section">
        <div class="container">
            <h2>How it works</h2>
            <div class="steps">
                <div class="card step-card">
                    <div class="step-num">1</div>
                    <h3>Issue</h3>
                    <p>Institutions upload the certificate file and student details; the system computes a SHA-256 digest.</p>
                </div>
                <div class="card step-card">
                    <div class="step-num">2</div>
                    <h3>Sign</h3>
                    <p>The digest is signed with the institution's RSA private key, and a unique QR token is generated.</p>
                </div>
                <div class="card step-card">
                    <div class="step-num">3</div>
                    <h3>Verify</h3>
                    <p>Anyone can scan the QR or enter the certificate ID to get an instant VALID, TAMPERED, REVOKED or EXPIRED verdict.</p>
                </div>
            </div>
        </div>
    </section>

    <section class="section section-alt">
        <div class="container">
            <h2>Built for trust</h2>
            <div class="feature-grid">
                <div class="card feature"><h3>SHA-256 tamper detection</h3><p>Every file is hashed at issuance; any byte change is caught on verification.</p></div>
                <div class="card feature"><h3>RSA digital signatures</h3><p>Certificates are signed per institution, so forgeries fail authenticity checks.</p></div>
                <div class="card feature"><h3>QR verification</h3><p>Scan to verify instantly — no account, no friction for employers and registrars.</p></div>
                <div class="card feature"><h3>Revocation &amp; versioning</h3><p>Bad credentials can be revoked, and corrections supersede old versions transparently.</p></div>
                <div class="card feature"><h3>Audit logs</h3><p>Every verification attempt is logged with timestamp, verdict and source IP.</p></div>
            </div>
        </div>
    </section>

    <section class="section">
        <div class="container narrow">
            <h2>Quick verify</h2>
            <form method="POST" action="verify.php" class="card">
                <div class="form-group">
                    <label for="certificate_id">Certificate ID</label>
                    <input type="text" id="certificate_id" name="certificate_id" placeholder="CV-YYYY-NNNNNN" data-validate="required|certid" required>
                </div>
                <button type="submit" class="btn btn-primary">Verify</button>
            </form>
        </div>
    </section>

</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/validation.js"></script>
</body>
</html>
