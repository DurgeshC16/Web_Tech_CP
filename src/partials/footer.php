<?php
// src/partials/footer.php — shared footer: brand blurb, link columns and
// the cookie note. Variables are prefixed $cv_ftr_ (runs in page scope).
$cv_ftr_role = $_SESSION['role'] ?? null;
?>
<footer class="site-footer" role="contentinfo">
    <div class="footer-inner">
        <div class="footer-grid">
            <div class="footer-brand">
                <a href="index.php" class="wordmark" aria-label="CertiVault home">
                    <svg class="wordmark-seal" width="30" height="30" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
                        <defs>
                            <linearGradient id="cvFooterGrad" x1="0" y1="0" x2="1" y2="1">
                                <stop offset="0" stop-color="#4f46e5"/>
                                <stop offset=".55" stop-color="#7c3aed"/>
                                <stop offset="1" stop-color="#0891b2"/>
                            </linearGradient>
                        </defs>
                        <rect width="64" height="64" rx="16" fill="url(#cvFooterGrad)"/>
                        <path d="M32 12l16 6v12c0 10.5-6.8 18.6-16 22-9.2-3.4-16-11.5-16-22V18z" fill="none" stroke="#fff" stroke-width="3.5" stroke-linejoin="round"/>
                        <path d="M24.5 32.5l5.5 5.5 10-11" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    <span class="wordmark-text">CertiVault</span>
                </a>
                <p>Tamper-evident digital certificates, signed with each institution's own key and verifiable by anyone in seconds — by QR code, certificate ID or the file itself.</p>
            </div>
            <div class="footer-col">
                <h2>Verify</h2>
                <nav class="footer-links" aria-label="Verification">
                    <a href="verify.php">Verify a certificate</a>
                    <a href="offline_verify.php">Check a credential file</a>
                    <?php if (defined('CERTIFICATE_TRANSPARENCY_ENABLED') && CERTIFICATE_TRANSPARENCY_ENABLED): ?><a href="institutions.php">Institution keys</a><?php endif; ?>
                </nav>
            </div>
            <div class="footer-col">
                <h2>Account</h2>
                <nav class="footer-links" aria-label="Account">
                    <?php if (!$cv_ftr_role): ?>
                        <a href="login.php">Login</a>
                        <a href="register_student.php">Register as a student</a>
                        <a href="register_institution.php">Register your institution</a>
                    <?php else: ?>
                        <a href="index.php">My dashboard</a>
                        <a href="change_password.php">Change password</a>
                        <a href="two_factor.php">Two-factor auth</a>
                    <?php endif; ?>
                </nav>
            </div>
            <div class="footer-col">
                <h2>CertiVault</h2>
                <nav class="footer-links" aria-label="Footer">
                    <a href="index.php">Home</a>
                    <a href="index.php#how-it-works">How it works</a>
                    <a href="index.php#faq">FAQ</a>
                </nav>
            </div>
        </div>
        <div class="footer-bottom">
            <p class="cookie-note">
                <svg width="16" height="16" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M21 12a9 9 0 1 1-9-9 3 3 0 0 0 3 3 3 3 0 0 0 3 3 3 3 0 0 0 3 3zM8.5 9.5h.01M15.5 15.5h.01M10 16h.01M12 12h.01"/></svg>
                This site uses cookies for your login session and preferences.
            </p>
            <p>&copy; <?= date('Y') ?> CertiVault · Signed with RSA, hashed with SHA-256.</p>
        </div>
    </div>
</footer>
