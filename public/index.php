<?php
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/utils/validators.php';
require_once __DIR__ . '/../src/services/GuestQuotaService.php';

// If already signed in, send the user straight to their area.
if (isset($_SESSION['user_id']) && isset($_SESSION['role'])) {
    redirect_to_dashboard($_SESSION['role']);
}

// Guest free-verification counter for the quick-verify box (read-only;
// the quick verify posts to verify.php, which enforces and records the
// quota). A DB problem must never break the landing page.
$index_quota = null;
try {
    $index_quota = GuestQuotaService::check(Database::getInstance(), $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0', $_SESSION);
} catch (Throwable $quotaError) {
    error_log('[CertiVault] index.php guest quota status unavailable: ' . $quotaError->getMessage());
}

// Two cheap aggregate counts for the stats strip (prepared, COUNT(*) only).
// On any DB problem the strip falls back to static facts.
$index_stats = ['certificates' => null, 'institutions' => null];
try {
    $index_db = Database::getInstance();
    $index_st = $index_db->prepare('SELECT COUNT(*) FROM certificates');
    $index_st->execute();
    $index_stats['certificates'] = (int)$index_st->fetchColumn();
    $index_st = $index_db->prepare('SELECT COUNT(*) FROM institutions WHERE status = :status');
    $index_st->execute(['status' => 'approved']);
    $index_stats['institutions'] = (int)$index_st->fetchColumn();
} catch (Throwable $statsError) {
    error_log('[CertiVault] index.php stats unavailable: ' . $statsError->getMessage());
}
$index_limit = is_array($index_quota) && isset($index_quota['limit']) ? (int)$index_quota['limit'] : GuestQuotaService::limit();

$page_title = 'CertiVault — Verifiable digital certificates';
?>
<?php require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main" class="landing">

    <!-- ── Hero + quick verify ─────────────────────────────────────── -->
    <section class="hero hero-gradient" aria-labelledby="heroTitle">
        <div class="hero-orbs" aria-hidden="true"><span></span><span></span><span></span></div>
        <div class="hero-grid-lines" aria-hidden="true"></div>
        <div class="wrap hero-grid">
            <div class="hero-copy" data-reveal>
                <p class="eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span>Trusted digital credentials</p>
                <h1 id="heroTitle">Issue, sign, and verify certificates <span class="hero-highlight">in seconds</span></h1>
                <p class="hero-sub">CertiVault lets institutions issue tamper-evident digital certificates and lets anyone verify authenticity with a QR code or certificate ID — no account needed.</p>
                <div class="hero-cta">
                    <a href="verify.php" class="btn btn-light btn-lg">
                        <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z M8.5 12l2.5 2.5 4.5-5"/></svg>
                        Verify a certificate
                    </a>
                    <a href="register_institution.php" class="btn btn-outline-light btn-lg">Register your institution</a>
                </div>
                <ul class="hero-trust">
                    <li><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" d="M5 12.5l4.5 4.5L19 7.5"/></svg>No account to verify</li>
                    <li><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" d="M5 12.5l4.5 4.5L19 7.5"/></svg>RSA-signed per institution</li>
                    <li><svg viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" d="M5 12.5l4.5 4.5L19 7.5"/></svg>Privacy-preserving checks</li>
                </ul>
            </div>

            <div class="hero-panel" data-reveal="zoom" data-reveal-delay="2">
                <span class="hero-float hero-float-a" aria-hidden="true">
                    <span class="hero-float-dot"><svg viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" d="M5 12.5l4.5 4.5L19 7.5"/></svg></span>VALID · signature OK
                </span>
                <div class="quick-verify">
                    <div class="quick-verify-head">
                        <span class="qv-icon" aria-hidden="true">
                            <svg viewBox="0 0 24 24" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7V5a1 1 0 0 1 1-1h2M17 4h2a1 1 0 0 1 1 1v2M20 17v2a1 1 0 0 1-1 1h-2M7 20H5a1 1 0 0 1-1-1v-2"/><path d="M8 12h8"/></g></svg>
                        </span>
                        <div>
                            <h2>Smart verify</h2>
                            <p>Paste any certificate ID, QR token or link.</p>
                        </div>
                    </div>
                    <form method="POST" action="verify.php" class="card quick-verify-form" id="smartVerifyFormIndex" data-loading>
                        <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                        <div class="form-group">
                            <label for="smart_id">Certificate ID, QR token or verification link</label>
                            <input type="text" id="smart_id" name="smart_id" placeholder="Paste an ID (any format), a QR token, or a verification URL">
                            <small>Any format works, e.g. CV-2026-000001, cv20260001, a 43-character QR token, or a full verify link.</small>
                        </div>
                        <button type="submit" class="btn btn-primary btn-block btn-lg">Smart Verify</button>
                    </form>
                    <?php if (is_array($index_quota) && !empty($index_quota['enabled']) && empty($index_quota['exempt']) && (int)$index_quota['remaining'] === 0): ?>
                        <?= GuestQuotaService::renderLimitNotice($index_quota) ?>
                    <?php elseif (is_array($index_quota)): ?>
                        <?= GuestQuotaService::renderCounter($index_quota) ?>
                    <?php endif; ?>
                    <p class="qv-foot">
                        Need to verify by file (PDF/PNG/JPG) or external issuers? Use the
                        <a href="verify.php">full Smart Verify panel</a>.
                    </p>
                </div>
                <span class="hero-float hero-float-b" aria-hidden="true">
                    <span class="hero-float-dot"><svg viewBox="0 0 24 24"><g fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></g></svg></span>SHA-256 fingerprint matched
                </span>
            </div>
        </div>
    </section>

    <!-- ── Stats strip ─────────────────────────────────────────────── -->
    <section class="stats-strip" aria-label="CertiVault at a glance">
        <div class="wrap">
            <div class="stats-strip-inner" data-reveal>
                <?php if ($index_stats['certificates'] !== null): ?>
                    <div class="stat"><span class="stat-num" data-count-to="<?= (int)$index_stats['certificates'] ?>"><?= number_format((int)$index_stats['certificates']) ?></span><span class="stat-label">Certificates issued</span></div>
                <?php else: ?>
                    <div class="stat"><span class="stat-num">SHA-256</span><span class="stat-label">File fingerprint</span></div>
                <?php endif; ?>
                <?php if ($index_stats['institutions'] !== null): ?>
                    <div class="stat"><span class="stat-num" data-count-to="<?= (int)$index_stats['institutions'] ?>"><?= number_format((int)$index_stats['institutions']) ?></span><span class="stat-label">Issuing institutions</span></div>
                <?php else: ?>
                    <div class="stat"><span class="stat-num">RSA</span><span class="stat-label">Per-institution keys</span></div>
                <?php endif; ?>
                <div class="stat"><span class="stat-num" data-count-to="6">6</span><span class="stat-label">Clear verdicts</span></div>
                <div class="stat"><span class="stat-num">0</span><span class="stat-label">Accounts needed to verify</span></div>
            </div>
        </div>
    </section>

    <!-- ── How it works ────────────────────────────────────────────── -->
    <section class="section" id="how-it-works" aria-labelledby="howTitle">
        <div class="wrap">
            <div class="section-head" data-reveal>
                <p class="eyebrow">Three steps</p>
                <h2 id="howTitle">How it works</h2>
                <p>From upload to an instant verdict — every certificate is bound to its exact file and its issuer's key.</p>
            </div>
            <div class="steps">
                <div class="steps-line" aria-hidden="true"></div>
                <div class="card step-card card-hover" data-reveal data-reveal-delay="1">
                    <svg class="step-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M12 17v-6M9 14l3-3 3 3"/></g></svg>
                    <div class="step-num">1</div>
                    <h3>Issue</h3>
                    <p>Institutions upload the certificate file and student details; the system computes a SHA-256 digest.</p>
                </div>
                <div class="card step-card card-hover" data-reveal data-reveal-delay="2">
                    <svg class="step-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2"/></g></svg>
                    <div class="step-num">2</div>
                    <h3>Sign</h3>
                    <p>The digest is signed with the institution's RSA private key, and a unique QR token is generated.</p>
                </div>
                <div class="card step-card card-hover" data-reveal data-reveal-delay="3">
                    <svg class="step-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></g></svg>
                    <div class="step-num">3</div>
                    <h3>Verify</h3>
                    <p>Anyone can scan the QR or enter the certificate ID to get an instant VALID, TAMPERED, REVOKED or EXPIRED verdict.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- ── Features ────────────────────────────────────────────────── -->
    <section class="section section-alt" aria-labelledby="featuresTitle">
        <div class="wrap">
            <div class="section-head" data-reveal>
                <p class="eyebrow">Built for trust</p>
                <h2 id="featuresTitle">Everything a verifier needs — nothing to install</h2>
                <p>Cryptography does the heavy lifting, so a certificate is trusted because the maths checks out, not because a web page says so.</p>
            </div>
            <div class="feature-grid">
                <article class="card feature card-hover" data-tilt data-reveal data-reveal-delay="1">
                    <span class="feature-icon" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></g></svg></span>
                    <h3>Cryptographic signatures</h3>
                    <p>Every file is hashed with SHA-256 at issuance and signed with the institution's own RSA key — any byte change or forgery fails.</p>
                </article>
                <article class="card feature card-hover" data-tilt data-reveal data-reveal-delay="2">
                    <span class="feature-icon" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20h.01M17 20h4v-3"/></g></svg></span>
                    <h3>QR + Smart Verify</h3>
                    <p>Scan with the camera, upload the PDF or image, or paste any ID format — Smart Verify works out what you gave it.</p>
                    <a class="feature-link" href="verify.php">Try Smart Verify <span aria-hidden="true">&rarr;</span></a>
                </article>
                <article class="card feature card-hover" data-tilt data-reveal data-reveal-delay="3">
                    <span class="feature-icon" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.9 17.9A10 10 0 0 1 12 20c-7 0-10-8-10-8a18 18 0 0 1 5-5.9M9.9 4.2A9 9 0 0 1 12 4c7 0 10 8 10 8a18 18 0 0 1-2.2 3.2M2 2l20 20"/></g></svg></span>
                    <h3>Privacy mode</h3>
                    <p>Hash the file in your browser and send only the fingerprint — the document itself never leaves your device.</p>
                </article>
                <article class="card feature card-hover" data-tilt data-reveal data-reveal-delay="1">
                    <span class="feature-icon" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h4"/></g></svg></span>
                    <h3>Trust score &amp; PDF report</h3>
                    <p>Each verdict comes with an explainable trust score and a downloadable PDF verification report for your records.</p>
                </article>
                <article class="card feature card-hover" data-tilt data-reveal data-reveal-delay="2">
                    <span class="feature-icon" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12a8 8 0 0 1 14-5.3L20 9M20 4v5h-5M20 12a8 8 0 0 1-14 5.3L4 15M4 20v-5h5"/></g></svg></span>
                    <h3>Revocation &amp; supersession</h3>
                    <p>Bad credentials can be revoked instantly, and corrections supersede old versions with a transparent version history.</p>
                </article>
                <article class="card feature card-hover" data-tilt data-reveal data-reveal-delay="3">
                    <span class="feature-icon" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="19" r="2"/><path d="M12 7v4M12 11l-6 6M12 11l6 6"/></g></svg></span>
                    <h3>Transparency log</h3>
                    <p>Issuance can be committed to a signed Merkle log with inclusion proofs, and every verification attempt is audit-logged.</p>
                </article>
                <article class="card feature card-hover" data-tilt data-reveal data-reveal-delay="1">
                    <span class="feature-icon" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><path d="M9 12h6M12 9v6"/></g></svg></span>
                    <h3>Offline credential check</h3>
                    <p>Re-check a signed credential file entirely in your browser with Web Crypto — no need to trust our server.</p>
                    <a class="feature-link" href="offline_verify.php">Check a credential file <span aria-hidden="true">&rarr;</span></a>
                </article>
                <article class="card feature card-hover" data-tilt data-reveal data-reveal-delay="2">
                    <span class="feature-icon" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M8 13h8M8 16h5"/></g></svg></span>
                    <h3>Bulk issuance</h3>
                    <p>Issue hundreds of signed certificates from one CSV, with a preview of every row before anything is committed.</p>
                </article>
                <article class="card feature card-hover" data-tilt data-reveal data-reveal-delay="3">
                    <span class="feature-icon" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="6" y="2" width="12" height="20" rx="2"/><path d="M10 18h4M9.5 10l2 2 3.5-3.5"/></g></svg></span>
                    <h3>Two-factor authentication</h3>
                    <p>Protect admin and student accounts with authenticator-app codes and one-time recovery codes.</p>
                </article>
            </div>
        </div>
    </section>

    <!-- ── Audiences ───────────────────────────────────────────────── -->
    <section class="section" aria-labelledby="audienceTitle">
        <div class="wrap">
            <div class="section-head" data-reveal>
                <p class="eyebrow">Made for everyone in the chain</p>
                <h2 id="audienceTitle">One platform, three happy sides</h2>
            </div>
            <div class="audience-grid">
                <article class="card audience-card card-hover" data-reveal data-reveal-delay="1">
                    <span class="pill audience-tag">For students</span>
                    <h3>Own your achievements</h3>
                    <ul>
                        <li>All your certificates in one dashboard</li>
                        <li>Share a verification link or QR in one click</li>
                        <li>Download a portable, signed credential file</li>
                    </ul>
                    <div class="card-actions">
                        <a href="register_student.php" class="btn btn-primary">Create a free account</a>
                    </div>
                </article>
                <article class="card audience-card card-hover" data-reveal data-reveal-delay="2">
                    <span class="pill audience-tag">For institutions</span>
                    <h3>Issue credentials nobody can fake</h3>
                    <ul>
                        <li>Your own RSA signing key, with rotation</li>
                        <li>Single and bulk issuance, revoke or supersede</li>
                        <li>Audit logs and verification analytics</li>
                    </ul>
                    <div class="card-actions">
                        <a href="register_institution.php" class="btn btn-primary">Register your institution</a>
                    </div>
                </article>
                <article class="card audience-card card-hover" data-reveal data-reveal-delay="3">
                    <span class="pill audience-tag">For employers &amp; verifiers</span>
                    <h3>Know in seconds, not days</h3>
                    <ul>
                        <li>No account, no API keys, no waiting</li>
                        <li>Scan a QR, upload the PDF or paste an ID</li>
                        <li>Clear verdict with a downloadable report</li>
                    </ul>
                    <div class="card-actions">
                        <a href="verify.php" class="btn btn-primary">Verify a certificate</a>
                        <a href="offline_verify.php" class="btn btn-secondary">Check a file</a>
                    </div>
                </article>
            </div>
        </div>
    </section>

    <!-- ── FAQ ─────────────────────────────────────────────────────── -->
    <section class="section section-alt" id="faq" aria-labelledby="faqTitle">
        <div class="wrap">
            <div class="section-head" data-reveal>
                <p class="eyebrow">Questions</p>
                <h2 id="faqTitle">Frequently asked</h2>
            </div>
            <div class="faq" data-reveal>
                <details>
                    <summary>Do I need an account to verify a certificate?</summary>
                    <p>No. Anyone can verify by scanning the QR code, pasting the certificate ID or link, or uploading the certificate file.<?php if ($index_limit > 0): ?> Guests get <?= (int)$index_limit ?> free verification<?= $index_limit === 1 ? '' : 's' ?> per day; signed-in users verify without a limit.<?php endif; ?></p>
                </details>
                <details>
                    <summary>What do the verdicts mean?</summary>
                    <p><strong>VALID</strong> — authentic and current. <strong>TAMPERED</strong> — the file or record no longer matches its signature. <strong>EXPIRED</strong> — authentic but past its expiry date. <strong>REVOKED</strong> — withdrawn by the issuer. <strong>SUPERSEDED</strong> — replaced by a corrected version. <strong>INVALID</strong> — no matching certificate was found.</p>
                </details>
                <details>
                    <summary>Does my document get uploaded when I verify a file?</summary>
                    <p>Not in privacy mode: your browser computes the SHA-256 fingerprint (and reads the QR code) locally, and only that fingerprint is sent for checking.</p>
                </details>
                <details>
                    <summary>How can I be sure the server itself is honest?</summary>
                    <p>Download the signed credential file and check it on the offline credential page — the signature and key fingerprint are verified in your browser with Web Crypto, and can also be checked with OpenSSL.</p>
                </details>
                <details>
                    <summary>What happens when a certificate has a mistake?</summary>
                    <p>The institution issues a corrected version that supersedes the original. Verifying the old one shows SUPERSEDED and points to the current version, so nothing is silently rewritten.</p>
                </details>
            </div>
        </div>
    </section>

    <!-- ── Final CTA ───────────────────────────────────────────────── -->
    <section class="section" aria-labelledby="ctaTitle">
        <div class="wrap">
            <div class="cta-band" data-reveal="zoom">
                <div class="hero-orbs" aria-hidden="true"><span></span><span></span><span></span></div>
                <h2 id="ctaTitle">Ready to put trust on autopilot?</h2>
                <p>Verify a certificate right now, or bring your institution on board and start issuing signed credentials today.</p>
                <div class="hero-cta">
                    <a href="verify.php" class="btn btn-light btn-lg">Verify a certificate</a>
                    <a href="register_institution.php" class="btn btn-outline-light btn-lg">Register your institution</a>
                </div>
            </div>
        </div>
    </section>

</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/validation.js"></script>
</body>
</html>
