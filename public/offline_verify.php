<?php
// public/offline_verify.php — zero-trust verification of a downloaded
// CertiVault credential (JSON). Every check runs in the visitor's browser
// with Web Crypto (assets/js/credential-verify.js); the server only serves
// this page and, optionally, the public key directory / live status.
require_once __DIR__ . '/../src/config/config.php'; // feature flags for the shared header nav
require_once __DIR__ . '/../src/utils/helpers.php';
$page_title = 'Verify a Credential File - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
// Decorative icon helper (aria-hidden inline SVG).
$ov_icon = static function (string $d): string {
    return '<svg class="sv-ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' . $d . '</svg>';
};
$ov_json   = $ov_icon('<path d="M8 4H7a2 2 0 0 0-2 2v4l-2 2 2 2v4a2 2 0 0 0 2 2h1M16 4h1a2 2 0 0 1 2 2v4l2 2-2 2v4a2 2 0 0 1-2 2h-1"/>');
$ov_file   = $ov_icon('<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M12 18v-6M9.5 14.5 12 12l2.5 2.5"/>');
$ov_shield = $ov_icon('<path d="M12 3 5 6v5c0 4.4 3 8.3 7 10 4-1.7 7-5.6 7-10V6z"/><path d="m9 12 2 2 4-4"/>');
$ov_lock   = $ov_icon('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>');
$ov_key    = $ov_icon('<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l3 3M14 9l2 2"/>');
$ov_cpu    = $ov_icon('<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>');
?>
<main id="main" class="sv-main">
    <div class="container verify-shell">
        <header class="sv-hero sv-hero-compact">
            <p class="sv-eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span> Zero-trust · runs entirely in your browser</p>
            <h1 class="sv-hero-title">Verify a credential file <span class="hero-highlight">— in your browser</span></h1>
            <p class="sv-hero-sub">
                Load a <code>certivault-credential-*.json</code> file. Your browser recomputes the
                fingerprint and checks the institution's RSA signature itself (Web Crypto) — you do not
                have to trust this server's verdict. Nothing you load is uploaded.
            </p>
            <ul class="sv-trust-chips">
                <li><?= $ov_cpu ?>Web Crypto</li>
                <li><?= $ov_lock ?>Nothing uploaded</li>
                <li><?= $ov_key ?>Key directory check</li>
            </ul>
            <svg class="sv-hero-art" viewBox="0 0 120 120" aria-hidden="true" focusable="false"><path d="M60 8 20 24v30c0 26 17 47 40 58 23-11 40-32 40-58V24z" fill="none" stroke="currentColor" stroke-width="3"/><path d="m42 60 13 13 25-26" fill="none" stroke="currentColor" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </header>

        <div class="sv-body">
            <form class="sv-form cred-form" id="credentialForm" novalidate>
                <div class="form-group">
                    <label for="credentialFile">Credential file (.json)</label>
                    <div class="sv-dropzone">
                        <span class="sv-drop-icon" aria-hidden="true"><?= $ov_json ?></span>
                        <span class="sv-drop-title">Drop the credential JSON here</span>
                        <span class="sv-drop-sub">or <span class="sv-drop-link">browse your files</span> · read locally, never uploaded</span>
                        <input type="file" id="credentialFile" accept=".json,application/json">
                        <span class="sv-drop-file" aria-live="polite" hidden></span>
                    </div>
                </div>
                <div class="sv-or" aria-hidden="true"><span>or</span></div>
                <div class="form-group">
                    <label for="credentialText">…or paste the JSON</label>
                    <textarea id="credentialText" class="cred-textarea" rows="5" spellcheck="false" placeholder='{"format":"certivault-credential-v1", …}'></textarea>
                </div>

                <details class="sv-advanced" open>
                    <summary>Extra checks (optional)</summary>
                    <div class="form-group">
                        <label for="certificateFile">Certificate file (optional — proves your PDF/image is the signed original)</label>
                        <div class="sv-dropzone sv-dropzone-sm">
                            <span class="sv-drop-icon" aria-hidden="true"><?= $ov_file ?></span>
                            <span class="sv-drop-title">Drop the certificate PDF or image</span>
                            <span class="sv-drop-sub">or <span class="sv-drop-link">browse</span> · hashed locally with SHA-256</span>
                            <input type="file" id="certificateFile" accept=".pdf,.png,.jpg,.jpeg">
                            <span class="sv-drop-file" aria-live="polite" hidden></span>
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="trustedFingerprint">Trusted key fingerprint (optional — e.g. from the institution's website)</label>
                        <input type="text" id="trustedFingerprint" class="mono" placeholder="AB:CD:EF:…" spellcheck="false">
                    </div>
                    <label class="checkbox-row">
                        <input type="checkbox" id="useDirectory" checked>
                        Also compare the key with this CertiVault server's public key directory and check the live status
                    </label>
                </details>
                <button type="submit" class="btn btn-primary btn-block btn-lg sv-submit"><?= $ov_shield ?><span>Verify in my browser</span></button>
            </form>

            <section id="credentialResult" class="card cred-result" hidden aria-live="polite">
                <div class="cred-result-head">
                    <span class="cred-badge" aria-hidden="true">
                        <svg class="cred-badge-pass" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M5 13l4 4L19 7"/></svg>
                        <svg class="cred-badge-warn" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M12 8v5M12 17h.01"/></svg>
                        <svg class="cred-badge-fail" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M7 7l10 10M17 7 7 17"/></svg>
                    </span>
                    <h2 id="credentialHeadline" class="card-title"></h2>
                </div>
                <dl id="credentialSummary" class="credential-summary"></dl>
                <ul id="credentialChecks" class="check-list"></ul>
                <p class="text-muted small m-0">
                    Prefer the command line? The same signature check with OpenSSL is described in
                    <code>docs/05_FEATURES_AND_USER_GUIDE.md</code>.
                </p>
            </section>

            <ol class="sv-how" aria-label="What your browser checks">
                <li data-reveal data-reveal-delay="1"><span class="sv-how-num">1</span><strong>Fingerprint</strong><span>The canonical SHA-256 digest is recomputed.</span></li>
                <li data-reveal data-reveal-delay="2"><span class="sv-how-num">2</span><strong>Signature</strong><span>The institution's RSA signature is checked with Web Crypto.</span></li>
                <li data-reveal data-reveal-delay="3"><span class="sv-how-num">3</span><strong>Key &amp; status</strong><span>Key compared with the directory; live revocation status.</span></li>
            </ol>
            <p class="sv-more-links">
                <a href="verify.php"><?= $ov_shield ?>Verify by ID, link or QR</a>
                <a href="institutions.php"><?= $ov_key ?>Institution public keys</a>
            </p>
        </div>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/credential-verify.js"></script>
</body>
</html>
