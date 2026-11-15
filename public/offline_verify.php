<?php
// public/offline_verify.php — zero-trust verification of a downloaded
// CertiVault credential (JSON). Every check runs in the visitor's browser
// with Web Crypto (assets/js/credential-verify.js); the server only serves
// this page and, optionally, the public key directory / live status.
require_once __DIR__ . '/../src/utils/helpers.php';
$page_title = 'Verify a Credential File - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main">
    <div class="container shell-narrow">
        <h2 class="text-center">Verify a credential file — in your browser</h2>
        <p class="text-muted text-center">
            Load a <code>certivault-credential-*.json</code> file. Your browser recomputes the
            fingerprint and checks the institution's RSA signature itself (Web Crypto) — you do not
            have to trust this server's verdict. Nothing you load is uploaded.
        </p>

        <form class="card" id="credentialForm" novalidate>
            <div class="form-group">
                <label for="credentialFile">Credential file (.json)</label>
                <input type="file" id="credentialFile" accept=".json,application/json">
            </div>
            <div class="form-group">
                <label for="credentialText">…or paste the JSON</label>
                <textarea id="credentialText" rows="5" spellcheck="false" placeholder='{"format":"certivault-credential-v1", …}'></textarea>
            </div>
            <div class="form-group">
                <label for="certificateFile">Certificate file (optional — proves your PDF/image is the signed original)</label>
                <input type="file" id="certificateFile" accept=".pdf,.png,.jpg,.jpeg">
            </div>
            <div class="form-group">
                <label for="trustedFingerprint">Trusted key fingerprint (optional — e.g. from the institution's website)</label>
                <input type="text" id="trustedFingerprint" placeholder="AB:CD:EF:…" spellcheck="false">
            </div>
            <label class="checkbox-row">
                <input type="checkbox" id="useDirectory" checked>
                Also compare the key with this CertiVault server's public key directory and check the live status
            </label>
            <button type="submit" class="btn btn-primary btn-block">Verify in my browser</button>
        </form>

        <section id="credentialResult" class="card" hidden aria-live="polite">
            <h3 id="credentialHeadline" class="card-title"></h3>
            <dl id="credentialSummary" class="credential-summary"></dl>
            <ul id="credentialChecks" class="check-list"></ul>
            <p class="text-muted small">
                Prefer the command line? The same signature check with OpenSSL is described in
                <code>docs/05_FEATURES_AND_USER_GUIDE.md</code>.
            </p>
        </section>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/credential-verify.js"></script>
</body>
</html>
