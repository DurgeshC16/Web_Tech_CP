/*
 * public/assets/js/smart-verify.js — Smart Verify enhancements (verify.php).
 *
 * Progressive enhancement only: the form works without JavaScript and the
 * SERVER always decides the verdict. This script adds:
 *   1. Camera QR scanning (html5-qrcode, permission asked on click only).
 *   2. Browser QR decoding of the chosen file before submit — PDF pages are
 *      rendered locally with pdf.js, images are scanned directly. Only the
 *      decoded QR TEXT is sent (hidden field smart_qr_text); the server
 *      tries the exact file hash first and uses this text as a fallback.
 *   3. Privacy mode: SHA-256 computed with Web Crypto and only the hash is
 *      sent (smart_hash) — the file never leaves the device.
 *   4. Issuer dropdown → "other link" field toggle.
 *
 * Loaded as an external file (no inline script) so the page can run with a
 * Content-Security-Policy that forbids inline scripts.
 */
(function () {
    'use strict';

    var form = document.getElementById('smartVerifyForm');
    if (!form) { return; } // verdict view — nothing to enhance

    var fileInput = document.getElementById('smart_file');
    var statusEl = document.getElementById('svStatus');
    var cfg = {
        pdfMaxPages: parseInt(form.getAttribute('data-pdf-max-pages'), 10) || 10,
        scanMaxMs: parseInt(form.getAttribute('data-scan-max-ms'), 10) || 20000,
        renderMaxWidth: parseInt(form.getAttribute('data-render-max-width'), 10) || 1600,
        workerSrc: form.getAttribute('data-pdf-worker') || 'assets/js/vendor/pdf.worker.min.js',
        pdfSrc: form.getAttribute('data-pdf-lib') || 'assets/js/vendor/pdf.min.js'
    };

    function setStatus(msg, kind) {
        if (!statusEl) { return; }
        statusEl.textContent = msg || '';
        statusEl.hidden = !msg;
        statusEl.className = 'sv-status' + (kind ? ' sv-status-' + kind : '');
    }

    // ── 4. Issuer dropdown ───────────────────────────────────────────────
    var issuerSel = document.getElementById('issuer');
    var otherGroup = document.getElementById('otherUrlGroup');
    if (issuerSel && otherGroup) {
        var syncOther = function () { otherGroup.hidden = issuerSel.value !== 'other'; };
        issuerSel.addEventListener('change', syncOther);
        syncOther();
    }

    // ── 3. Privacy toggle ────────────────────────────────────────────────
    var privacy = false;
    var toggle = document.getElementById('privacyHashToggle');
    if (toggle) {
        toggle.addEventListener('click', function () {
            privacy = !privacy;
            toggle.setAttribute('aria-pressed', privacy ? 'true' : 'false');
            toggle.classList.toggle('is-active', privacy);
        });
    }

    // ── QR decoding helpers ──────────────────────────────────────────────
    var scratchId = 'svQrScratch';
    function scratchScanner() {
        if (typeof window.Html5Qrcode === 'undefined') { return null; }
        if (!document.getElementById(scratchId)) {
            var d = document.createElement('div');
            d.id = scratchId;
            d.hidden = true;
            document.body.appendChild(d);
        }
        return new window.Html5Qrcode(scratchId, { verbose: false });
    }

    function html5Scan(blob) {
        var scanner = scratchScanner();
        if (!scanner) { return Promise.resolve(null); }
        var file = blob instanceof File ? blob : new File([blob], 'scan.png', { type: blob.type || 'image/png' });
        return scanner.scanFile(file, false).then(function (t) {
            try { scanner.clear(); } catch (e) { /* ignore */ }
            return t || null;
        }).catch(function () { return null; });
    }

    /**
     * Redraw an image on a white canvas (quiet zone added) at `scale`, so the
     * decoder sees crisp, well-sized modules regardless of the source size.
     */
    function rasterize(blob, scale) {
        if (!window.createImageBitmap) { return Promise.resolve(null); }
        return window.createImageBitmap(blob).then(function (bmp) {
            var pad = Math.round(Math.max(bmp.width, bmp.height) * 0.08 * scale) + 8;
            var c = document.createElement('canvas');
            c.width = Math.round(bmp.width * scale) + pad * 2;
            c.height = Math.round(bmp.height * scale) + pad * 2;
            var ctx = c.getContext('2d');
            ctx.fillStyle = '#ffffff';
            ctx.fillRect(0, 0, c.width, c.height);
            ctx.imageSmoothingEnabled = false;
            ctx.drawImage(bmp, pad, pad, bmp.width * scale, bmp.height * scale);
            return new Promise(function (res) { c.toBlob(res, 'image/png'); });
        }).catch(function () { return null; });
    }

    /**
     * Decode a QR from an image File/Blob; resolves to text or null.
     * Escalating attempts: native BarcodeDetector → ZXing (html5-qrcode) on
     * the raw image → padded redraw at 1× → at 2×.
     */
    function decodeImage(blob) {
        var attempts = [];
        if ('BarcodeDetector' in window && window.createImageBitmap) {
            attempts.push(function () {
                return window.createImageBitmap(blob).then(function (bmp) {
                    return new window.BarcodeDetector({ formats: ['qr_code'] }).detect(bmp);
                }).then(function (codes) {
                    return codes && codes.length ? codes[0].rawValue : null;
                });
            });
        }
        attempts.push(function () { return html5Scan(blob); });
        attempts.push(function () { return rasterize(blob, 1).then(function (b) { return b ? html5Scan(b) : null; }); });
        attempts.push(function () { return rasterize(blob, 2).then(function (b) { return b ? html5Scan(b) : null; }); });
        var i = 0;
        function next() {
            if (i >= attempts.length) { return Promise.resolve(null); }
            return Promise.resolve().then(attempts[i++]).catch(function () { return null; })
                .then(function (text) { return text || next(); });
        }
        return next();
    }

    var pdfJsPromise = null;
    function loadPdfJs() {
        if (pdfJsPromise) { return pdfJsPromise; }
        pdfJsPromise = new Promise(function (resolve, reject) {
            function ready() {
                window.pdfjsLib.GlobalWorkerOptions.workerSrc = cfg.workerSrc;
                resolve(window.pdfjsLib);
            }
            if (window.pdfjsLib) { ready(); return; }
            var s = document.createElement('script');
            s.src = cfg.pdfSrc;
            s.onload = function () { window.pdfjsLib ? ready() : reject(new Error('pdf.js missing')); };
            s.onerror = function () { reject(new Error('pdf.js failed to load')); };
            document.head.appendChild(s);
        });
        return pdfJsPromise;
    }

    /** Render each PDF page locally and look for a QR; text or null. */
    function decodePdf(file) {
        var started = Date.now();
        var canvas = document.createElement('canvas');
        return loadPdfJs().then(function (pdfjsLib) {
            return file.arrayBuffer().then(function (buf) {
                return pdfjsLib.getDocument({
                    data: buf,
                    isEvalSupported: false,   // never evaluate embedded JS
                    disableAutoFetch: true,
                    disableStream: true
                }).promise;
            });
        }).then(function (doc) {
            var pages = Math.min(doc.numPages, cfg.pdfMaxPages);
            function scanPage(n) {
                if (n > pages || Date.now() - started > cfg.scanMaxMs) {
                    doc.destroy();
                    return null;
                }
                setStatus('Looking for the QR code on page ' + n + ' of ' + pages + '…', 'busy');
                return doc.getPage(n).then(function (page) {
                    var base = page.getViewport({ scale: 1 });
                    var vp = page.getViewport({ scale: Math.min(cfg.renderMaxWidth / base.width, 3) });
                    canvas.width = Math.max(1, Math.floor(vp.width));
                    canvas.height = Math.max(1, Math.floor(vp.height));
                    var ctx = canvas.getContext('2d');
                    ctx.fillStyle = '#ffffff';
                    ctx.fillRect(0, 0, canvas.width, canvas.height);
                    return page.render({ canvasContext: ctx, viewport: vp }).promise.then(function () {
                        page.cleanup();
                        return new Promise(function (res) { canvas.toBlob(res, 'image/png'); });
                    });
                }).then(function (blob) {
                    return blob ? decodeImage(blob) : null;
                }).then(function (text) {
                    if (text) { doc.destroy(); return text; }
                    return scanPage(n + 1);
                });
            }
            return scanPage(1);
        });
    }

    function decodeFile(file) {
        var name = (file.name || '').toLowerCase();
        if (file.type === 'application/pdf' || /\.pdf$/.test(name)) { return decodePdf(file); }
        if (/^image\//.test(file.type) || /\.(png|jpe?g|webp)$/.test(name)) { return decodeImage(file); }
        return Promise.resolve(null);
    }

    function sha256Hex(file) {
        return file.arrayBuffer().then(function (buf) {
            return window.crypto.subtle.digest('SHA-256', buf);
        }).then(function (digest) {
            var view = new Uint8Array(digest);
            var hex = '';
            for (var i = 0; i < view.length; i++) { hex += ('0' + view[i].toString(16)).slice(-2); }
            return hex;
        });
    }

    function addHidden(name, value) {
        var old = form.querySelector('input[type=hidden][name="' + name + '"]');
        if (old) { old.parentNode.removeChild(old); }
        var h = document.createElement('input');
        h.type = 'hidden';
        h.name = name;
        h.value = value;
        form.appendChild(h);
    }

    // ── 2 + 3. Submit: decode QR (and hash in privacy mode), then post ──
    function onSubmit(e) {
        if (e.defaultPrevented) { return; }            // validation.js blocked it
        var file = fileInput && fileInput.files && fileInput.files[0];
        if (!file) { return; }                          // ID-only lookup: nothing to do
        e.preventDefault();

        var canHash = !!(window.crypto && window.crypto.subtle && file.arrayBuffer);
        var submitBtn = form.querySelector('button[type=submit]');
        if (submitBtn) { submitBtn.disabled = true; }
        setStatus('Reading your file in the browser…', 'busy');

        var timeout = new Promise(function (res) { setTimeout(function () { res(null); }, cfg.scanMaxMs + 2000); });
        Promise.race([decodeFile(file).catch(function () { return null; }), timeout]).then(function (qrText) {
            if (qrText) { addHidden('smart_qr_text', String(qrText).slice(0, 1024)); }
            if (privacy && canHash) {
                setStatus('Hashing your file locally…', 'busy');
                return sha256Hex(file).then(function (hex) {
                    addHidden('smart_hash', hex);
                    fileInput.disabled = true;           // the file itself is never uploaded
                });
            }
            return null;
        }).catch(function () {
            fileInput.disabled = false;                  // fall back to a normal upload
        }).then(function () {
            setStatus('Verifying…', 'busy');
            form.submit();                               // does not re-fire 'submit'
        });
    }
    // Registered after load so validation.js's own submit check runs first.
    window.addEventListener('load', function () { form.addEventListener('submit', onSubmit); });

    // ── 1. Camera scanning ───────────────────────────────────────────────
    var camBtn = document.getElementById('scanQrBtn');
    var camWrap = document.getElementById('qrScanner');
    var camErr = document.getElementById('qrError');
    var camStop = document.getElementById('qrStopBtn');
    if (camBtn && camWrap && camErr && camStop) {
        var cam = null;
        var running = false;
        var showError = function (msg) { camErr.textContent = msg; camErr.hidden = false; };
        var hideError = function () { camErr.textContent = ''; camErr.hidden = true; };

        // Our QR codes encode a verify.php URL or a bare token; any other
        // text goes to the server as an ID candidate (server decides).
        var route = function (text) {
            text = (text || '').trim();
            if (!text) { return null; }
            var m = text.match(/[?&]token=([A-Za-z0-9_\-]{43})(?:&|$)/);
            if (m) { return { type: 'token', value: m[1] }; }
            if (/^[A-Za-z0-9_\-]{43}$/.test(text)) { return { type: 'token', value: text }; }
            return { type: 'id', value: text };
        };
        var stop = function () {
            camBtn.disabled = false;
            if (cam && running) {
                running = false;
                cam.stop().then(function () { cam.clear(); camWrap.hidden = true; })
                    .catch(function () { camWrap.hidden = true; });
            } else {
                camWrap.hidden = true;
            }
        };
        camBtn.addEventListener('click', function () {
            if (typeof window.Html5Qrcode === 'undefined') {
                showError('Scanner unavailable right now — please type the Certificate ID instead.');
                return;
            }
            hideError();
            camWrap.hidden = false;
            camBtn.disabled = true;
            cam = new window.Html5Qrcode('qrReader');
            cam.start(
                { facingMode: 'environment' },
                { fps: 10, qrbox: { width: 250, height: 250 } },
                function (decodedText) {
                    var r = route(decodedText);
                    var idInput = document.getElementById('smart_id');
                    if (r && r.type === 'token') {
                        stop();
                        window.location.href = 'verify.php?token=' + encodeURIComponent(r.value);
                    } else if (r && idInput) {
                        stop();
                        idInput.value = r.value;
                        form.submit();
                    } else {
                        showError('That QR code is not a CertiVault code — try again or type the Certificate ID.');
                    }
                },
                function () { /* per-frame misses are normal */ }
            ).then(function () { running = true; }).catch(function (err) {
                running = false;
                var name = (err && err.name) || '';
                if (name === 'NotAllowedError') { showError('Camera permission was denied. Allow camera access, or type the Certificate ID instead.'); }
                else if (name === 'NotFoundError' || name === 'OverconstrainedError') { showError('No camera was found on this device — please type the Certificate ID instead.'); }
                else if (name === 'NotReadableError') { showError('The camera is busy in another app — close it and try again.'); }
                else { showError('Could not start the camera. You can still type the Certificate ID.'); }
                camBtn.disabled = false;
            });
        });
        camStop.addEventListener('click', stop);
    }

    // Test hook (no sensitive data).
    window.CertiVaultSmartVerify = { decodeFile: decodeFile, version: '2.0' };
})();
