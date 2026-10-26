/* public/assets/js/verify-scan.js
 * CertiVault — multi-input certificate verification UI.
 *
 * Input methods (all feed the SAME server-side pipeline in verify.php):
 *   1. Camera          — html5-qrcode live decode
 *   2. QR image upload — decoded in the browser (PNG/JPEG/WebP)
 *   3. PDF upload      — rendered in the browser with pdf.js, pages scanned
 *   4. Certificate ID  — plain GET form (works without JS)
 *
 * SECURITY MODEL
 *   - Uploaded files and decoded QR payloads never leave the browser; there
 *     is no server upload endpoint and no third-party service is contacted.
 *   - A decoded QR is treated as UNTRUSTED text. This module only ever
 *     extracts a 43-char token (or a certificate id) and rebuilds a LOCAL
 *     verify.php URL. It never navigates to, redirects to, or embeds the
 *     decoded URL, so a hostile QR cannot cause an open redirect.
 *   - Decoded data is written with textContent only (never innerHTML).
 *   - No decoded value is written to the console or to error strings.
 *
 * Progressive enhancement: with JS disabled the Certificate ID tab/panel is
 * visible and submits normally.
 */
(function () {
    'use strict';

    var app = document.getElementById('verifyApp');
    if (!app) { return; } // verdict page or non-landing state

    var cfg = {
        imageMax:      parseInt(app.getAttribute('data-image-max'), 10) || 10 * 1024 * 1024,
        pdfMax:        parseInt(app.getAttribute('data-pdf-max'), 10) || 25 * 1024 * 1024,
        pdfMaxPages:   parseInt(app.getAttribute('data-pdf-max-pages'), 10) || 30,
        scanMaxMs:     parseInt(app.getAttribute('data-scan-max-ms'), 10) || 60000,
        renderMaxWidth: parseInt(app.getAttribute('data-render-max-width'), 10) || 1600
    };

    // A QR token is 32 random bytes encoded base64url without padding (43 chars).
    var TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
    // Certificate id format, mirrors validators.php / validation.js.
    var CERTID_RE = /^CV-\d{4}-\d{6}$/;

    var IMAGE_EXT = ['png', 'jpg', 'jpeg', 'webp'];

    var statusEl  = document.getElementById('verifyStatus');
    var chooserEl = document.getElementById('verifyChooser');

    // ── Shared status / loading helpers ─────────────────────────────────
    var busy = false;
    function setStatus(msg, kind) {
        if (!statusEl) { return; }
        statusEl.hidden = !msg;
        statusEl.textContent = msg || '';
        statusEl.className = 'scan-status' + (kind ? ' scan-status-' + kind : '');
    }
    function setBusy(on) {
        busy = on;
        app.querySelectorAll('button').forEach(function (b) {
            if (b.classList.contains('tab')) { return; }
            b.disabled = on;
        });
    }
    function clearChooser() {
        if (!chooserEl) { return; }
        chooserEl.hidden = true;
        while (chooserEl.firstChild) { chooserEl.removeChild(chooserEl.firstChild); }
    }

    // ── Identifier extraction (the ONE place untrusted text is parsed) ──
    // Returns {type:'token'|'certificate_id', value} or null.
    function extractIdentifier(rawText) {
        if (rawText == null) { return null; }
        var text = String(rawText).replace(/\s+/g, ' ').trim();
        if (text === '') { return null; }

        // 1) A bare token is the most common case (QR may encode just the token).
        if (TOKEN_RE.test(text)) { return { type: 'token', value: text }; }
        if (CERTID_RE.test(text)) { return { type: 'certificate_id', value: text }; }

        // 2) Otherwise treat it as a URL and pull out the token/cert id *only*.
        //    We never follow this URL — we only read its query parameters and
        //    rebuild a local link. Origin/path are still validated so a QR
        //    pointing at a foreign host is rejected rather than silently used.
        if (text.indexOf('://') !== -1 || text.indexOf('/') === 0 || text.indexOf('verify.php') !== -1) {
            var url;
            try { url = new URL(text, window.location.href); } catch (e) { return null; }
            if (url.protocol !== 'http:' && url.protocol !== 'https:') { return null; }
            // Same-origin check: an absolute URL must point at this site.
            if (url.origin !== window.location.origin) { return null; }
            // Path check: only our own verification page is acceptable.
            if (!/\/verify\.php$/.test(url.pathname)) { return null; }

            var t = url.searchParams.get('token');
            if (t && TOKEN_RE.test(t)) { return { type: 'token', value: t }; }
            var c = url.searchParams.get('certificate_id');
            if (c && CERTID_RE.test(c)) { return { type: 'certificate_id', value: c }; }
            return null;
        }
        return null;
    }

    // ── Navigate to the authoritative verifier ──────────────────────────
    function goVerify(ident) {
        if (!ident) { return; }
        setBusy(true);
        setStatus('Identifier recognised — verifying…', 'busy');
        var param = ident.type === 'token' ? 'token' : 'certificate_id';
        // Rebuilt locally from a validated token/id; nothing user-controlled
        // is concatenated without encoding.
        window.location.assign('verify.php?' + param + '=' + encodeURIComponent(ident.value));
    }

    // Offer a choice when one image/PDF yields several different QR tokens.
    function offerChoice(idents) {
        setBusy(false);
        if (!chooserEl) { goVerify(idents[0]); return; }
        clearChooser();
        var p = document.createElement('p');
        p.className = 'panel-help';
        p.textContent = 'This file contains ' + idents.length + ' different certificates. Choose the one to verify:';
        chooserEl.appendChild(p);
        idents.forEach(function (ident) {
            var b = document.createElement('button');
            b.type = 'button';
            b.className = 'btn btn-secondary qr-choice';
            // Truncated label only; full value goes through encodeURIComponent.
            b.textContent = ident.type === 'token'
                ? 'Token ' + ident.value.slice(0, 8) + '…'
                : ident.value;
            b.addEventListener('click', function () { goVerify(ident); });
            chooserEl.appendChild(b);
        });
        chooserEl.hidden = false;
        setStatus('Multiple QR codes found — please choose one.', 'info');
    }

    // Collapse decodes into distinct identifiers of the same type, preserving order.
    function uniqueIdents(list) {
        var seen = {};
        var out = [];
        list.forEach(function (ident) {
            if (!ident) { return; }
            var key = ident.type + ':' + ident.value;
            if (!seen[key]) { seen[key] = true; out.push(ident); }
        });
        return out;
    }

    // ── Decoders ────────────────────────────────────────────────────────
    var hasBarcodeDetector = (typeof window.BarcodeDetector === 'function');

    var imageScanner = null; // lazy Html5Qrcode instance on #qrImageReader
    function html5() {
        return (typeof window.Html5Qrcode === 'function') ? window.Html5Qrcode : null;
    }
    function getImageScanner() {
        var H = html5();
        if (!H) { return null; }
        if (!imageScanner) { imageScanner = new H('qrImageReader'); }
        return imageScanner;
    }

    // Decode one image with html5-qrcode (single QR). Resolves decoded text or null.
    // html5-qrcode's scanFile() requires a File instance, so wrap blobs.
    function decodeWithHtml5(fileOrBlob) {
        var scanner = getImageScanner();
        if (!scanner) { return Promise.resolve(null); }
        var file = fileOrBlob;
        if (!(fileOrBlob instanceof File)) {
            try { file = new File([fileOrBlob], 'scan.png', { type: 'image/png' }); }
            catch (e) { return Promise.resolve(null); }
        }
        try {
            return scanner.scanFile(file, false).then(function (text) {
                return text || null;
            }).catch(function () { return null; });
        } catch (e) {
            // scanFile throws synchronously for unsupported input types.
            return Promise.resolve(null);
        }
    }

    // Detect every QR on a canvas via BarcodeDetector when available.
    function detectOnCanvas(canvas) {
        if (!hasBarcodeDetector) { return Promise.resolve([]); }
        var det;
        try { det = new window.BarcodeDetector({ formats: ['qr_code'] }); }
        catch (e) { return Promise.resolve([]); }
        return det.detect(canvas).then(function (codes) {
            return (codes || []).map(function (c) { return c.rawValue; });
        }).catch(function () { return []; });
    }

    function canvasToBlob(canvas) {
        return new Promise(function (resolve) {
            if (typeof canvas.toBlob === 'function') {
                canvas.toBlob(function (b) { resolve(b); }, 'image/png');
            } else {
                resolve(null);
            }
        });
    }

    // Decode a canvas into a list of identifiers (multi when supported).
    function decodeCanvas(canvas) {
        return detectOnCanvas(canvas).then(function (raws) {
            var idents = uniqueIdents(raws.map(extractIdentifier));
            if (idents.length) { return idents; }
            // Fallback: single-QR decode via html5-qrcode.
            return canvasToBlob(canvas).then(function (blob) {
                if (!blob) { return []; }
                return decodeWithHtml5(blob).then(function (txt) {
                    return uniqueIdents([extractIdentifier(txt)]);
                });
            });
        });
    }

    // Decode the QR from the original bytes (no rasterising).
    function rawScanHtml5(file) {
        return decodeWithHtml5(file).then(function (t) {
            return uniqueIdents([extractIdentifier(t)]);
        });
    }

    // Rasterise the file to a canvas at `scale` and decode it (multi-capable).
    function bitmapScan(file, scale) {
        if (typeof window.createImageBitmap !== 'function') {
            return Promise.resolve([]);
        }
        return window.createImageBitmap(file).then(function (bmp) {
            var canvas = document.createElement('canvas');
            canvas.width = Math.max(1, Math.round((bmp.width || 1) * scale));
            canvas.height = Math.max(1, Math.round((bmp.height || 1) * scale));
            canvas.getContext('2d').drawImage(bmp, 0, 0, canvas.width, canvas.height);
            if (bmp.close) { bmp.close(); }
            return decodeCanvas(canvas);
        });
    }

    // Run decode strategies in order and return the first that finds a QR.
    function firstIdentifiers(fns) {
        var i = 0;
        function next() {
            if (i >= fns.length) { return Promise.resolve([]); }
            var fn = fns[i++];
            return Promise.resolve().then(fn).catch(function () { return []; })
                .then(function (ids) { return (ids && ids.length) ? ids : next(); });
        }
        return next();
    }

    // Decode an uploaded image with progressive fallbacks: the native
    // BarcodeDetector (multi) when available, then the original bytes, then a
    // natural-size and 2x-upscaled canvas. The retries make marginal photos
    // and small QRs far less likely to be dropped by html5-qrcode.
    function decodeImageFile(file) {
        var canBitmap = (typeof window.createImageBitmap === 'function');
        var fns = [];
        if (hasBarcodeDetector && canBitmap) {
            fns.push(function () { return bitmapScan(file, 1); });
        }
        fns.push(function () { return rawScanHtml5(file); });
        if (canBitmap) {
            if (!hasBarcodeDetector) {
                fns.push(function () { return bitmapScan(file, 1); });
            }
            fns.push(function () { return bitmapScan(file, 2); });
        }
        return firstIdentifiers(fns);
    }

    // ── Tabs (accessible, roving tabindex) ──────────────────────────────
    (function initTabs() {
        var tabs = Array.prototype.slice.call(app.querySelectorAll('[role="tab"]'));
        var panels = tabs.map(function (t) { return document.getElementById(t.getAttribute('aria-controls')); });

        function selectTab(idx, focus) {
            tabs.forEach(function (t, i) {
                var active = i === idx;
                t.setAttribute('aria-selected', active ? 'true' : 'false');
                t.tabIndex = active ? 0 : -1;
                t.classList.toggle('is-active', active);
                if (panels[i]) { panels[i].hidden = !active; }
            });
            if (focus) { tabs[idx].focus(); }
            if (window.stopCamera) { window.stopCamera(); }
        }

        tabs.forEach(function (tab, i) {
            tab.addEventListener('click', function () { selectTab(i, false); });
            tab.addEventListener('keydown', function (e) {
                var k = e.key, n = null;
                if (k === 'ArrowRight' || k === 'ArrowDown') { n = (i + 1) % tabs.length; }
                else if (k === 'ArrowLeft' || k === 'ArrowUp') { n = (i - 1 + tabs.length) % tabs.length; }
                else if (k === 'Home') { n = 0; }
                else if (k === 'End') { n = tabs.length - 1; }
                if (n !== null) { e.preventDefault(); selectTab(n, true); }
            });
        });
        // Start on the selected tab; ensure panels reflect it.
        var start = tabs.findIndex(function (t) { return t.getAttribute('aria-selected') === 'true'; });
        selectTab(start < 0 ? 0 : start, false);
    })();

    // ── 1. Camera ───────────────────────────────────────────────────────
    (function initCamera() {
        var startBtn = document.getElementById('cameraStartBtn');
        var stopBtn  = document.getElementById('cameraStopBtn');
        var reader   = document.getElementById('qrReader');
        if (!startBtn || !stopBtn || !reader) { return; }

        var scanner = null, running = false;

        function cameraError(e) {
            var name = (e && e.name) || '';
            if (name === 'NotAllowedError') {
                setStatus('Camera permission was denied. Allow camera access in your browser, or use the Upload QR image / Certificate ID option instead.', 'error');
            } else if (name === 'NotFoundError' || name === 'OverconstrainedError') {
                setStatus('No camera was found on this device. Use the Upload QR image / PDF / Certificate ID option instead.', 'error');
            } else if (name === 'NotReadableError') {
                setStatus('The camera is busy in another application. Close it and try again.', 'error');
            } else {
                setStatus('Could not start the camera. You can still upload a QR image or type the Certificate ID.', 'error');
            }
        }

        function stop() {
            stopBtn.hidden = true;
            startBtn.hidden = false;
            reader.hidden = true;
            if (scanner && running) {
                running = false;
                var s = scanner;
                scanner = null;
                s.stop().then(function () { s.clear(); }).catch(function () {});
            }
        }
        window.stopCamera = stop;

        startBtn.addEventListener('click', function () {
            var H = html5();
            if (!H) {
                setStatus('The QR scanner library did not load, so the camera is unavailable. Upload a QR image or type the Certificate ID instead.', 'error');
                return;
            }
            clearChooser();
            setStatus('Requesting camera…', 'busy');
            reader.hidden = false;
            startBtn.hidden = true;
            stopBtn.hidden = false;
            scanner = new H('qrReader');
            scanner.start(
                { facingMode: 'environment' },
                { fps: 10, qrbox: { width: 250, height: 250 } },
                function (decodedText) {
                    var ident = extractIdentifier(decodedText);
                    if (ident) { stop(); goVerify(ident); }
                    else { setStatus('That QR code is not a CertiVault certificate code. Try again or use another option.', 'error'); }
                },
                function () { /* per-frame miss is normal */ }
            ).then(function () {
                running = true;
                setStatus('Scanning… hold the QR code steady inside the frame.', 'info');
            }).catch(function (e) {
                running = false;
                scanner = null;
                startBtn.hidden = false;
                stopBtn.hidden = true;
                reader.hidden = true;
                cameraError(e);
            });
        });
        stopBtn.addEventListener('click', stop);
    })();

    // ── 2. QR image upload ──────────────────────────────────────────────
    (function initImage() {
        var input = document.getElementById('qrImageInput');
        var btn   = document.getElementById('qrImageBtn');
        if (!input || !btn) { return; }

        function fileExt(name) { return (name.split('.').pop() || '').toLowerCase(); }

        btn.addEventListener('click', function () {
            clearChooser();
            var file = input.files && input.files[0];
            if (!file) { setStatus('Choose a QR image file first.', 'error'); return; }
            var ext = fileExt(file.name);
            if (IMAGE_EXT.indexOf(ext) === -1) {
                setStatus('Unsupported image type. Please choose a PNG, JPEG or WebP image.', 'error'); return;
            }
            if (file.size === 0) { setStatus('That file is empty.', 'error'); return; }
            if (file.size > cfg.imageMax) {
                setStatus('That image is too large (limit ' + Math.round(cfg.imageMax / (1024 * 1024)) + ' MB).', 'error'); return;
            }
            setBusy(true);
            setStatus('Reading the image and looking for a QR code…', 'busy');
            decodeImageFile(file).then(function (idents) {
                if (!idents.length) {
                    setBusy(false);
                    setStatus('No CertiVault QR code could be read from that image. Make sure the QR is clear, unrotated and not cropped, then try again or type the Certificate ID.', 'error');
                    return;
                }
                if (idents.length > 1) { offerChoice(idents); return; }
                goVerify(idents[0]);
            }).catch(function () {
                setBusy(false);
                setStatus('That image could not be processed. It may be corrupted or not a supported format.', 'error');
            });
        });
    })();

    // ── 3. PDF upload (pdf.js + QR decode) ──────────────────────────────
    var pdfJsPromise = null;
    function loadPdfJs() {
        if (pdfJsPromise) { return pdfJsPromise; }
        pdfJsPromise = new Promise(function (resolve, reject) {
            if (window.pdfjsLib) {
                window.pdfjsLib.GlobalWorkerOptions.workerSrc = 'assets/js/vendor/pdf.worker.min.js';
                resolve(window.pdfjsLib);
                return;
            }
            var s = document.createElement('script');
            s.src = 'assets/js/vendor/pdf.min.js';
            s.onload = function () {
                if (!window.pdfjsLib) { reject(new Error('pdfjs missing')); return; }
                window.pdfjsLib.GlobalWorkerOptions.workerSrc = 'assets/js/vendor/pdf.worker.min.js';
                resolve(window.pdfjsLib);
            };
            s.onerror = function () { reject(new Error('pdfjs load failed')); };
            document.head.appendChild(s);
        });
        return pdfJsPromise;
    }

    (function initPdf() {
        var input    = document.getElementById('pdfInput');
        var btn      = document.getElementById('pdfBtn');
        var progress = document.getElementById('pdfProgress');
        var fill     = document.getElementById('pdfProgressFill');
        var label    = document.getElementById('pdfProgressLabel');
        var canvas   = document.getElementById('pdfCanvas');
        var sizeLabel = document.getElementById('pdfSizeLabel');
        var pageLabel = document.getElementById('pdfLimitLabel');
        if (!input || !btn || !canvas) { return; }

        if (sizeLabel) { sizeLabel.textContent = Math.round(cfg.pdfMax / (1024 * 1024)) + ' MB'; }
        if (pageLabel) { pageLabel.textContent = String(cfg.pdfMaxPages); }

        function fileExt(name) { return (name.split('.').pop() || '').toLowerCase(); }
        function progressUI(pct, text) {
            if (!progress || !fill || !label) { return; }
            progress.hidden = false;
            fill.style.width = Math.max(0, Math.min(100, pct)) + '%';
            label.textContent = text || '';
        }

        btn.addEventListener('click', function () {
            clearChooser();
            var file = input.files && input.files[0];
            if (!file) { setStatus('Choose a certificate PDF first.', 'error'); return; }
            if (fileExt(file.name) !== 'pdf' && file.type !== 'application/pdf') {
                setStatus('Please choose a PDF file.', 'error'); return;
            }
            if (file.size === 0) { setStatus('That PDF is empty.', 'error'); return; }
            if (file.size > cfg.pdfMax) {
                setStatus('That PDF is too large (limit ' + Math.round(cfg.pdfMax / (1024 * 1024)) + ' MB).', 'error'); return;
            }

            setBusy(true);
            setStatus('Opening the PDF…', 'busy');
            progressUI(2, 'Loading PDF…');

            var startedAt = Date.now();
            var pdfDoc = null;
            var renderTask = null;

            function fail(msg) {
                setBusy(false);
                setStatus(msg, 'error');
                progressUI(100, 'Failed');
            }

            loadPdfJs().then(function (pdfjsLib) {
                return file.arrayBuffer().then(function (buf) {
                    // getDocument() returns a loading task; .promise resolves
                    // to the PDFDocumentProxy.
                    return pdfjsLib.getDocument({
                        data: buf,
                        isEvalSupported: false,   // harden: never eval embedded JS
                        disableAutoFetch: true,
                        disableStream: true
                    }).promise;
                });
            }).then(function (doc) {
                pdfDoc = doc;
                var total = doc.numPages;
                if (total > cfg.pdfMaxPages) {
                    // Enforce the page-count limit rather than silently scanning a subset.
                    return Promise.reject({ friendly: 'This PDF has ' + total + ' pages, which exceeds the ' + cfg.pdfMaxPages + '-page scan limit.' });
                }
                var found = [];
                var chain = Promise.resolve();
                for (var p = 1; p <= total; p++) {
                    (function (pageNo) {
                        chain = chain.then(function () {
                            if (Date.now() - startedAt > cfg.scanMaxMs) {
                                throw { friendly: 'Scanning took too long and was stopped after ' + Math.round(cfg.scanMaxMs / 1000) + ' seconds. Try a smaller PDF or the Certificate ID.' };
                            }
                            progressUI(Math.round((pageNo - 1) / total * 100), 'Scanning page ' + pageNo + ' of ' + total + '…');
                            return pdfDoc.getPage(pageNo).then(function (page) {
                                var base = page.getViewport({ scale: 1 });
                                var scale = Math.min(cfg.renderMaxWidth / base.width, 2);
                                var vp = page.getViewport({ scale: scale });
                                canvas.width = Math.max(1, Math.floor(vp.width));
                                canvas.height = Math.max(1, Math.floor(vp.height));
                                var ctx = canvas.getContext('2d');
                                ctx.fillStyle = '#ffffff';
                                ctx.fillRect(0, 0, canvas.width, canvas.height);
                                renderTask = page.render({ canvasContext: ctx, viewport: vp });
                                return renderTask.promise.then(function () {
                                    return decodeCanvas(canvas).then(function (idents) {
                                        idents.forEach(function (id) { found.push(id); });
                                        page.cleanup();
                                    });
                                });
                            });
                        });
                    })(p);
                }
                return chain.then(function () { return uniqueIdents(found); });
            }).then(function (idents) {
                if (pdfDoc) { pdfDoc.destroy(); }
                progressUI(100, 'Done');
                if (!idents.length) {
                    fail('No CertiVault QR code was found in that PDF. Make sure you uploaded the certificate PDF (not a scan of the wrong page) or type the Certificate ID.');
                    return;
                }
                if (idents.length > 1) { offerChoice(idents); return; }
                goVerify(idents[0]);
            }).catch(function (e) {
                if (renderTask && renderTask.cancel) { try { renderTask.cancel(); } catch (x) {} }
                if (pdfDoc) { try { pdfDoc.destroy(); } catch (x) {} }
                if (e && e.friendly) { fail(e.friendly); }
                else { fail('That PDF could not be read. It may be corrupted, password-protected or not a valid PDF.'); }
            });
        });
    })();

    // ── 4. Manual certificate-id: keep native GET form (server validates) ─
    // Nothing to do here; validation.js validates before the GET request and
    // verify.php re-validates server-side. Direct links simply work.

    // Expose a tiny hook for tests (no sensitive data).
    window.CertiVaultVerify = {
        extractIdentifier: extractIdentifier,
        version: '1.0'
    };
})();
