/*
 * public/assets/js/credential-verify.js — zero-trust credential verifier.
 *
 * Re-checks a certivault-credential-v1 JSON entirely in the browser:
 *   1. format + required fields
 *   2. canonical digest recomputed with SHA-256 (Web Crypto)
 *   3. RSASSA-PKCS1-v1_5 / SHA-256 signature over the hex digest, using the
 *      embedded SPKI public key (Web Crypto importKey + verify)
 *   4. key fingerprint recomputed exactly like CryptoService::
 *      fingerprintPublicKey() (SHA-256 of the whitespace-stripped PEM)
 *   5. key TRUST: fingerprint compared with a fingerprint the user pasted
 *      and/or this server's public key directory (well-known-keys.php)
 *   6. optional certificate file: SHA-256 must equal certificate.file_sha256
 *   7. optional live status via api_status.php (revocation after export)
 * Steps 1–4 and 6 never contact any server.
 */
(function () {
    'use strict';

    var form = document.getElementById('credentialForm');
    if (!form) { return; }
    var subtle = window.crypto && window.crypto.subtle;
    var enc = new TextEncoder();

    function hex(buf) {
        var v = new Uint8Array(buf), s = '';
        for (var i = 0; i < v.length; i++) { s += ('0' + v[i].toString(16)).slice(-2); }
        return s;
    }
    function sha256Hex(data) {
        return subtle.digest('SHA-256', typeof data === 'string' ? enc.encode(data) : data).then(hex);
    }
    function b64ToBytes(b64) {
        var bin = atob(String(b64).replace(/\s+/g, ''));
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
        return out;
    }
    function fingerprint(pem) {
        return sha256Hex(String(pem).trim().replace(/\s+/g, '')).then(function (h) {
            return h.toUpperCase().match(/.{2}/g).join(':');
        });
    }
    function normFp(s) { return String(s || '').toUpperCase().replace(/[^0-9A-F]/g, ''); }

    function canonical(c) {
        var cert = c.certificate;
        return [cert.certificate_id, c.issuer.institution_id, c.subject.student_id, cert.title,
            cert.issue_date, cert.expiry_date == null ? '' : cert.expiry_date, cert.file_sha256].join('|');
    }

    function importSpki(pem) {
        var body = String(pem).replace(/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\s+/g, '');
        return subtle.importKey('spki', b64ToBytes(body), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    }

    function readFileText(input) {
        var f = input.files && input.files[0];
        return f ? f.text() : Promise.resolve(null);
    }

    /**
     * Core verification. Returns {checks:[{id,label,state,detail}], credential}.
     * state: 'pass' | 'fail' | 'warn' | 'skip'. Exposed for tests.
     */
    function verifyCredential(credential, opts) {
        opts = opts || {};
        var checks = [];
        function add(id, label, state, detail) { checks.push({ id: id, label: label, state: state, detail: detail || '' }); }

        var shapeOk = credential && credential.format === 'certivault-credential-v1' && credential.certificate
            && credential.issuer && credential.subject && credential.proof
            && /^[a-f0-9]{64}$/.test(String(credential.proof.digest_sha256 || ''))
            && /^[a-f0-9]{64}$/.test(String(credential.certificate.file_sha256 || ''));
        add('format', 'Recognised credential format', shapeOk ? 'pass' : 'fail',
            shapeOk ? 'certivault-credential-v1' : 'Not a CertiVault credential file, or fields are missing.');
        if (!shapeOk) { return Promise.resolve({ checks: checks, credential: credential }); }
        var p = credential.proof;

        return sha256Hex(canonical(credential)).then(function (digest) {
            var digestOk = digest === p.digest_sha256;
            add('digest', 'Fields match the signed fingerprint (SHA-256)', digestOk ? 'pass' : 'fail',
                digestOk ? digest : 'Recomputed ' + digest + ' ≠ ' + p.digest_sha256 + ' — a field was changed.');
            return importSpki(p.public_key_pem).then(function (key) {
                return subtle.verify('RSASSA-PKCS1-v1_5', key, b64ToBytes(p.signature_base64), enc.encode(p.digest_sha256));
            }).then(function (sigOk) {
                add('signature', 'Institution signature is valid (RSA, checked by your browser)', sigOk ? 'pass' : 'fail',
                    sigOk ? 'RSASSA-PKCS1-v1_5 / SHA-256' : 'The signature does not match the digest and key in this file.');
            }, function () {
                add('signature', 'Institution signature is valid (RSA, checked by your browser)', 'fail', 'The embedded public key could not be read.');
            });
        }).then(function () {
            return fingerprint(p.public_key_pem);
        }).then(function (fp) {
            var selfOk = normFp(fp) === normFp(p.key_fingerprint_sha256);
            add('fingerprint', 'Key fingerprint is consistent with the embedded key', selfOk ? 'pass' : 'fail', fp);

            // Key trust: the file could carry an attacker's key, so compare
            // with something independent of the file.
            var trusted = normFp(opts.trustedFingerprint);
            var trustChecks = [];
            if (trusted) {
                add('trusted', 'Key matches the fingerprint you entered', trusted === normFp(fp) ? 'pass' : 'fail',
                    trusted === normFp(fp) ? 'Match' : 'Different key — do not trust this credential.');
            }
            if (opts.directory) {
                trustChecks.push(fetch(opts.directoryUrl || 'well-known-keys.php', { cache: 'no-store' }).then(function (r) {
                    if (!r.ok) { throw new Error('HTTP ' + r.status); }
                    return r.json();
                }).then(function (dir) {
                    var entry = (dir.keys || []).filter(function (k) {
                        return Number(k.institution_id) === Number(credential.issuer.institution_id)
                            && Number(k.key_id) === Number(credential.issuer.key_id);
                    })[0];
                    if (!entry) {
                        add('directory', 'Key is published in the CertiVault key directory', 'fail', 'No published key for this institution/key version.');
                    } else {
                        var same = normFp(entry.fingerprint_sha256) === normFp(fp);
                        add('directory', 'Key is published in the CertiVault key directory', same ? 'pass' : 'fail',
                            same ? entry.institution + ' — key v' + entry.key_id + ' (' + entry.status + ')' : 'Published key differs from the key in this file.');
                    }
                }).catch(function (e) {
                    add('directory', 'Key is published in the CertiVault key directory', 'warn', 'Directory unavailable (' + e.message + ').');
                }));
            }
            if (!trusted && !opts.directory) {
                add('trusted', 'Key trust', 'warn', 'No independent fingerprint was checked — enter one or enable the key directory.');
            }
            return Promise.all(trustChecks);
        }).then(function () {
            if (!opts.certificateFile) {
                add('file', 'Certificate file matches the credential', 'skip', 'No certificate file selected.');
                return null;
            }
            return opts.certificateFile.arrayBuffer().then(sha256Hex).then(function (h) {
                var same = h === credential.certificate.file_sha256;
                add('file', 'Certificate file matches the credential', same ? 'pass' : 'fail',
                    same ? 'SHA-256 ' + h : 'This file is not the signed original (SHA-256 ' + h + ').');
            });
        }).then(function () {
            if (!opts.directory) {
                add('status', 'Live status (revocation)', 'skip', 'Offline — status at export: ' + (credential.status_at_export || {}).verdict);
                return null;
            }
            return fetch((opts.statusUrl || 'api_status.php') + '?certificate_id=' + encodeURIComponent(credential.certificate.certificate_id), { cache: 'no-store' })
                .then(function (r) { return r.json(); })
                .then(function (s) {
                    var v = s.verdict || 'UNKNOWN';
                    add('status', 'Live status (revocation)', v === 'VALID' ? 'pass' : (v === 'EXPIRED' ? 'warn' : 'fail'), v + (s.detail ? ' — ' + s.detail : ''));
                }).catch(function () {
                    add('status', 'Live status (revocation)', 'warn', 'Status service unavailable.');
                });
        }).then(function () {
            return { checks: checks, credential: credential };
        });
    }

    function overall(checks) {
        var crypto = ['format', 'digest', 'signature', 'fingerprint'].every(function (id) {
            return checks.some(function (c) { return c.id === id && c.state === 'pass'; });
        });
        var anyFail = checks.some(function (c) { return c.state === 'fail'; });
        var keyTrusted = checks.some(function (c) { return (c.id === 'directory' || c.id === 'trusted') && c.state === 'pass'; });
        if (!crypto) { return { cls: 'fail', text: '✗ Not authentic — the credential failed its cryptographic checks' }; }
        if (anyFail) { return { cls: 'fail', text: '✗ Signature is intact, but a trust or status check failed' }; }
        if (!keyTrusted) { return { cls: 'warn', text: '⚠ Signature is intact — confirm the institution key before relying on it' }; }
        return { cls: 'pass', text: '✓ Authentic — signed by a published institution key' };
    }

    function render(result) {
        var box = document.getElementById('credentialResult');
        var list = document.getElementById('credentialChecks');
        var head = document.getElementById('credentialHeadline');
        var sum = document.getElementById('credentialSummary');
        list.textContent = ''; sum.textContent = '';
        var o = overall(result.checks);
        head.textContent = o.text;
        head.className = 'card-title credential-' + o.cls;
        var c = result.credential;
        if (c && c.certificate) {
            [['Certificate', c.certificate.certificate_id], ['Title', c.certificate.title], ['Awarded to', c.subject && c.subject.name],
                ['Issued by', c.issuer && c.issuer.name], ['Issue date', c.certificate.issue_date], ['Expiry', c.certificate.expiry_date || '—']]
                .forEach(function (row) {
                    var dt = document.createElement('dt'); dt.textContent = row[0];
                    var dd = document.createElement('dd'); dd.textContent = row[1] == null ? '' : String(row[1]);
                    sum.appendChild(dt); sum.appendChild(dd);
                });
        }
        result.checks.forEach(function (ch) {
            var li = document.createElement('li');
            li.className = 'check check-' + ch.state;
            li.setAttribute('data-check', ch.id);
            var icon = { pass: '✓', fail: '✗', warn: '⚠', skip: '–' }[ch.state] || '?';
            var strong = document.createElement('strong'); strong.textContent = icon + ' ' + ch.label;
            var small = document.createElement('small'); small.textContent = ch.detail;
            li.appendChild(strong); li.appendChild(document.createElement('br')); li.appendChild(small);
            list.appendChild(li);
        });
        box.hidden = false;
        box.setAttribute('data-overall', o.cls);
        // Presentation: replay the entrance animation and bring the result
        // into view (instant jump when the user prefers reduced motion).
        box.classList.remove('is-shown');
        void box.offsetWidth;
        box.classList.add('is-shown');
        if (box.scrollIntoView) {
            var still = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            box.scrollIntoView({ behavior: still ? 'auto' : 'smooth', block: 'nearest' });
        }
    }

    // ── Presentation: drop zones (offline_verify.php) ────────────────────
    // The native file inputs keep working without this; with it they are
    // laid over a styled drop area that shows the chosen file name.
    form.classList.add('sv-enhanced');
    Array.prototype.forEach.call(form.querySelectorAll('.sv-dropzone'), function (zone) {
        var input = zone.querySelector('input[type=file]');
        var out = zone.querySelector('.sv-drop-file');
        if (!input) { return; }
        ['dragenter', 'dragover'].forEach(function (ev) {
            zone.addEventListener(ev, function () { zone.classList.add('is-dragover'); });
        });
        ['dragleave', 'dragend', 'drop'].forEach(function (ev) {
            zone.addEventListener(ev, function () { zone.classList.remove('is-dragover'); });
        });
        input.addEventListener('change', function () {
            var f = input.files && input.files[0];
            zone.classList.toggle('has-file', !!f);
            if (out) {
                out.hidden = !f;
                out.textContent = f ? f.name + ' — ' + Math.max(1, Math.round(f.size / 1024)) + ' KB' : '';
            }
        });
    });

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        if (!subtle) {
            render({ checks: [{ id: 'format', label: 'Web Crypto is unavailable in this browser (use HTTPS or a modern browser)', state: 'fail' }] });
            return;
        }
        readFileText(document.getElementById('credentialFile')).then(function (text) {
            text = text || document.getElementById('credentialText').value;
            var credential = null;
            try { credential = JSON.parse(text); } catch (x) { credential = null; }
            var certInput = document.getElementById('certificateFile');
            return verifyCredential(credential, {
                trustedFingerprint: document.getElementById('trustedFingerprint').value,
                directory: document.getElementById('useDirectory').checked,
                certificateFile: certInput.files && certInput.files[0]
            });
        }).then(render);
    });

    window.CertiVaultCredential = { verify: verifyCredential, overall: overall, fingerprint: fingerprint, version: '1.0' };
})();
