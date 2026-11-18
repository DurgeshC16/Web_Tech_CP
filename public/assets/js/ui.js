/*
 * public/assets/js/ui.js — small, declarative UI behaviours for every page.
 *
 * Loaded once from src/partials/head.php with `defer`. It replaces every
 * inline <script> block and on*="" handler the pages used to carry, so the
 * Content-Security-Policy can forbid inline scripts (script-src 'self').
 * All behaviour is opt-in through data attributes / known element ids and
 * is purely progressive enhancement: the server validates everything.
 *
 *   <form data-confirm="Question?">        confirm() before submitting
 *   <input data-select-on-click>           select the whole value on click
 *   <a data-history-back href="fallback">  go back; href is the no-JS fallback
 *   <input type=file data-filename-target="id">  show "name — size KB" in #id
 *   #resendBtn[data-wait="N"]              OTP resend countdown
 *   #validity_years / #issue_date          suggest expiry = issue + N years
 *   #copyShareBtn / #shareLinkInput        copy the share link, show #copiedToast
 *   input[type=password]                   gets a show/hide "eye" button
 *                                          (opt out: data-no-toggle)
 */
(function () {
    'use strict';

    // ── Show/hide password toggle (every password field, site-wide) ─────
    // Wraps the input in <span class="pw-field"> and appends a real
    // <button type="button"> — natively focusable and operable with
    // Enter/Space — carrying aria-pressed + an aria-label that flips
    // between "Show password" and "Hide password". validation.js (whose
    // DOMContentLoaded handler runs after this deferred script) places the
    // strength meter / error text AFTER the wrapper. Before submit the field
    // is masked again so the browser never stores it as plain text.
    (function () {
        var SVG_OPEN = '<svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true" focusable="false">';
        var EYE = SVG_OPEN + '<path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="2"/></svg>';
        var EYE_OFF = SVG_OPEN + '<path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M17.94 17.94A10.07 10.07 0 0 1 12 19c-7 0-11-7-11-7a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 7 11 7a18.5 18.5 0 0 1-2.16 3.19M14.12 14.12a3 3 0 1 1-4.24-4.24M1 1l22 22"/></svg>';
        var n = 0;
        document.querySelectorAll('input[type="password"]').forEach(function (input) {
            if (input.hasAttribute('data-no-toggle') || input.closest('.pw-field')) { return; }
            if (!input.id) { input.id = 'pw-field-' + (++n); }
            var wrap = document.createElement('span');
            wrap.className = 'pw-field';
            input.parentNode.insertBefore(wrap, input);
            wrap.appendChild(input);

            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'pw-toggle';
            btn.setAttribute('aria-controls', input.id);
            function render(shown) {
                btn.setAttribute('aria-pressed', shown ? 'true' : 'false');
                btn.setAttribute('aria-label', shown ? 'Hide password' : 'Show password');
                btn.title = shown ? 'Hide password' : 'Show password';
                btn.innerHTML = shown ? EYE_OFF : EYE;
            }
            render(false);
            btn.addEventListener('click', function () {
                var show = input.type === 'password';
                input.type = show ? 'text' : 'password';
                render(show);
            });
            wrap.appendChild(btn);

            if (input.form) {
                input.form.addEventListener('submit', function () {
                    input.type = 'password';
                    render(false);
                });
            }
        });
    })();
    // ── Confirmation dialogs on forms ────────────────────────────────────
    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (!(form instanceof HTMLFormElement)) { return; }
        var msg = form.getAttribute('data-confirm');
        if (msg && !window.confirm(msg)) { e.preventDefault(); }
    }, true);

    // ── Select-on-click inputs ───────────────────────────────────────────
    document.addEventListener('click', function (e) {
        var el = e.target;
        if (el instanceof HTMLInputElement && el.hasAttribute('data-select-on-click')) { el.select(); }
        var back = el instanceof Element ? el.closest('a[data-history-back]') : null;
        if (back && window.history.length > 1) {
            e.preventDefault();
            window.history.back();
        }
    });

    // ── File name + size preview ─────────────────────────────────────────
    document.querySelectorAll('input[type=file][data-filename-target]').forEach(function (input) {
        input.addEventListener('change', function () {
            var out = document.getElementById(input.getAttribute('data-filename-target'));
            if (!out) { return; }
            var f = input.files && input.files[0];
            out.textContent = f ? f.name + ' — ' + (f.size / 1024).toFixed(1) + ' KB' : '';
        });
    });

    // ── OTP resend countdown ─────────────────────────────────────────────
    (function () {
        var btn = document.getElementById('resendBtn');
        if (!btn) { return; }
        var seconds = parseInt(btn.getAttribute('data-wait') || '0', 10);
        if (!(seconds > 0)) { return; }
        var label = btn.textContent;
        var note = document.getElementById('resendCountdown');
        function render() {
            btn.disabled = true;
            btn.setAttribute('aria-disabled', 'true');
            btn.textContent = 'Try again in ' + seconds + ' second' + (seconds === 1 ? '' : 's');
            if (note) { note.textContent = 'You can resend after the cooldown — a code was just sent.'; }
        }
        render();
        var t = setInterval(function () {
            seconds--;
            if (seconds <= 0) {
                clearInterval(t);
                btn.disabled = false;
                btn.textContent = label;
                btn.removeAttribute('aria-disabled');
                if (note) { note.textContent = ''; }
                return;
            }
            render();
        }, 1000);
    })();

    // ── Validity (years) → suggested expiry date (server recomputes) ─────
    (function () {
        var y = document.getElementById('validity_years');
        var i = document.getElementById('issue_date');
        var e = document.querySelector('[name="expiry_date"]');
        if (!y || !i || !e) { return; }
        y.addEventListener('change', function () {
            var n = parseInt(y.value, 10);
            if (!e.value && i.value && !isNaN(n) && n >= 1 && n <= 50) {
                var d = new Date(i.value + 'T00:00:00');
                if (!isNaN(d.getTime())) {
                    d.setFullYear(d.getFullYear() + n);
                    // Local date parts: toISOString() is UTC and lands a
                    // day early in time zones east of UTC.
                    e.value = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0')
                        + '-' + String(d.getDate()).padStart(2, '0');
                }
            }
        });
    })();

    // ── Copy share link ──────────────────────────────────────────────────
    (function () {
        var btn = document.getElementById('copyShareBtn');
        var input = document.getElementById('shareLinkInput');
        var toast = document.getElementById('copiedToast');
        if (!btn || !input) { return; }
        function shown() {
            if (!toast) { return; }
            toast.hidden = false;
            setTimeout(function () { toast.hidden = true; }, 2500);
        }
        btn.addEventListener('click', function () {
            input.select();
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(input.value).then(shown, function () {
                    document.execCommand('copy'); shown();
                });
            } else {
                document.execCommand('copy');
                shown();
            }
        });
    })();

    /* ==================================================================
     * Design-system enhancements (docs/12_DESIGN_SYSTEM.md). All optional:
     * with JS off every element is already visible and final.
     *   [data-reveal]              fade/slide in when scrolled into view
     *                              (data-reveal="left|right|zoom",
     *                              data-reveal-delay="1..5" staggers)
     *   [data-count-to="191"]      count up from 0 when visible; the
     *                              server-rendered text is the final value
     *   .btn                       material-style ripple on press
     *   [data-tilt]                subtle 3D tilt + glare (fine pointers)
     *   .site-header               .is-scrolled once the page scrolls
     *   [data-copy="text"] / [data-copy-target="id"]  copy + toast
     *   form[data-loading]         spinner on the submit button
     *   [data-print]               button that opens the print dialog
     *   window.CertiVaultUI.toast(message, 'success'|'error'|'info', ms)
     * Reduced motion: reveal, counters, ripple and tilt are skipped.
     * ================================================================== */
    var mq = function (q) { return !!(window.matchMedia && window.matchMedia(q).matches); };
    var reduceMotion = mq('(prefers-reduced-motion: reduce)');
    var finePointer = mq('(hover: hover) and (pointer: fine)');

    // ── Toast helper ─────────────────────────────────────────────────────
    var toastStack = null;
    function toast(message, type, ms) {
        if (!toastStack) {
            toastStack = document.createElement('div');
            toastStack.className = 'toast-stack';
            toastStack.setAttribute('role', 'status');
            toastStack.setAttribute('aria-live', 'polite');
            document.body.appendChild(toastStack);
        }
        var t = document.createElement('div');
        t.className = 'toast' + (type ? ' toast-' + type : '');
        t.textContent = message;
        toastStack.appendChild(t);
        setTimeout(function () {
            t.classList.add('is-leaving');
            setTimeout(function () { if (t.parentNode) { t.parentNode.removeChild(t); } }, reduceMotion ? 0 : 320);
        }, ms || 3000);
        return t;
    }
    window.CertiVaultUI = { toast: toast };

    // ── Header condenses on scroll ───────────────────────────────────────
    (function () {
        var header = document.querySelector('.site-header');
        if (!header) { return; }
        var ticking = false;
        function update() {
            ticking = false;
            header.classList.toggle('is-scrolled', (window.scrollY || window.pageYOffset) > 8);
        }
        window.addEventListener('scroll', function () {
            if (!ticking) { ticking = true; window.requestAnimationFrame(update); }
        }, { passive: true });
        update();
    })();

    // ── Animated counters ────────────────────────────────────────────────
    function runCounter(el) {
        if (el.getAttribute('data-counted')) { return; }
        el.setAttribute('data-counted', '1');
        var raw = String(el.getAttribute('data-count-to'));
        var target = parseFloat(raw);
        if (!isFinite(target)) { return; }
        var finalText = el.textContent;
        var suffix = el.getAttribute('data-count-suffix') || '';
        var duration = parseInt(el.getAttribute('data-count-duration') || '1400', 10);
        var decimals = (raw.split('.')[1] || '').length;
        var start = null;
        function fmt(v) {
            return v.toLocaleString('en-US', { minimumFractionDigits: decimals, maximumFractionDigits: decimals }) + suffix;
        }
        function frame(ts) {
            if (start === null) { start = ts; }
            var p = Math.min(1, (ts - start) / duration);
            var eased = 1 - Math.pow(1 - p, 3);
            el.textContent = p < 1 ? fmt(target * eased) : finalText;
            if (p < 1) { window.requestAnimationFrame(frame); }
        }
        el.textContent = fmt(0);
        window.requestAnimationFrame(frame);
    }

    // ── Scroll reveal (+ counters when visible) ──────────────────────────
    (function () {
        if (reduceMotion || !('IntersectionObserver' in window)) { return; }
        var revealEls = document.querySelectorAll('[data-reveal], .steps-line');
        var counters = document.querySelectorAll('[data-count-to]');
        document.documentElement.classList.add('js-reveal');
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (!entry.isIntersecting) { return; }
                var el = entry.target;
                io.unobserve(el);
                if (el.hasAttribute('data-count-to')) { runCounter(el); }
                if (el.hasAttribute('data-reveal') || el.classList.contains('steps-line')) { el.classList.add('is-revealed'); }
            });
        }, { threshold: 0.12, rootMargin: '0px 0px -6% 0px' });
        revealEls.forEach(function (el) { io.observe(el); });
        counters.forEach(function (el) { io.observe(el); });
    })();

    // ── Button ripple ────────────────────────────────────────────────────
    if (!reduceMotion) {
        document.addEventListener('pointerdown', function (e) {
            var btn = e.target instanceof Element ? e.target.closest('.btn') : null;
            if (!btn || btn.disabled || btn.getAttribute('aria-disabled') === 'true' || e.button > 0) { return; }
            var rect = btn.getBoundingClientRect();
            var size = Math.max(rect.width, rect.height) * 2.2;
            var r = document.createElement('span');
            r.className = 'ripple';
            r.setAttribute('aria-hidden', 'true');
            r.style.setProperty('--rx', (e.clientX - rect.left) + 'px');
            r.style.setProperty('--ry', (e.clientY - rect.top) + 'px');
            r.style.setProperty('--rs', size + 'px');
            btn.appendChild(r);
            var done = function () { if (r.parentNode) { r.parentNode.removeChild(r); } };
            r.addEventListener('animationend', done);
            setTimeout(done, 900);
        }, { passive: true });
    }

    // ── 3D tilt on [data-tilt] (fine pointers, motion allowed) ───────────
    if (!reduceMotion && finePointer) {
        document.querySelectorAll('[data-tilt]').forEach(function (card) {
            var raf = 0;
            card.addEventListener('pointermove', function (e) {
                var rect = card.getBoundingClientRect();
                var px = (e.clientX - rect.left) / rect.width - 0.5;
                var py = (e.clientY - rect.top) / rect.height - 0.5;
                if (raf) { return; }
                raf = window.requestAnimationFrame(function () {
                    raf = 0;
                    card.classList.add('is-tilting');
                    card.style.setProperty('--tilt-x', (-py * 6).toFixed(2) + 'deg');
                    card.style.setProperty('--tilt-y', (px * 8).toFixed(2) + 'deg');
                    card.style.setProperty('--glow-x', ((px + 0.5) * 100).toFixed(1) + '%');
                    card.style.setProperty('--glow-y', ((py + 0.5) * 100).toFixed(1) + '%');
                });
            });
            card.addEventListener('pointerleave', function () {
                if (raf) { window.cancelAnimationFrame(raf); raf = 0; }
                card.classList.remove('is-tilting');
            });
        });
    }

    // ── Copy buttons ─────────────────────────────────────────────────────
    function legacyCopy(text) {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.className = 'visually-hidden';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } finally { document.body.removeChild(ta); }
    }
    function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text).catch(function () { legacyCopy(text); });
        }
        legacyCopy(text);
        return Promise.resolve();
    }
    document.addEventListener('click', function (e) {
        var btn = e.target instanceof Element ? e.target.closest('[data-copy], [data-copy-target]') : null;
        if (!btn) { return; }
        var text = btn.getAttribute('data-copy');
        if (text === null || text === '') {
            var src = document.getElementById(btn.getAttribute('data-copy-target') || '');
            if (!src) { return; }
            text = typeof src.value === 'string' ? src.value : src.textContent;
        }
        e.preventDefault();
        copyText(String(text).trim()).then(function () {
            toast(btn.getAttribute('data-copy-message') || 'Copied to clipboard', 'success', 2200);
        });
    });

    // ── Missing images (e.g. a QR PNG absent from this checkout) ─────────
    // Swap the broken-image icon for a dashed placeholder with a note.
    function markMissing(img) {
        if (!(img instanceof HTMLImageElement) || img.classList.contains('img-missing')) { return; }
        img.classList.add('img-missing');
        var note = document.createElement('span');
        note.className = 'img-missing-note';
        note.textContent = /qr/i.test(img.getAttribute('alt') || img.getAttribute('src') || '') ? 'QR image unavailable' : 'Image unavailable';
        img.insertAdjacentElement('afterend', note);
    }
    document.addEventListener('error', function (e) { if (e.target instanceof HTMLImageElement) { markMissing(e.target); } }, true);
    Array.prototype.forEach.call(document.images, function (img) {
        if (img.complete && img.getAttribute('src') && img.naturalWidth === 0) { markMissing(img); }
    });

    // ── Print buttons ────────────────────────────────────────────────────
    document.addEventListener('click', function (e) {
        var btn = e.target instanceof Element ? e.target.closest('[data-print]') : null;
        if (!btn) { return; }
        e.preventDefault();
        window.print();
    });

    // ── Loading state on opt-in forms ────────────────────────────────────
    // Bubble phase: the capture-phase data-confirm handler above runs first,
    // so a cancelled confirm never shows a spinner. The button is NOT
    // disabled (that would drop its name/value from the submission).
    document.addEventListener('submit', function (e) {
        var form = e.target;
        if (e.defaultPrevented || !(form instanceof HTMLFormElement) || !form.hasAttribute('data-loading')) { return; }
        var btn = e.submitter || form.querySelector('[type=submit]');
        if (btn && btn.classList.contains('btn')) {
            btn.classList.add('is-loading');
            btn.setAttribute('aria-busy', 'true');
        }
    });
    window.addEventListener('pageshow', function () {
        document.querySelectorAll('.btn.is-loading').forEach(function (b) {
            b.classList.remove('is-loading');
            b.removeAttribute('aria-busy');
        });
    });
})();
