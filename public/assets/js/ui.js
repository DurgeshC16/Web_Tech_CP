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
                    e.value = d.toISOString().slice(0, 10);
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
})();
