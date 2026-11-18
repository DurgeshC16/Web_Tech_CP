/* public/assets/js/theme.js
 * Loaded synchronously in <head> (before first paint) so it can:
 *   - mark <html class="js"> — CSS only collapses the mobile nav into a
 *     drawer when JS is available (without JS the nav stays expanded);
 *   - write the cv_theme preference cookie (light/dark) if not present.
 * PHP's current_theme() renders <html data-theme="..."> on first paint, so
 * there is no theme flash. On DOMContentLoaded it wires the header theme
 * toggle (#themeToggle, sun/moon icon button) and the mobile nav
 * hamburger (#navToggle -> #primaryNav.open + aria-expanded).
 */
(function () {
    'use strict';

    var COOKIE_MAX_AGE = 365 * 24 * 60 * 60; // 1 year
    var root = document.documentElement;
    root.classList.add('js');

    function readTheme() {
        var m = document.cookie.match(/(?:^|;\s*)cv_theme=(light|dark)(?:;|$)/);
        return m ? m[1] : null;
    }
    function writeTheme(value) {
        var flags = '; path=/; max-age=' + COOKIE_MAX_AGE + '; SameSite=Strict';
        if (location.protocol === 'https:') { flags += '; Secure'; }
        document.cookie = 'cv_theme=' + value + flags;
    }

    var theme = readTheme();
    if (!theme) {
        theme = 'light';
        writeTheme(theme);
    }

    function labelToggle(toggle, current) {
        var label = current === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
        toggle.setAttribute('aria-label', label);
        toggle.setAttribute('aria-pressed', current === 'dark' ? 'true' : 'false');
        toggle.title = label;
    }

    document.addEventListener('DOMContentLoaded', function () {
        var toggle = document.getElementById('themeToggle');
        if (toggle) {
            toggle.addEventListener('click', function () {
                var current = root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
                var next = current === 'dark' ? 'light' : 'dark';
                root.setAttribute('data-theme', next);
                writeTheme(next);
                labelToggle(toggle, next);
                var meta = document.querySelector('meta[name="theme-color"]');
                if (meta) { meta.setAttribute('content', next === 'dark' ? '#0a0f1e' : '#4f46e5'); }
                toggle.classList.remove('is-switching');
                void toggle.offsetWidth; // restart the icon animation
                toggle.classList.add('is-switching');
            });
        }

        var navToggle = document.getElementById('navToggle');
        var nav = document.getElementById('primaryNav');
        if (navToggle && nav) {
            var setOpen = function (open) {
                nav.classList.toggle('open', open);
                navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
            };
            navToggle.addEventListener('click', function () {
                setOpen(!nav.classList.contains('open'));
            });
            // Escape closes the drawer and returns focus to the hamburger.
            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && nav.classList.contains('open')) {
                    setOpen(false);
                    navToggle.focus();
                }
            });
            // Clicking outside the header closes it.
            document.addEventListener('click', function (e) {
                if (!nav.classList.contains('open')) { return; }
                var header = navToggle.closest('header');
                if (header && !header.contains(e.target)) { setOpen(false); }
            });
        }
    });
})();
