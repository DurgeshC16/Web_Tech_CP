/* public/assets/js/theme.js
 * Writes the cv_theme preference cookie (light/dark) if not present, and
 * wires the header toggle button + mobile nav hamburger. PHP's
 * current_theme() renders <html data-theme="..."> on first paint.
 */
(function () {
    'use strict';

    var COOKIE_MAX_AGE = 365 * 24 * 60 * 60; // 1 year

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

    document.addEventListener('DOMContentLoaded', function () {
        var toggle = document.getElementById('themeToggle');
        if (toggle) {
            toggle.addEventListener('click', function () {
                var current = document.documentElement.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
                var next = current === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', next);
                writeTheme(next);
                toggle.textContent = next === 'dark' ? 'Light' : 'Dark';
            });
        }

        var navToggle = document.getElementById('navToggle');
        var nav = document.getElementById('primaryNav');
        if (navToggle && nav) {
            navToggle.addEventListener('click', function () {
                var open = nav.classList.toggle('open');
                navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
            });
        }
    });
})();
