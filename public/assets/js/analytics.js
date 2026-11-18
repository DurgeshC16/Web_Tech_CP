/*
 * public/assets/js/analytics.js — hover / keyboard layer for analytics.php.
 * Tooltips enhance, never gate: every value is also printed on the page or
 * in the "Show as table" view. Text is inserted with textContent only.
 *   • daily chart: a crosshair snaps to the day under the pointer (or the
 *     focused day) and the tooltip shows value + date
 *   • ranked bars: the hovered/focused row lifts and shows its value
 *   • bar lengths come from data-bar (percent) -> --bar (CSSOM, CSP-safe)
 */
(function () {
    'use strict';
    var root = document.getElementById('analytics');
    if (!root) { return; }

    var tip = document.createElement('div');
    tip.className = 'viz-tooltip viz-tooltip-float';
    tip.setAttribute('role', 'status');
    tip.hidden = true;
    var tipValue = document.createElement('strong');
    var tipLabel = document.createElement('span');
    tip.appendChild(tipValue);
    tip.appendChild(tipLabel);
    document.body.appendChild(tip);

    function show(value, label, rect) {
        tipValue.textContent = value;
        tipLabel.textContent = label;
        tip.hidden = false;
        var w = tip.offsetWidth, h = tip.offsetHeight;
        var left = Math.min(Math.max(8, rect.left + rect.width / 2 - w / 2), document.documentElement.clientWidth - w - 8);
        tip.style.left = (left + window.scrollX) + 'px';
        tip.style.top = (rect.top + window.scrollY - h - 10) + 'px';
    }
    function hide() { tip.hidden = true; }

    // ── Daily chart crosshair ────────────────────────────────────────────
    var svg = document.getElementById('dailyChart');
    var cross = document.getElementById('dailyCrosshair');
    if (svg && cross) {
        var pt = svg.createSVGPoint();
        var activate = function (hit) {
            var x = hit.getAttribute('data-x');
            cross.setAttribute('x1', x);
            cross.setAttribute('x2', x);
            cross.setAttribute('visibility', 'visible');
            var v = Number(hit.getAttribute('data-value'));
            // Anchor the tooltip at the crosshair, top of the plot.
            pt.x = Number(x); pt.y = Number(cross.getAttribute('y1'));
            var screen = pt.matrixTransform(svg.getScreenCTM());
            show(v.toLocaleString() + (v === 1 ? ' verification' : ' verifications'), hit.getAttribute('data-label'),
                { left: screen.x, top: screen.y, width: 0 });
        };
        var clear = function () { cross.setAttribute('visibility', 'hidden'); hide(); };
        svg.querySelectorAll('.viz-hit').forEach(function (hit) {
            hit.addEventListener('pointerenter', function () { activate(hit); });
            hit.addEventListener('focus', function () { activate(hit); });
            hit.addEventListener('blur', clear);
        });
        svg.addEventListener('pointerleave', clear);
    }

    // ── Bar lengths ──────────────────────────────────────────────────────
    // The markup carries data-bar="<percent>" instead of a style="" attribute
    // (CSP: no inline styles); the width is applied through the --bar custom
    // property (CSSOM is allowed). Set after two frames so the CSS width
    // transition grows each bar from zero; immediate under reduced motion.
    var reduceMotion = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    var bars = root.querySelectorAll('.viz-bar[data-bar]');
    var sizeBars = function () {
        bars.forEach(function (bar) {
            var pct = parseFloat(bar.getAttribute('data-bar'));
            if (isFinite(pct)) { bar.style.setProperty('--bar', Math.max(0, Math.min(100, pct)) + '%'); }
        });
    };
    if (reduceMotion || !window.requestAnimationFrame) { sizeBars(); }
    else { window.requestAnimationFrame(function () { window.requestAnimationFrame(sizeBars); }); }

    // ── Ranked bars ──────────────────────────────────────────────────────
    root.querySelectorAll('.viz-bar-row').forEach(function (row) {
        var on = function () {
            row.classList.add('is-hover');
            var bar = row.querySelector('.viz-bar');
            show(row.getAttribute('data-value'), row.getAttribute('data-label'), (bar || row).getBoundingClientRect());
        };
        var off = function () { row.classList.remove('is-hover'); hide(); };
        row.addEventListener('pointerenter', on);
        row.addEventListener('pointerleave', off);
        row.addEventListener('focus', on);
        row.addEventListener('blur', off);
    });
})();
