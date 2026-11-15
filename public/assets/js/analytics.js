/*
 * public/assets/js/analytics.js — hover / keyboard layer for analytics.php.
 * Tooltips enhance, never gate: every value is also printed on the page or
 * in the "Show as table" view. Text is inserted with textContent only.
 *   • daily chart: a crosshair snaps to the day under the pointer (or the
 *     focused day) and the tooltip shows value + date
 *   • ranked bars: the hovered/focused row lifts and shows its value
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
