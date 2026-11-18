/*
 * public/assets/js/admin-ui.js — presentation-only enhancements for the
 * institution / super-admin pages. Loaded with `defer` (after ui.js) from
 * the admin pages; every behaviour is opt-in through markup and is purely
 * progressive: with JS off the forms, links and tables work unchanged and
 * the server validates everything.
 *
 *   [data-pct="42"]                sets --pct: 42% (KPI meters)
 *   [data-share="17"]              sets --share: 17 (audit outcome bar)
 *   .upload-zone                   drag-over highlight + .has-file state
 *   input[data-table-filter="id"]  instant client-side row filter for
 *                                  table#id (data-filter-count="id",
 *                                  data-filter-empty="id")
 *   [data-char-count="fieldId"]    live character counter (data-min/max)
 *   [data-preview-from="fieldId"]  mirrors a field into a live preview
 *                                  (data-preview-format="date")
 * Values are written with textContent / CSSOM only (CSP-safe).
 */
(function () {
    'use strict';
    var reduce = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    var later = function (fn) {
        if (reduce || !window.requestAnimationFrame) { fn(); return; }
        window.requestAnimationFrame(function () { window.requestAnimationFrame(fn); });
    };

    // ── CSS custom properties from data attributes ─────────────────────
    document.querySelectorAll('[data-pct]').forEach(function (el) {
        var v = parseFloat(el.getAttribute('data-pct'));
        if (!isFinite(v)) { return; }
        later(function () { el.style.setProperty('--pct', Math.max(0, Math.min(100, v)) + '%'); });
    });
    document.querySelectorAll('[data-share]').forEach(function (el) {
        var v = parseFloat(el.getAttribute('data-share'));
        if (isFinite(v) && v >= 0) { el.style.setProperty('--share', String(v)); }
    });

    // ── Upload drop zones ──────────────────────────────────────────────
    document.querySelectorAll('.upload-zone').forEach(function (zone) {
        var input = zone.querySelector('input[type=file]');
        if (!input) { return; }
        var depth = 0;
        zone.addEventListener('dragenter', function () { depth++; zone.classList.add('is-dragover'); });
        zone.addEventListener('dragleave', function () {
            depth = Math.max(0, depth - 1);
            if (!depth) { zone.classList.remove('is-dragover'); }
        });
        zone.addEventListener('drop', function () { depth = 0; zone.classList.remove('is-dragover'); });
        var sync = function () { zone.classList.toggle('has-file', !!(input.files && input.files.length)); };
        input.addEventListener('change', sync);
        sync();
    });

    // ── Instant table filter ───────────────────────────────────────────
    document.querySelectorAll('input[data-table-filter]').forEach(function (input) {
        var table = document.getElementById(input.getAttribute('data-table-filter'));
        if (!table || !table.tBodies[0]) { return; }
        var rows = Array.prototype.slice.call(table.tBodies[0].rows);
        var count = document.getElementById(input.getAttribute('data-filter-count') || '');
        var empty = document.getElementById(input.getAttribute('data-filter-empty') || '');
        var total = rows.length;
        var initial = count ? count.textContent : '';
        input.addEventListener('input', function () {
            var q = input.value.trim().toLowerCase();
            var shown = 0;
            rows.forEach(function (r) {
                var hit = !q || r.textContent.toLowerCase().indexOf(q) !== -1;
                r.hidden = !hit;
                if (hit) { shown++; }
            });
            if (count) { count.textContent = q ? shown + ' of ' + total + ' shown' : initial; }
            if (empty) { empty.hidden = shown !== 0; }
        });
    });

    // ── Character counters ─────────────────────────────────────────────
    document.querySelectorAll('[data-char-count]').forEach(function (out) {
        var field = document.getElementById(out.getAttribute('data-char-count'));
        if (!field) { return; }
        var min = parseInt(out.getAttribute('data-min') || '0', 10);
        var max = parseInt(out.getAttribute('data-max') || '0', 10);
        var render = function () {
            var n = field.value.trim().length;
            out.textContent = n + (max ? ' / ' + max : '') + (min && n < min ? ' · at least ' + min : '');
            out.classList.toggle('is-under', !!min && n > 0 && n < min);
            out.classList.toggle('is-over', !!max && n > max);
            out.classList.toggle('is-ok', n >= min && n > 0 && (!max || n <= max));
        };
        field.addEventListener('input', render);
        render();
    });

    // ── Live preview (issue form) ──────────────────────────────────────
    var previews = Array.prototype.slice.call(document.querySelectorAll('[data-preview-from]'));
    if (previews.length) {
        var renderAll = function () {
            previews.forEach(function (out) {
                var src = document.getElementById(out.getAttribute('data-preview-from'));
                if (!src) { return; }
                if (!out.hasAttribute('data-preview-empty')) { out.setAttribute('data-preview-empty', out.textContent); }
                var v = String(src.value || '').trim();
                if (v && out.getAttribute('data-preview-format') === 'date') {
                    var d = new Date(v + 'T00:00:00');
                    if (!isNaN(d.getTime())) { v = d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }); }
                }
                out.textContent = v || out.getAttribute('data-preview-empty');
                out.classList.toggle('is-empty', !v);
            });
        };
        document.addEventListener('input', renderAll);
        // 'change' also catches the expiry date ui.js fills from #validity_years.
        document.addEventListener('change', renderAll);
        renderAll();
    }
})();
