<?php
// public/analytics.php — verification analytics for an institution admin.
// KPI tiles, daily verifications (server-rendered SVG area chart with a
// keyboard/hover tooltip from assets/js/analytics.js), verdict mix and most-
// checked certificates (ranked bars), and a table view of every value.
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/AnalyticsService.php';

require_role('admin');
require_approved_institution();

$db = Database::getInstance();
$institutionId = (int)current_institution_id($db);
$days = AnalyticsService::normaliseRange($_GET['days'] ?? 30);
$s = AnalyticsService::summary($db, $institutionId, $days);
$e = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
$fmtDay = fn($d) => date('M j', strtotime($d));

// ── Area chart geometry ───────────────────────────────────────────────
$W = 720; $H = 236; $L = 44; $R = 20; $T = 18; $B = 200; // plot box; x labels below $B
$n = count($s['daily']);
$dates = array_keys($s['daily']);
$vals = array_values($s['daily']);
[$yMax, $yStep] = AnalyticsService::niceScale(max($vals ?: [0]));
$x = fn($i) => $L + ($n > 1 ? $i * ($W - $L - $R) / ($n - 1) : ($W - $L - $R) / 2);
$y = fn($v) => $B - ($v / $yMax) * ($B - $T);
$pts = [];
foreach ($vals as $i => $v) { $pts[] = round($x($i), 1) . ',' . round($y($v), 1); }
$line = 'M' . implode(' L', $pts);
$area = $line . ' L' . round($x($n - 1), 1) . ',' . $B . ' L' . round($x(0), 1) . ',' . $B . ' Z';
$peakI = $vals ? array_search(max($vals), $vals, true) : 0;
$lastI = $n - 1;
$labelEvery = $days <= 7 ? 1 : ($days <= 30 ? 7 : 15);
$slot = $n > 1 ? ($W - $L - $R) / ($n - 1) : ($W - $L - $R);

$delta = $s['total'] - $s['previous'];
$validShare = $s['total'] > 0 ? round(100 * $s['valid'] / $s['total']) : null;
$verdictTotal = array_sum($s['verdicts']);
$verdictMax = max(array_values($s['verdicts']) ?: [0]);
$topMax = $s['top'] ? max(array_column($s['top'], 'count')) : 0;
$icons = ['VALID' => '✓', 'EXPIRED' => '◷', 'SUPERSEDED' => '↻', 'REVOKED' => '⊘', 'TAMPERED' => '✗', 'INVALID' => '?'];

require_once __DIR__ . '/../src/utils/admin_ui.php';
// Plain integers animate with ui.js counters; compact values ("12K") and
// #kpiTotal (read by the browser test right after load) stay static.
$countAttr = fn(int $n) => $n < 10000 ? ' data-count-to="' . $n . '"' : '';
$page_title = 'Analytics - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main">
    <div class="admin-shell viz-root" id="analytics">
        <header class="admin-head">
            <div class="admin-head-row">
                <span class="admin-head-icon" aria-hidden="true"><?= cv_icon('chart') ?></span>
                <div class="admin-head-text">
                    <ol class="crumbs" aria-label="Breadcrumb"><li><a href="admin_dashboard.php">Dashboard</a></li><li aria-current="page">Analytics</li></ol>
                    <h1>Verification analytics</h1>
                    <p class="admin-head-sub">Who is checking your certificates, how often, and what they saw — <?= $e($fmtDay($s['from'])) ?> to <?= $e($fmtDay($s['to'])) ?>.</p>
                </div>
                <div class="admin-head-actions">
                    <a href="audit_logs.php" class="btn btn-outline-light"><?= cv_icon('history') ?> Audit logs</a>
                    <a href="admin_dashboard.php" class="btn btn-light"><?= cv_icon('arrow-left') ?> Back to Dashboard</a>
                </div>
            </div>
        </header>

        <nav class="viz-filters" aria-label="Date range">
            <?php foreach (AnalyticsService::RANGES as $r): ?>
                <a href="analytics.php?days=<?= $r ?>" class="viz-filter<?= $r === $days ? ' is-active' : '' ?>"
                   <?= $r === $days ? 'aria-current="true"' : '' ?>><?= $r === $days ? '✓ ' : '' ?>Last <?= $r ?> days</a>
            <?php endforeach; ?>
        </nav>

        <section class="viz-kpis" aria-label="Key figures">
            <div class="viz-tile" data-reveal data-reveal-delay="1">
                <div class="viz-tile-head"><span class="viz-tile-label">Verifications</span><span class="viz-tile-icon" aria-hidden="true"><?= cv_icon('activity') ?></span></div>
                <div class="viz-tile-value" id="kpiTotal"><?= $e(AnalyticsService::compact($s['total'])) ?></div>
                <div class="viz-tile-delta"><span class="delta-pill"><?= $delta === 0 ? 'No change' : ($delta > 0 ? '▲ +' : '▼ ') . $e(number_format($delta)) ?></span> vs previous <?= $days ?> days</div>
            </div>
            <div class="viz-tile" data-reveal data-reveal-delay="2">
                <div class="viz-tile-head"><span class="viz-tile-label">Checks that were VALID</span><span class="viz-tile-icon" aria-hidden="true"><?= cv_icon('shield') ?></span></div>
                <div class="viz-tile-value" id="kpiValid"<?= $validShare === null ? '' : ' data-count-to="' . (int)$validShare . '" data-count-suffix="%"' ?>><?= $validShare === null ? '—' : $validShare . '%' ?></div>
                <div class="viz-tile-delta"><?= $e(number_format($s['valid'])) ?> of <?= $e(number_format($s['total'])) ?></div>
            </div>
            <div class="viz-tile" data-reveal data-reveal-delay="3">
                <div class="viz-tile-head"><span class="viz-tile-label">Distinct verifiers</span><span class="viz-tile-icon" aria-hidden="true"><?= cv_icon('users') ?></span></div>
                <div class="viz-tile-value"<?= $countAttr((int)$s['verifiers']) ?>><?= $e(AnalyticsService::compact($s['verifiers'])) ?></div>
                <div class="viz-tile-delta">unique IP addresses</div>
            </div>
            <div class="viz-tile" data-reveal data-reveal-delay="4">
                <div class="viz-tile-head"><span class="viz-tile-label">Active certificates</span><span class="viz-tile-icon" aria-hidden="true"><?= cv_icon('award') ?></span></div>
                <div class="viz-tile-value"<?= $countAttr((int)$s['certificates']) ?>><?= $e(AnalyticsService::compact($s['certificates'])) ?></div>
                <div class="viz-tile-delta">issued by your institution</div>
            </div>
        </section>

        <section class="viz-card" aria-labelledby="dailyTitle">
            <h2 id="dailyTitle" class="viz-title">Verifications per day</h2>
            <p class="viz-subtitle"><?= $e($fmtDay($s['from'])) ?> – <?= $e($fmtDay($s['to'])) ?> · lookups of your certificates</p>
            <?php if ($s['total'] === 0): ?>
                <div class="empty-state">
                    <span class="empty-state-icon"><?= cv_icon('chart') ?></span>
                    <p class="viz-empty">No verifications in this period yet. Share a certificate's QR code or link to see activity here.</p>
                </div>
            <?php else: ?>
            <div class="viz-chart">
                <svg id="dailyChart" viewBox="0 0 <?= $W ?> <?= $H ?>" role="img"
                     aria-label="Verifications per day, <?= $e($fmtDay($s['from'])) ?> to <?= $e($fmtDay($s['to'])) ?>: total <?= (int)$s['total'] ?>, peak <?= (int)$vals[$peakI] ?> on <?= $e($fmtDay($dates[$peakI])) ?>.">
                    <defs>
                        <linearGradient id="vizAreaFill" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0" class="viz-stop-top"/>
                            <stop offset="1" class="viz-stop-bottom"/>
                        </linearGradient>
                    </defs>
                    <?php for ($t = 0; $t <= $yMax; $t += $yStep): $yy = round($y($t), 1); ?>
                        <line class="viz-grid" x1="<?= $L ?>" x2="<?= $W - $R ?>" y1="<?= $yy ?>" y2="<?= $yy ?>"/>
                        <text class="viz-tick" x="<?= $L - 8 ?>" y="<?= $yy + 4 ?>" text-anchor="end"><?= $e(number_format($t)) ?></text>
                    <?php endfor; ?>
                    <line class="viz-axis" x1="<?= $L ?>" x2="<?= $W - $R ?>" y1="<?= $B ?>" y2="<?= $B ?>"/>
                    <?php foreach ($dates as $i => $d): if ($i % $labelEvery !== 0 && $i !== $lastI) { continue; }
                        if ($i !== $lastI && $lastI - $i < $labelEvery / 2) { continue; } ?>
                        <text class="viz-tick" x="<?= round($x($i), 1) ?>" y="<?= $B + 20 ?>" text-anchor="<?= $i === 0 ? 'start' : ($i === $lastI ? 'end' : 'middle') ?>"><?= $e($fmtDay($d)) ?></text>
                    <?php endforeach; ?>
                    <path class="viz-area" d="<?= $area ?>"/>
                    <path class="viz-line" d="<?= $line ?>" pathLength="1"/>
                    <line class="viz-crosshair" id="dailyCrosshair" x1="0" x2="0" y1="<?= $T ?>" y2="<?= $B ?>" visibility="hidden"/>
                    <?php foreach (array_unique([$peakI, $lastI]) as $li): ?>
                        <circle class="viz-dot" cx="<?= round($x($li), 1) ?>" cy="<?= round($y($vals[$li]), 1) ?>" r="4"/>
                        <?php // Latest value sits beside its dot (clear of gridlines); the peak sits above. ?>
                        <text class="viz-label" x="<?= round($x($li), 1) + ($li === $lastI ? -10 : 0) ?>" y="<?= round($y($vals[$li]), 1) + ($li === $lastI ? 4 : -10) ?>"
                              text-anchor="<?= $li === $lastI ? 'end' : 'middle' ?>"><?= (int)$vals[$li] ?></text>
                    <?php endforeach; ?>
                    <?php foreach ($dates as $i => $d): ?>
                        <rect class="viz-hit" x="<?= round(max($L - $slot / 2, $x($i) - $slot / 2), 1) ?>" y="<?= $T ?>"
                              width="<?= round(max(24, $slot), 1) ?>" height="<?= $B - $T ?>" tabindex="0"
                              data-x="<?= round($x($i), 1) ?>" data-label="<?= $e($fmtDay($d)) ?>" data-value="<?= (int)$vals[$i] ?>"
                              aria-label="<?= $e($fmtDay($d)) ?>: <?= (int)$vals[$i] ?> verification<?= $vals[$i] === 1 ? '' : 's' ?>"/>
                    <?php endforeach; ?>
                </svg>
                <div class="viz-tooltip" id="vizTooltip" role="status" hidden><strong></strong><span></span></div>
            </div>
            <?php endif; ?>
            <details class="viz-table">
                <summary>Show as table</summary>
                <div class="table-wrap"><table class="data-table" id="dailyTable">
                    <thead><tr><th scope="col">Date</th><th scope="col" class="num">Verifications</th></tr></thead>
                    <tbody><?php foreach ($s['daily'] as $d => $v): ?><tr><td><?= $e($d) ?></td><td class="num"><?= (int)$v ?></td></tr><?php endforeach; ?></tbody>
                </table></div>
            </details>
        </section>

        <div class="viz-grid-2">
            <section class="viz-card" aria-labelledby="verdictTitle" data-reveal>
                <h2 id="verdictTitle" class="viz-title">Verdict mix</h2>
                <p class="viz-subtitle">What verifiers saw, <?= $days ?> days</p>
                <?php if ($verdictTotal === 0): ?>
                    <p class="viz-empty">No verdicts recorded in this period.</p>
                <?php else: ?>
                <ul class="viz-bars" id="verdictBars">
                    <?php foreach ($s['verdicts'] as $v => $count): if ($count === 0) { continue; } $pct = round(100 * $count / $verdictTotal); $vk = strtolower($v); ?>
                        <li class="viz-bar-row" tabindex="0" data-label="<?= $e($v) ?>" data-value="<?= $count ?> (<?= $pct ?>%)">
                            <span class="viz-bar-name"><span class="verdict-glyph verdict-glyph-<?= $e($vk) ?>" aria-hidden="true"><?= $icons[$v] ?></span> <?= $e(ucfirst(strtolower($v))) ?></span>
                            <span class="viz-bar-track"><span class="viz-bar viz-bar-<?= $e($vk) ?>" data-bar="<?= max(1, round(100 * $count / $verdictMax, 1)) ?>"></span></span>
                            <span class="viz-bar-value"><?= $e(number_format($count)) ?> · <?= $pct ?>%</span>
                        </li>
                    <?php endforeach; ?>
                </ul>
                <?php endif; ?>
            </section>

            <section class="viz-card" aria-labelledby="topTitle" data-reveal data-reveal-delay="1">
                <h2 id="topTitle" class="viz-title">Most-checked certificates</h2>
                <p class="viz-subtitle">Top <?= count($s['top']) ?: 5 ?>, <?= $days ?> days</p>
                <?php if (!$s['top']): ?>
                    <p class="viz-empty">No certificate was checked in this period.</p>
                <?php else: ?>
                <ul class="viz-bars" id="topBars">
                    <?php foreach ($s['top'] as $t): ?>
                        <li class="viz-bar-row" tabindex="0" data-label="<?= $e($t['certificate_id']) ?>" data-value="<?= (int)$t['count'] ?> checks">
                            <span class="viz-bar-name"><a href="verify.php?certificate_id=<?= rawurlencode($t['certificate_id']) ?>"><?= $e($t['certificate_id']) ?></a><br><small><?= $e($t['title']) ?></small></span>
                            <span class="viz-bar-track"><span class="viz-bar" data-bar="<?= max(1, round(100 * $t['count'] / $topMax, 1)) ?>"></span></span>
                            <span class="viz-bar-value"><?= $e(number_format($t['count'])) ?></span>
                        </li>
                    <?php endforeach; ?>
                </ul>
                <?php endif; ?>
            </section>
        </div>
        <p class="viz-footnote">Counts lookups that resolved to your certificates (QR scans, typed IDs, file uploads, reports,
            credential exports and status API calls). Lookups that matched no certificate cannot be attributed to an institution.</p>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
<script src="assets/js/analytics.js"></script>
</body>
</html>
