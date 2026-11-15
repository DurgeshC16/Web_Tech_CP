<?php
// tests/test_analytics.php — AnalyticsService (institution analytics page).
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/services/AnalyticsService.php';

// ── Helpers ───────────────────────────────────────────────────────────
t_check('niceScale(0) -> 0..4 step 1', AnalyticsService::niceScale(0) === [4, 1]);
t_check('niceScale(28) -> 0..30 step 10', AnalyticsService::niceScale(28) === [30, 10]);
t_check('niceScale(41) -> 0..60 step 20', AnalyticsService::niceScale(41) === [60, 20]);
t_check('niceScale(1234) -> 0..1500 step 500', AnalyticsService::niceScale(1234) === [1500, 500]);
t_check('compact numbers', AnalyticsService::compact(1284) === '1,284' && AnalyticsService::compact(12940) === '12.9K' && AnalyticsService::compact(4200000) === '4.2M');
t_check('range normalised to 7/30/90 (default 30)', AnalyticsService::normaliseRange('7') === 7 && AnalyticsService::normaliseRange('9999') === 30 && AnalyticsService::normaliseRange('x') === 30);

// ── Summary over a controlled data set ────────────────────────────────
$db = test_db();
$tag = bin2hex(random_bytes(4));
$db->beginTransaction();
try {
    $mk = function (string $name) use ($db, $tag) {
        $db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "admin", 1)')->execute(['e' => "an-$name-$tag@example.com"]);
        $db->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:u, :n, "approved")')->execute(['u' => $db->lastInsertId(), 'n' => "An $name $tag"]);
        return (int)$db->lastInsertId();
    };
    $mine = $mk('mine');
    $other = $mk('other');
    $db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "student", 1)')->execute(['e' => "an-stu-$tag@example.com"]);
    $db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "An Student")')->execute(['u' => $db->lastInsertId()]);
    $sid = (int)$db->lastInsertId();
    $cert = $db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, file_path, status, key_id)
                          VALUES (:c, :i, :s, :t, "2025-01-01", "x.pdf", "active", 1)');
    test_insert_institution_key($db, $mine, 'k', 'k');
    test_insert_institution_key($db, $other, 'k', 'k');
    $cert->execute(['c' => "AN-A-$tag", 'i' => $mine, 's' => $sid, 't' => 'Course A']);
    $cert->execute(['c' => "AN-B-$tag", 'i' => $mine, 's' => $sid, 't' => 'Course B']);
    $cert->execute(['c' => "AN-X-$tag", 'i' => $other, 's' => $sid, 't' => 'Other Inst']);

    $today = '2026-11-15';                                // the range crosses the DST change of 2026-10-25
    $log = $db->prepare('INSERT INTO verification_logs (query_type, query_value, certificate_id_found, result, verifier_ip, verified_at)
                         VALUES ("token", "q", :c, :r, :ip, :t)');
    $rows = [
        ["AN-A-$tag", 'VALID', '203.0.113.1', '2026-11-15 09:00:00'],
        ["AN-A-$tag", 'VALID', '203.0.113.2', '2026-11-15 23:59:00'],
        ["AN-A-$tag", 'TAMPERED', '203.0.113.2', '2026-11-01 12:00:00'],
        ["AN-B-$tag", 'EXPIRED', '203.0.113.3', '2026-10-17 00:30:00'],   // first day of the 30-day range
        ["AN-B-$tag", 'VALID', '203.0.113.3', '2026-10-16 23:00:00'],     // previous period
        ["AN-X-$tag", 'VALID', '203.0.113.9', '2026-11-10 10:00:00'],     // other institution: excluded
        [null, 'INVALID', '203.0.113.9', '2026-11-10 10:00:00'],          // unattributed: excluded
    ];
    foreach ($rows as [$c, $r, $ip, $t]) { $log->execute(['c' => $c, 'r' => $r, 'ip' => $ip, 't' => $t]); }

    $s = AnalyticsService::summary($db, $mine, 30, $today);
    t_check('30 calendar days across the DST change, no gaps or repeats', count($s['daily']) === 30
        && array_key_first($s['daily']) === '2026-10-17' && array_key_last($s['daily']) === '2026-11-15');
    t_check('total counts only this institution\'s certificates', $s['total'] === 4);
    t_check('per-day counts (incl. 23:59 and first-day 00:30)', $s['daily']['2026-11-15'] === 2 && $s['daily']['2026-10-17'] === 1 && $s['daily']['2026-11-01'] === 1);
    t_check('previous period counted separately', $s['previous'] === 1);
    t_check('verdict mix', $s['verdicts']['VALID'] === 2 && $s['verdicts']['TAMPERED'] === 1 && $s['verdicts']['EXPIRED'] === 1 && $s['valid'] === 2);
    t_check('distinct verifiers', $s['verifiers'] === 3);
    t_check('top certificates ranked', $s['top'][0]['certificate_id'] === "AN-A-$tag" && $s['top'][0]['count'] === 3 && count($s['top']) === 2);
    t_check('active certificate count', $s['certificates'] === 2);
    $s7 = AnalyticsService::summary($db, $mine, 7, $today);
    t_check('7-day range re-scopes every figure', count($s7['daily']) === 7 && $s7['total'] === 2 && $s7['previous'] === 0);
} finally {
    $db->rollBack();
}

exit(t_summary('test_analytics') ? 0 : 1);
