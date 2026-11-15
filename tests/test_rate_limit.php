<?php
// tests/test_rate_limit.php
// Boundary tests for the public verification rate limiter.
//
// Contract (VerificationService::checkAndRecordLookup, migration 014):
//   - Gate runs BEFORE any certificate query and records the lookup key.
//   - Exactly VERIFY_RATE_MAX (30) distinct keys per IP per window are
//     allowed; the 31st distinct key is REJECTED and not recorded.
//   - Repeating a key already in the window is free, even when full.
//   - Keys older than the window do not count and are pruned.
//   - State is bounded: never more than 30 live rows per IP.
//   - Without the verify_rate table the legacy COUNT(DISTINCT) query over
//     verification_logs is used (same boundary).

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/services/VerificationService.php';

$db = test_db();
$db->exec(file_get_contents(__DIR__ . '/../database/migrations/014_verify_rate_limiter.sql'));

$IP     = '203.0.113.77';   // TEST-NET-3, reserved for documentation
$IP_DUP = '203.0.113.78';
$IP_OLD = '203.0.113.79';
$IP_LEG = '203.0.113.80';
$IP_BIG = '203.0.113.81';
$MAX = VerificationService::VERIFY_RATE_MAX;

function rl_clear($db, $ip) {
    $db->prepare('DELETE FROM verify_rate WHERE ip = :ip')->execute(['ip' => $ip]);
    $db->prepare('DELETE FROM verification_logs WHERE verifier_ip = :ip')->execute(['ip' => $ip]);
}
function rl_lookup($db, $ip, $key) {
    return VerificationService::checkAndRecordLookup($db, $ip, $key);
}
function rl_rows($db, $ip) {
    $s = $db->prepare('SELECT COUNT(*) FROM verify_rate WHERE ip = :ip');
    $s->execute(['ip' => $ip]);
    return (int)$s->fetchColumn();
}

echo "== rate-limit boundary (verify_rate) ==\n";

// 1. Empty window.
rl_clear($db, $IP);
t_check('empty window: count 0', VerificationService::recentLookupCount($db, $IP) === 0);
t_check('empty window: not limited', VerificationService::isRateLimited($db, $IP) === false);

// 2. 30 distinct lookups are all allowed; the 31st distinct is refused.
$allowed = 0;
for ($i = 1; $i <= $MAX; $i++) {
    $allowed += rl_lookup($db, $IP, "key-$i")['limited'] ? 0 : 1;
}
t_check('30 distinct lookups all allowed', $allowed === $MAX);
t_check('after 30: count 30', VerificationService::recentLookupCount($db, $IP) === $MAX);
$r31 = rl_lookup($db, $IP, 'key-31');
t_check('31st distinct lookup rejected', $r31['limited'] === true);
t_check('rejected key is not recorded', rl_rows($db, $IP) === $MAX);

// 3. A key already in the window stays free even when the window is full.
t_check('repeat of a seen key allowed while full', rl_lookup($db, $IP, 'key-7')['limited'] === false);

// 4. Expire one key → a new one fits again.
$db->prepare('UPDATE verify_rate SET seen_at = DATE_SUB(NOW(), INTERVAL 11 MINUTE) WHERE ip = :ip AND value_hash = :h')
   ->execute(['ip' => $IP, 'h' => hash('sha256', 'key-1')]);
t_check('one key expired: new key allowed', rl_lookup($db, $IP, 'key-new')['limited'] === false);
t_check('expired key was pruned (still 30 rows)', rl_rows($db, $IP) === $MAX);

// 5. 40 repeats of one value count once.
rl_clear($db, $IP_DUP);
for ($i = 0; $i < 40; $i++) {
    rl_lookup($db, $IP_DUP, 'SAME-VALUE');
}
t_check('40 repeats of one value: count 1', VerificationService::recentLookupCount($db, $IP_DUP) === 1);
t_check('40 repeats of one value: not limited', VerificationService::isRateLimited($db, $IP_DUP) === false);

// 6. Stale rows never count.
rl_clear($db, $IP_OLD);
$stale = $db->prepare('INSERT INTO verify_rate (ip, value_hash, seen_at) VALUES (:ip, :h, DATE_SUB(NOW(), INTERVAL 11 MINUTE))');
for ($i = 0; $i < $MAX; $i++) {
    $stale->execute(['ip' => $IP_OLD, 'h' => hash('sha256', "old-$i")]);
}
t_check('30 stale rows: count 0', VerificationService::recentLookupCount($db, $IP_OLD) === 0);
t_check('30 stale rows: new lookup allowed', rl_lookup($db, $IP_OLD, 'fresh')['limited'] === false);
t_check('stale rows pruned on next lookup', rl_rows($db, $IP_OLD) === 1);

// 7. Bounded state under a flood of distinct keys.
rl_clear($db, $IP_BIG);
$rejected = 0;
for ($i = 0; $i < 100; $i++) {
    $rejected += rl_lookup($db, $IP_BIG, "flood-$i")['limited'] ? 1 : 0;
}
t_check('flood of 100: 70 rejected', $rejected === 70);
t_check('flood of 100: at most 30 rows stored', rl_rows($db, $IP_BIG) === $MAX);

// 8. Cost does not grow with audit-log history: 30 000 logged rows for the
//    IP are irrelevant to the new gate (printed, not asserted — timing).
$db->beginTransaction();
$ins = $db->prepare('INSERT INTO verification_logs (query_type, query_value, result, verifier_ip) VALUES ("certificate_id", :qv, "INVALID", :ip)');
for ($i = 0; $i < 30000; $i++) {
    $ins->execute(['qv' => "hist-$i", 'ip' => $IP_BIG]);
}
$db->commit();
$t0 = hrtime(true);
for ($i = 0; $i < 50; $i++) { rl_lookup($db, $IP_BIG, 'flood-1'); }
$newMs = (hrtime(true) - $t0) / 1e6 / 50;
$t0 = hrtime(true);
for ($i = 0; $i < 50; $i++) {
    $s = $db->prepare('SELECT COUNT(DISTINCT query_value) FROM verification_logs WHERE verifier_ip = :ip AND verified_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)');
    $s->execute(['ip' => $IP_BIG]); $s->fetchColumn();
}
$oldMs = (hrtime(true) - $t0) / 1e6 / 50;
printf("INFO gate with 30k logged rows: new %.2f ms vs legacy query %.2f ms\n", $newMs, $oldMs);
t_check('new gate faster than legacy query at 30k rows', $newMs < $oldMs);

// 9. Legacy fallback when migration 014 is not applied.
rl_clear($db, $IP_LEG);
$db->exec('RENAME TABLE verify_rate TO verify_rate_off');
try {
    $seed = $db->prepare('INSERT INTO verification_logs (query_type, query_value, result, verifier_ip) VALUES ("certificate_id", :qv, "INVALID", :ip)');
    for ($i = 0; $i < $MAX - 1; $i++) {
        $seed->execute(['qv' => "L$i", 'ip' => $IP_LEG]);
    }
    t_check('legacy: 29 logged → allowed', rl_lookup($db, $IP_LEG, 'x')['limited'] === false);
    $seed->execute(['qv' => 'L-last', 'ip' => $IP_LEG]);
    t_check('legacy: 30 logged → limited', rl_lookup($db, $IP_LEG, 'y')['limited'] === true);
    t_check('legacy: recentLookupCount = 30', VerificationService::recentLookupCount($db, $IP_LEG) === $MAX);
} finally {
    $db->exec('RENAME TABLE verify_rate_off TO verify_rate');
}

foreach ([$IP, $IP_DUP, $IP_OLD, $IP_LEG, $IP_BIG] as $ip) {
    rl_clear($db, $ip);
}

exit(t_summary('test_rate_limit') ? 0 : 1);
