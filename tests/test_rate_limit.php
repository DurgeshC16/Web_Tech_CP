<?php
// tests/test_rate_limit.php
// Boundary tests for the public verification rate limiter.
//
// Contract (VerificationService):
//   - Counter = COUNT(DISTINCT query_value) for one IP inside the window.
//   - The pre-request check counts what is ALREADY logged, so:
//       29 logged distinct -> this request is the 30th -> allowed
//       30 logged distinct -> this request is the 31st -> REJECTED
//     i.e. exactly VERIFY_RATE_MAX (30) successful lookups per window.
//   - Repeats of the same value are free (DISTINCT).
//   - Rows older than the window do not count.
//
// These are DB-level unit tests of the limiter logic; the HTTP wiring in
// public/verify.php is exercised separately by test_verify_http.php.

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/services/VerificationService.php';

$db = test_db();
$IP = '203.0.113.77';           // TEST-NET-3, reserved for documentation
$IP_DUP = '203.0.113.78';
$IP_OLD = '203.0.113.79';

function rl_clear($db, $ip) {
    $db->prepare('DELETE FROM verification_logs WHERE verifier_ip = :ip')->execute(['ip' => $ip]);
}

/** Insert $n distinct rows for $ip; $ageMinutes ages them (>= window => stale). */
function rl_seed($db, $ip, $prefix, $n, $ageMinutes = 0) {
    $sql = 'INSERT INTO verification_logs
                (query_type, query_value, result, verifier_ip, verified_at)
            VALUES ("certificate_id", :qv, "INVALID", :ip, ' .
            ($ageMinutes > 0 ? 'DATE_SUB(NOW(), INTERVAL ' . (int)$ageMinutes . ' MINUTE)' : 'NOW()') . ')';
    $stmt = $db->prepare($sql);
    for ($i = 0; $i < $n; $i++) {
        $stmt->execute(['qv' => $prefix . str_pad((string)$i, 4, '0', STR_PAD_LEFT), 'ip' => $ip]);
    }
}

echo "== rate-limit boundary ==\n";

// 1. Empty window => nothing to limit.
rl_clear($db, $IP);
t_check('empty window: count 0', VerificationService::recentLookupCount($db, $IP) === 0);
t_check('empty window: not limited', VerificationService::isRateLimited($db, $IP) === false);

// 2. 29 distinct logged => the 30th request is still allowed.
rl_clear($db, $IP);
rl_seed($db, $IP, 'A', 29);
t_check('29 logged: count 29', VerificationService::recentLookupCount($db, $IP) === 29);
t_check('29 logged: 30th allowed (not limited)', VerificationService::isRateLimited($db, $IP) === false);

// 3. 30 distinct logged => the 31st request is rejected (limit = 30).
rl_seed($db, $IP, 'B', 1); // 30th distinct
t_check('30 logged: count 30', VerificationService::recentLookupCount($db, $IP) === 30);
t_check('30 logged: 31st rejected (limited)', VerificationService::isRateLimited($db, $IP) === true);

// 4. Exactly at the boundary again: drop one, becomes allowed.
$db->prepare('DELETE FROM verification_logs WHERE verifier_ip = :ip ORDER BY id DESC LIMIT 1')
   ->execute(['ip' => $IP]);
t_check('29 logged again: not limited', VerificationService::isRateLimited($db, $IP) === false);

// 5. Repeated identical lookups never count more than once.
rl_clear($db, $IP_DUP);
for ($i = 0; $i < 40; $i++) {
    $db->prepare('INSERT INTO verification_logs
                    (query_type, query_value, result, verifier_ip)
                  VALUES ("certificate_id", "SAME-VALUE", "INVALID", :ip)')
       ->execute(['ip' => $IP_DUP]);
}
t_check('40 repeats of one value: count 1', VerificationService::recentLookupCount($db, $IP_DUP) === 1);
t_check('40 repeats of one value: not limited', VerificationService::isRateLimited($db, $IP_DUP) === false);

// 6. Rows older than the window are ignored (window resets).
rl_clear($db, $IP_OLD);
rl_seed($db, $IP_OLD, 'O', 30, 11); // 11 minutes old > 10-minute window
t_check('30 stale (11min) rows: count 0', VerificationService::recentLookupCount($db, $IP_OLD) === 0);
t_check('30 stale rows: not limited', VerificationService::isRateLimited($db, $IP_OLD) === false);

// 7. Mixed: 20 stale + 30 fresh => limit driven only by fresh.
rl_clear($db, $IP_OLD);
rl_seed($db, $IP_OLD, 'S', 20, 11);
rl_seed($db, $IP_OLD, 'F', 30);
t_check('20 stale + 30 fresh: count 30', VerificationService::recentLookupCount($db, $IP_OLD) === 30);
t_check('20 stale + 30 fresh: limited', VerificationService::isRateLimited($db, $IP_OLD) === true);

// Cleanup test fixtures.
rl_clear($db, $IP);
rl_clear($db, $IP_DUP);
rl_clear($db, $IP_OLD);

exit(t_summary('test_rate_limit') ? 0 : 1);
