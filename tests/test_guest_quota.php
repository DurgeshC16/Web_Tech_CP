<?php
// tests/test_guest_quota.php
// Guest free-verification quota (GuestQuotaService, migration 017).
//
// Contract:
//   - Visitors who are not logged in get `limit` (default 5) distinct
//     verifications per rolling window; the next distinct one is refused
//     and NOT recorded. Repeating a key (or an alias such as the
//     certificate itself) already used in the window is free.
//   - Two counters, per client IP (server-side, HMAC'd IP) and per session;
//     the guest is limited when EITHER is full (clearing cookies or
//     changing IP alone does not reset it).
//   - Logged-in users (live session, any role) are exempt; limit 0 = off.
//   - Old rows expire and are pruned; alias rows are capped (bounded).
//   - Missing table: the IP counter fails OPEN (session counter still works).
// The second half runs verify.php / report.php over real HTTP (php -S) with
// the quota ENABLED (limit 5) and checks the visible UX.

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/GuestQuotaService.php';

$db = test_db();
$db->exec(file_get_contents(__DIR__ . '/../database/migrations/017_guest_verify_quota.sql'));

const GQ_LIMIT  = 5;
const GQ_WINDOW = 86400;

function gq_clear($db, string $ip): void {
    $db->prepare('DELETE FROM guest_verify_quota WHERE subject_hash = :s')
       ->execute(['s' => GuestQuotaService::subjectHash($ip)]);
}
function gq_rows($db, string $ip, ?int $credit = null): int {
    $sql = 'SELECT COUNT(*) FROM guest_verify_quota WHERE subject_hash = :s' . ($credit === null ? '' : ' AND is_credit = ' . (int)$credit);
    $st = $db->prepare($sql);
    $st->execute(['s' => GuestQuotaService::subjectHash($ip)]);
    return (int)$st->fetchColumn();
}
function gq_check($db, string $ip, array &$sess, array $keys, int $limit = GQ_LIMIT) {
    return GuestQuotaService::check($db, $ip, $sess, $keys, $limit, GQ_WINDOW);
}
function gq_record($db, string $ip, array &$sess, array $keys, int $limit = GQ_LIMIT) {
    return GuestQuotaService::record($db, $ip, $sess, $keys, $limit, GQ_WINDOW);
}

// TEST-NET-2 addresses (reserved for documentation).
$IP_A = '198.51.100.21';
$IP_B = '198.51.100.22';
$IP_C = '198.51.100.23';
$IP_D = '198.51.100.24';
foreach ([$IP_A, $IP_B, $IP_C, $IP_D] as $ip) {
    gq_clear($db, $ip);
}

echo "== guest quota: unit (GuestQuotaService) ==\n";

// ── 1. Boundary: 5 distinct lookups allowed, the 6th refused ───────────
$s1 = [];
$st = gq_check($db, $IP_A, $s1, []);
t_check('fresh guest: 5 of 5 left', $st['allowed'] && $st['remaining'] === 5 && $st['used'] === 0 && !$st['exempt']);
$okAll = true; $remainingSeq = [];
for ($i = 1; $i <= GQ_LIMIT; $i++) {
    $c = gq_check($db, $IP_A, $s1, ["token:k$i"]);
    $okAll = $okAll && $c['allowed'];
    $r = gq_record($db, $IP_A, $s1, ["token:k$i", "cert:cv-2026-00000$i"]);
    $remainingSeq[] = $r['remaining'];
}
t_check('5 distinct lookups all allowed', $okAll);
t_check('remaining counts down 4,3,2,1,0', $remainingSeq === [4, 3, 2, 1, 0]);
t_check('5 credit rows stored for the IP', gq_rows($db, $IP_A, 1) === 5);
$c6 = gq_check($db, $IP_A, $s1, ['token:k6']);
t_check('6th distinct lookup refused', $c6['allowed'] === false && $c6['remaining'] === 0);
t_check('limited status carries a reset time within the window', is_int($c6['resets_in']) && $c6['resets_in'] > GQ_WINDOW - 120 && $c6['resets_in'] <= GQ_WINDOW);
$r6 = gq_record($db, $IP_A, $s1, ['token:k6']);
t_check('record() past the limit refuses and stores nothing', $r6['allowed'] === false && gq_rows($db, $IP_A, 1) === 5 && gq_rows($db, $IP_A) === 10);

// ── 2. Repeats are free, also when full ─────────────────────────────────
$rep = gq_check($db, $IP_A, $s1, ['token:k3']);
t_check('repeat key allowed while full', $rep['allowed'] && $rep['repeat']);
$repR = gq_record($db, $IP_A, $s1, ['token:k3']);
t_check('repeat does not consume a credit', $repR['used'] === 5 && gq_rows($db, $IP_A, 1) === 5);
$alias = gq_check($db, $IP_A, $s1, ['cert:cv-2026-000002']);
t_check('certificate alias counts as a repeat (report of a verified cert)', $alias['allowed'] && $alias['repeat']);

// ── 3. Session vs IP counters ──────────────────────────────────────────
$s2 = []; // cookies cleared, same IP
t_check('new session on a full IP is still refused (server-side counter)', gq_check($db, $IP_A, $s2, ['token:fresh'])['allowed'] === false);
$s1b = $s1; // same session, IP changed (mobile network)
t_check('full session on a NEW IP is still refused (session counter)', gq_check($db, $IP_B, $s1b, ['token:fresh'])['allowed'] === false);
t_check('the new IP itself is untouched', gq_rows($db, $IP_B) === 0);
$s3 = [];
gq_record($db, $IP_B, $s3, ['token:b1']);
t_check('IP counter is per IP (other IP has its own 4 left)', gq_check($db, $IP_B, $s3, [])['remaining'] === 4);

// ── 4. Logged-in users are exempt ──────────────────────────────────────
foreach (['student', 'admin', 'super_admin'] as $role) {
    $auth = ['user_id' => 42, 'role' => $role, 'login_time' => time(), 'last_activity' => time()];
    $ex = gq_check($db, $IP_A, $auth, ['token:k99']);
    t_check("logged-in $role exempt on a full IP", $ex['allowed'] && $ex['exempt']);
}
$auth = ['user_id' => 42, 'role' => 'student', 'login_time' => time(), 'last_activity' => time()];
$before = gq_rows($db, $IP_A);
gq_record($db, $IP_A, $auth, ['token:k100']);
t_check('logged-in lookups are not recorded', gq_rows($db, $IP_A) === $before && empty($auth[GuestQuotaService::SESSION_KEY]));
$idle = ['user_id' => 42, 'role' => 'student', 'login_time' => time() - 4000, 'last_activity' => time() - 4000];
t_check('idle-expired login is treated as a guest', GuestQuotaService::isAuthenticated($idle) === false
    && gq_check($db, $IP_A, $idle, ['token:k101'])['allowed'] === false);
t_check('renderCounter is empty for exempt users', GuestQuotaService::renderCounter(gq_check($db, $IP_A, $auth, [])) === '');

// ── 5. Quota disabled (limit 0) ────────────────────────────────────────
$s0 = [];
$off = gq_check($db, $IP_A, $s0, ['token:k200'], 0);
t_check('limit 0: allowed even on a full IP', $off['allowed'] && $off['enabled'] === false);
$before = gq_rows($db, $IP_A);
gq_record($db, $IP_A, $s0, ['token:k200'], 0);
t_check('limit 0: nothing recorded', gq_rows($db, $IP_A) === $before && $s0 === []);
t_check('limit 0: no counter rendered', GuestQuotaService::renderCounter($off) === '');

// ── 6. Window expiry + pruning (backdated rows) ────────────────────────
$db->prepare('UPDATE guest_verify_quota SET seen_at = DATE_SUB(NOW(), INTERVAL ' . (GQ_WINDOW + 5) . ' SECOND) WHERE subject_hash = :s')
   ->execute(['s' => GuestQuotaService::subjectHash($IP_A)]);
foreach ($s1[GuestQuotaService::SESSION_KEY] as $h => $e) {
    $s1[GuestQuotaService::SESSION_KEY][$h][0] = time() - GQ_WINDOW - 5;
}
$exp = gq_check($db, $IP_A, $s1, ['token:k6']);
t_check('after the window: allowed again with 5 left', $exp['allowed'] && $exp['remaining'] === 5);
t_check('stale IP rows pruned', gq_rows($db, $IP_A) === 0);
t_check('stale session entries pruned', ($s1[GuestQuotaService::SESSION_KEY] ?? []) === []);
// Half-expired: one old credit + four fresh ones = 4 used.
$sc = [];
gq_record($db, $IP_C, $sc, ['token:old']);
$db->prepare('UPDATE guest_verify_quota SET seen_at = DATE_SUB(NOW(), INTERVAL ' . (GQ_WINDOW + 5) . ' SECOND) WHERE subject_hash = :s')
   ->execute(['s' => GuestQuotaService::subjectHash($IP_C)]);
$sc = [];
for ($i = 1; $i <= 4; $i++) {
    gq_record($db, $IP_C, $sc, ["token:c$i"]);
}
t_check('only in-window credits count (rolling window)', gq_check($db, $IP_C, $sc, [])['remaining'] === 1);

// ── 7. Bounded storage: alias rows are capped ──────────────────────────
$sd = [];
gq_record($db, $IP_D, $sd, ['token:d1', 'cert:cv-2026-000777']);
for ($i = 0; $i < GuestQuotaService::MAX_ALIAS_ROWS + 20; $i++) {
    // Same certificate typed many ways: every one is a free repeat.
    gq_record($db, $IP_D, $sd, ["id:variant-$i", 'cert:cv-2026-000777']);
}
t_check('many spellings of one certificate cost one credit', gq_rows($db, $IP_D, 1) === 1);
t_check('alias rows capped per IP', gq_rows($db, $IP_D, 0) <= GuestQuotaService::MAX_ALIAS_ROWS);
t_check('alias entries capped per session', count($sd[GuestQuotaService::SESSION_KEY]) <= GuestQuotaService::MAX_ALIAS_ROWS + GQ_LIMIT);

// ── 8. Privacy: no raw IP or raw key stored ────────────────────────────
$h = GuestQuotaService::subjectHash($IP_D);
t_check('subject hash is an HMAC (not plain SHA-256 of the IP)', $h !== hash('sha256', $IP_D) && $h !== hash('sha256', 'ip:' . $IP_D) && strlen($h) === 64);
$raw = (int)$db->query("SELECT COUNT(*) FROM guest_verify_quota WHERE subject_hash LIKE '%198.51%' OR key_hash LIKE '%token%'")->fetchColumn();
t_check('table holds only hashes', $raw === 0);

// ── 9. Missing table: fail open (session counter still applies) ───────
$noTable = new PDO('sqlite::memory:', null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$sm = [];
$m1 = gq_check($noTable, $IP_A, $sm, ['token:m1']);
t_check('missing table: allowed (fail open) and flagged degraded', $m1['allowed'] && $m1['degraded']);
$okM = true;
for ($i = 1; $i <= GQ_LIMIT; $i++) {
    $okM = $okM && gq_record($noTable, $IP_A, $sm, ["token:m$i"])['allowed'];
}
t_check('missing table: 5 lookups recorded without errors', $okM && count($sm[GuestQuotaService::SESSION_KEY]) === 5);
t_check('missing table: session counter still limits the 6th', gq_check($noTable, $IP_A, $sm, ['token:m6'])['allowed'] === false);
$smFresh = [];
t_check('missing table: a fresh session is never blocked', gq_check($noTable, $IP_A, $smFresh, ['token:m6'])['allowed'] === true);

// ── 10. Rendering ──────────────────────────────────────────────────────
$full = ['enabled' => true, 'exempt' => false, 'allowed' => false, 'repeat' => false, 'used' => 5, 'limit' => 5, 'remaining' => 0, 'resets_in' => 7200, 'degraded' => false];
$notice = GuestQuotaService::renderLimitNotice($full);
t_check('notice: exact headline message', str_contains($notice, "Free verification limit reached — you've used all 5 free verifications. Log in or create a free account to keep verifying certificates."));
t_check('notice: login + register buttons', str_contains($notice, 'href="login.php"') && str_contains($notice, 'href="register_student.php"'));
t_check('notice: reset time shown', str_contains($notice, 'reset in about 2 hours'));
t_check('notice: no inline script/style', !preg_match('/<script|style="/i', $notice));
$counter = GuestQuotaService::renderCounter(['enabled' => true, 'exempt' => false, 'remaining' => 3, 'limit' => 5]);
t_check('counter: "3 of 5 free verifications left today"', str_contains($counter, '3 of 5 free verifications left today') && str_contains($counter, 'login.php'));
t_check('humanDuration minutes', GuestQuotaService::humanDuration(600) === 'in about 10 minutes');

foreach ([$IP_A, $IP_B, $IP_C, $IP_D] as $ip) {
    gq_clear($db, $ip);
}

// ════════════════════════════════════════════════════════════════════════
// HTTP: verify.php / report.php with the quota ENABLED (limit 5)
// ════════════════════════════════════════════════════════════════════════
if (!function_exists('curl_init')) {
    echo "SKIP guest-quota HTTP: curl extension unavailable.\n";
    exit(t_summary('test_guest_quota') ? 0 : 1);
}

$port = (int)(getenv('CV_TEST_GUEST_QUOTA_PORT') ?: 8151);
for ($probe = 0; $probe < 20; $probe++) {          // never hit a foreign server
    $sock = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.3);
    if ($sock === false) {
        break;
    }
    fclose($sock);
    $port++;
}
$base = "http://127.0.0.1:$port";
$appRoot = realpath(__DIR__ . '/../public');
$LOCAL = '127.0.0.1';

// Clean slate for the loopback client: quota rows, limiter rows, and the
// report.php download counter (5 per IP / 10 min, from verification_logs).
gq_clear($db, $LOCAL);
$db->exec(file_get_contents(__DIR__ . '/../database/migrations/014_verify_rate_limiter.sql'));
$db->prepare("DELETE FROM verify_rate WHERE ip = '127.0.0.1'")->execute();
$db->prepare("DELETE FROM verification_logs WHERE verifier_ip = '127.0.0.1'")->execute();

// ── Fixture: one institution, one student (who can log in), 6 certs ──
$instName = 'Guest Quota Fixture Uni';
$email = 'guestquota.student@example.com';
$password = 'GuestQuota#2026!';
$st = $db->prepare('SELECT id FROM institutions WHERE name = :n');
$st->execute(['n' => $instName]);
foreach ($st->fetchAll(PDO::FETCH_COLUMN) as $oldIid) {
    $db->prepare('DELETE FROM certificates WHERE institution_id = :i')->execute(['i' => $oldIid]);
    $db->prepare('DELETE FROM institution_keys WHERE institution_id = :i')->execute(['i' => $oldIid]);
}
$db->prepare('DELETE FROM students WHERE full_name = "Guest Quota Student"')->execute();
$db->prepare('DELETE FROM institutions WHERE name = :n')->execute(['n' => $instName]);
$db->prepare('DELETE FROM users WHERE email IN ("guestquota.admin@example.com", :e)')->execute(['e' => $email]);
$db->prepare("DELETE FROM login_attempts WHERE email = :e")->execute(['e' => $email]);

$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES ("guestquota.admin@example.com", "x", "admin", 1)')->execute();
$adminUid = (int)$db->lastInsertId();
$keys = CryptoService::generateRSAKeyPair();
$db->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:u, :n, "approved")')->execute(['u' => $adminUid, 'n' => $instName]);
$instId = (int)$db->lastInsertId();
test_insert_institution_key($db, $instId, $keys['public_key'], CryptoService::encryptPrivateKey($keys['private_key']));
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, :p, "student", 1)')
   ->execute(['e' => $email, 'p' => password_hash($password, PASSWORD_DEFAULT)]);
$studentUid = (int)$db->lastInsertId();
$db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "Guest Quota Student")')->execute(['u' => $studentUid]);
$studentId = (int)$db->lastInsertId();

$createdFiles = [];
$certs = [];
for ($i = 1; $i <= 6; $i++) {
    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $certId = 'CV-2026-88000' . $i;
    $filename = 'guestquota-' . $token . '.pdf';
    $path = __DIR__ . '/../private_data/uploads/' . $filename;
    file_put_contents($path, "%PDF-1.4 guest quota fixture $token\n" . str_repeat('G', 240));
    $createdFiles[] = $path;
    $data = ['certificate_id' => $certId, 'institution_id' => $instId, 'student_id' => $studentId,
             'title' => 'Guest Quota Fixture', 'issue_date' => '2024-01-01', 'expiry_date' => '2099-01-01'];
    $hash = CryptoService::computeCertificateHash($data, $path);
    $sig  = CryptoService::signCertificateHash($hash, $keys['private_key']);
    $db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, expiry_date, file_path, status, version, qr_token, sha256_hash, digital_signature)
                  VALUES (:cid, :iid, :sid, "Guest Quota Fixture", "2024-01-01", "2099-01-01", :fp, "active", 1, :qr, :h, :s)')
       ->execute(['cid' => $certId, 'iid' => $instId, 'sid' => $studentId, 'fp' => $filename, 'qr' => $token, 'h' => $hash, 's' => $sig]);
    $certs[$i] = ['token' => $token, 'id' => $certId];
}

// ── Server with the quota ON (limit 5, 24 h) ───────────────────────────
$env = getenv();
$env['CV_DB_NAME'] = getenv('CV_TEST_DB') ?: 'certivault_test';
$env['CV_MAIL_TRANSPORT'] = 'file';
$env['CV_ENV'] = 'development';
$env['CV_GUEST_VERIFY_LIMIT'] = '5';
$env['CV_GUEST_VERIFY_WINDOW_SECONDS'] = '86400';
$log = sys_get_temp_dir() . '/cv_guest_quota_http.log';
$proc = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', $appRoot],
    [0 => ['pipe', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']], $pipes, dirname($appRoot), $env);

function gq_http(string $url, ?string $jar = null, ?array $post = null): array {
    $ch = curl_init($url);
    $o = [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 30, CURLOPT_FOLLOWLOCATION => false, CURLOPT_HEADER => true];
    if ($jar !== null) { $o[CURLOPT_COOKIEJAR] = $jar; $o[CURLOPT_COOKIEFILE] = $jar; }
    if ($post !== null) { $o[CURLOPT_POST] = true; $o[CURLOPT_POSTFIELDS] = http_build_query($post); }
    curl_setopt_array($ch, $o);
    $raw = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $hs = (int)curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    curl_close($ch);
    if ($raw === false) {
        return [0, '', ''];
    }
    return [$code, substr($raw, $hs), substr($raw, 0, $hs)];
}
function gq_seal(string $html, string $verdict): bool {
    return preg_match('/verdict-seal-' . strtolower($verdict) . '"/', $html) === 1;
}
function gq_left(string $html): ?int {
    return preg_match('/(\d+) of 5 free verifications? left today/', $html, $m) ? (int)$m[1] : null;
}

$ready = false;
for ($i = 0; $i < 60 && is_resource($proc); $i++) {
    usleep(200000);
    if (gq_http("$base/login.php")[0] === 200) { $ready = true; break; }
}
if (!$ready) {
    if (is_resource($proc)) { proc_terminate($proc); proc_close($proc); }
    echo "SKIP guest-quota HTTP: server did not become ready.\n";
} else {
    echo "== guest quota over real HTTP (php -S :$port, limit 5) ==\n";
    $jar = tempnam(sys_get_temp_dir(), 'cvgq');

    [$code, $land] = gq_http("$base/verify.php", $jar);
    t_check('landing shows 5 of 5 free verifications', $code === 200 && gq_left($land) === 5);

    [$code, $r1] = gq_http("$base/verify.php?token={$certs[1]['token']}", $jar);
    t_check('lookup 1 (token): VALID + 4 left', gq_seal($r1, 'VALID') && gq_left($r1) === 4);
    [, $r1b] = gq_http("$base/verify.php?token={$certs[1]['token']}", $jar);
    t_check('refresh of the same token is free (still 4 left)', gq_seal($r1b, 'VALID') && gq_left($r1b) === 4);
    [, $mal] = gq_http("$base/verify.php?token=tooshort", $jar);
    t_check('malformed token: INVALID and no credit used', gq_seal($mal, 'INVALID') && gq_left($mal) === 4);
    [$rcode] = gq_http("$base/report.php?cert=" . rawurlencode($certs[1]['id']), $jar);
    [, $afterReport] = gq_http("$base/verify.php", $jar);
    t_check('report of an already verified certificate is not refused', $rcode !== 429 && $rcode !== 0);
    t_check('report of an already verified certificate costs nothing', gq_left($afterReport) === 4);

    [, $r2] = gq_http("$base/verify.php?token={$certs[2]['token']}", $jar);
    t_check('lookup 2 (token): VALID + 3 left', gq_seal($r2, 'VALID') && gq_left($r2) === 3);
    [, $r3] = gq_http("$base/verify.php?certificate_id=" . rawurlencode($certs[3]['id']), $jar);
    t_check('lookup 3 (?certificate_id=): VALID + 2 left', gq_seal($r3, 'VALID') && gq_left($r3) === 2);
    preg_match('/name="csrf_token" value="([^"]+)"/', $land, $m);
    // Long Smart Verify text: the ID sits AFTER char 512. The lookup key
    // must cover the whole input (a key truncated at 512 chars made every
    // later "same prefix + other ID" a free repeat — quota/limiter bypass).
    $pad = str_repeat('x ', 300);
    [, $r4] = gq_http("$base/verify.php", $jar, ['csrf_token' => $m[1] ?? '', 'smart_id' => $pad . $certs[4]['id'], 'issuer' => 'certivault']);
    t_check('lookup 4 (Smart Verify POST, long text): VALID + 1 left', gq_seal($r4, 'VALID') && gq_left($r4) === 1);
    [, $r5] = gq_http("$base/verify.php?token={$certs[5]['token']}", $jar);
    t_check('lookup 5 (token): VALID, no free verification left', gq_seal($r5, 'VALID') && gq_left($r5) === 0);

    [$c6, $r6, $h6] = gq_http("$base/verify.php?token={$certs[6]['token']}", $jar);
    t_check('lookup 6: HTTP 429', $c6 === 429);
    t_check('lookup 6: Retry-After header', stripos($h6, 'Retry-After:') !== false);
    t_check('lookup 6: limit-reached message', str_contains($r6, 'Free verification limit reached')
        && str_contains($r6, 'used all 5 free verifications'));
    t_check('lookup 6: login + register buttons', str_contains($r6, 'href="login.php"') && str_contains($r6, 'href="register_student.php"'));
    t_check('lookup 6: NO verdict seal (lookup never ran)', !str_contains($r6, 'verdict-seal'));
    t_check('lookup 6: no inline <script> blocks', preg_match('/<script\b(?![^>]*\bsrc\s*=)[^>]*>/i', $r6) === 0);

    [$cPad, $rPad] = gq_http("$base/verify.php", $jar, ['csrf_token' => $m[1] ?? '', 'smart_id' => $pad . $certs[6]['id'], 'issuer' => 'certivault']);
    t_check('same 512-char prefix + a NEW ID is not a free repeat (429, no verdict)', $cPad === 429 && !str_contains($rPad, 'verdict-seal'));

    [, $again] = gq_http("$base/verify.php?token={$certs[1]['token']}", $jar);
    t_check('re-opening an already verified certificate still works when full', gq_seal($again, 'VALID'));
    [$rc6, $rep6] = gq_http("$base/report.php?cert=" . rawurlencode($certs[6]['id']), $jar);
    t_check('report of a NEW certificate when full: 429 limit page', $rc6 === 429 && str_contains($rep6, 'Free verification limit reached'));
    [, $landFull] = gq_http("$base/verify.php", $jar);
    t_check('landing tells an exhausted guest up front', str_contains($landFull, 'Free verification limit reached'));

    $jar2 = tempnam(sys_get_temp_dir(), 'cvgq');   // "cleared cookies"
    [$c7, $r7] = gq_http("$base/verify.php?token={$certs[6]['token']}", $jar2);
    t_check('clearing cookies does not reset the quota (same IP)', $c7 === 429 && !str_contains($r7, 'verdict-seal'));

    // ── Logged in through the real login form: no limit, no counter ───
    $jar3 = tempnam(sys_get_temp_dir(), 'cvgq');
    [, $loginPage] = gq_http("$base/login.php", $jar3);
    preg_match('/name="csrf_token" value="([^"]+)"/', $loginPage, $lc);
    preg_match('/What is (\d+) \+ (\d+)\?/', $loginPage, $q);
    [$lcode, , $lh] = gq_http("$base/login.php", $jar3, [
        'csrf_token' => $lc[1] ?? '', 'email' => $email, 'password' => $password,
        'captcha_answer' => (string)((int)($q[1] ?? 0) + (int)($q[2] ?? 0)),
    ]);
    $loggedIn = in_array($lcode, [302, 303], true) && stripos($lh, 'student_dashboard.php') !== false;
    t_check('student logs in through login.php', $loggedIn);
    [$c8, $r8] = gq_http("$base/verify.php?token={$certs[6]['token']}", $jar3);
    t_check('logged-in user on an exhausted IP: verification runs (VALID)', $c8 === 200 && gq_seal($r8, 'VALID'));
    t_check('logged-in user sees no guest counter', gq_left($r8) === null && !str_contains($r8, 'Free verification limit reached'));

    foreach ([$jar, $jar2, $jar3] as $j) { @unlink($j); }
    proc_terminate($proc);
    proc_close($proc);
}

// ── Cleanup ───────────────────────────────────────────────────────────
gq_clear($db, $LOCAL);
$db->prepare("DELETE FROM verify_rate WHERE ip = '127.0.0.1'")->execute();
$db->prepare('DELETE FROM certificates WHERE institution_id = :i')->execute(['i' => $instId]);
$db->prepare('DELETE FROM institution_keys WHERE institution_id = :i')->execute(['i' => $instId]);
$db->prepare('DELETE FROM institutions WHERE id = :i')->execute(['i' => $instId]);
$db->prepare('DELETE FROM students WHERE id = :i')->execute(['i' => $studentId]);
$db->prepare('DELETE FROM users WHERE id IN (:a, :s)')->execute(['a' => $adminUid, 's' => $studentUid]);
foreach ($createdFiles as $f) { @unlink($f); }

exit(t_summary('test_guest_quota') ? 0 : 1);
