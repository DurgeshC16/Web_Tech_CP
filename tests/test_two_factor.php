<?php
// tests/test_two_factor.php
// TOTP two-factor authentication: RFC 6238 test vectors, replay protection,
// encrypted secret, single-use recovery codes, and the real two-step login
// over HTTP (php -S): password → login_2fa.php → dashboard.

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/services/TotpService.php';

// ── RFC 6238 Appendix B vectors (SHA-1, 8 digits) ─────────────────────
$rfcSecret = TotpService::base32Encode('12345678901234567890');
t_check('base32 of the RFC secret', $rfcSecret === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
t_check('base32 round trip (random bytes)', ($r = random_bytes(23)) === TotpService::base32Decode(TotpService::base32Encode($r)));
foreach ([59 => '94287082', 1111111109 => '07081804', 1111111111 => '14050471',
          1234567890 => '89005924', 2000000000 => '69279037', 20000000000 => '65353130'] as $t => $expect) {
    t_check("RFC 6238 vector T=$t", TotpService::hotp($rfcSecret, intdiv($t, 30), 8) === $expect);
}
t_check('6-digit code = last 6 digits of the 8-digit vector', TotpService::code($rfcSecret, 59) === '287082');

// ── Window + replay ───────────────────────────────────────────────────
$secret = TotpService::generateSecret();
$now = 1_800_000_000;
$step = intdiv($now, 30);
t_check('generated secret is 32 base32 chars (160 bits)', (bool)preg_match('/^[A-Z2-7]{32}$/', $secret));
t_check('current code accepted', TotpService::verifyCode($secret, TotpService::code($secret, $now), null, $now) === $step);
t_check('previous-step code accepted (clock skew)', TotpService::verifyCode($secret, TotpService::code($secret, $now - 30), null, $now) === $step - 1);
t_check('code two steps old rejected', TotpService::verifyCode($secret, TotpService::code($secret, $now - 60), null, $now) === null);
t_check('replay of an already-used step rejected', TotpService::verifyCode($secret, TotpService::code($secret, $now), $step, $now) === null);
t_check('non-numeric / wrong length rejected', TotpService::verifyCode($secret, 'abc123', null, $now) === null && TotpService::verifyCode($secret, '12345', null, $now) === null);
t_check('otpauth URI', str_starts_with(TotpService::otpauthUri($secret, 'a@b.test'), 'otpauth://totp/CertiVault%3Aa%40b.test?secret=' . $secret));

// ── Persistence ───────────────────────────────────────────────────────
$db = test_db();
$db->exec(file_get_contents(__DIR__ . '/../database/migrations/015_two_factor_auth.sql'));
$tag = bin2hex(random_bytes(4));
$email = "tfa-$tag@example.com";
$password = 'Str0ng!Pass' . $tag;
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, :h, "student", 1)')
   ->execute(['e' => $email, 'h' => password_hash($password, PASSWORD_BCRYPT)]);
$uid = (int)$db->lastInsertId();
$db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "Two Factor")')->execute(['u' => $uid]);

try {
    t_check('2FA off by default', TotpService::enabledFor($db, $uid) === false);
    $codes = TotpService::enable($db, $uid, $secret, intdiv(time(), 30) - 5);
    t_check('enable returns 10 recovery codes', count($codes) === 10 && count(array_unique($codes)) === 10);
    $row = $db->query("SELECT totp_secret FROM users WHERE id = $uid")->fetchColumn();
    t_check('secret stored encrypted (not the base32 secret)', is_string($row) && str_starts_with($row, 'CFG1.') && !str_contains($row, $secret));
    $stored = $db->query("SELECT code_hash FROM user_recovery_codes WHERE user_id = $uid")->fetchAll(PDO::FETCH_COLUMN);
    t_check('recovery codes stored as hashes only', count($stored) === 10 && !in_array($codes[0], $stored, true) && strlen($stored[0]) === 64);
    t_check('2FA enabled', TotpService::enabledFor($db, $uid) === true);
    t_check('login with current TOTP code', TotpService::verifyForUser($db, $uid, TotpService::code($secret)) === 'totp');
    t_check('same TOTP code cannot be reused', TotpService::verifyForUser($db, $uid, TotpService::code($secret)) === null);
    t_check('recovery code works (case/format tolerant)', TotpService::verifyForUser($db, $uid, strtoupper(str_replace('-', ' ', $codes[0]))) === 'recovery');
    t_check('recovery code is single-use', TotpService::verifyForUser($db, $uid, $codes[0]) === null);
    t_check('9 recovery codes remain', TotpService::remainingRecoveryCodes($db, $uid) === 9);
    t_check('wrong code rejected', TotpService::verifyForUser($db, $uid, '000000') === null || TotpService::code($secret) === '000000');

    // ── Real two-step login over HTTP ─────────────────────────────────
    if (function_exists('curl_init')) {
        $db->prepare('UPDATE users SET totp_last_step = NULL WHERE id = :id')->execute(['id' => $uid]);
        $db->prepare('DELETE FROM login_attempts WHERE email = :e')->execute(['e' => $email]);
        $port = (int)(getenv('CV_TEST_2FA_PORT') ?: 8181);
        $env = getenv();
        $env['CV_DB_NAME'] = getenv('CV_TEST_DB') ?: 'certivault_test';
        $env['CV_ENV'] = 'development';
        $env['CV_MAIL_TRANSPORT'] = 'file';
        $log = sys_get_temp_dir() . '/cv_2fa_http.log';
        $proc = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', realpath(__DIR__ . '/../public')],
            [0 => ['pipe', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']], $pipes, null, $env);
        $base = "http://127.0.0.1:$port";
        $req = function (string $path, ?array $post, string $jar) use ($base) {
            $ch = curl_init($base . '/' . $path);
            $o = [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_TIMEOUT => 20,
                  CURLOPT_COOKIEJAR => $jar, CURLOPT_COOKIEFILE => $jar, CURLOPT_FOLLOWLOCATION => false];
            if ($post !== null) { $o[CURLOPT_POST] = true; $o[CURLOPT_POSTFIELDS] = http_build_query($post); }
            curl_setopt_array($ch, $o);
            $raw = (string)curl_exec($ch);
            $hs = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            curl_close($ch);
            $headers = substr($raw, 0, $hs);
            preg_match('/^Location:\s*(\S+)/mi', $headers, $m);
            return ['location' => $m[1] ?? '', 'body' => substr($raw, $hs)];
        };
        for ($i = 0; $i < 50; $i++) { usleep(200000); if ($req('login.php', null, tempnam(sys_get_temp_dir(), 'j'))['body'] !== '') break; }
        $csrf = fn($html) => preg_match('/name="csrf_token" value="([^"]+)"/', $html, $m) ? $m[1] : '';
        $passwordStep = function (string $jar) use ($req, $csrf, $email, $password) {
            $page = $req('login.php', null, $jar)['body'];
            preg_match('/What is (\d+) \+ (\d+)\?/', $page, $q);
            return $req('login.php', ['csrf_token' => $csrf($page), 'email' => $email, 'password' => $password,
                'captcha_answer' => (string)((int)($q[1] ?? 0) + (int)($q[2] ?? 0))], $jar);
        };

        $jar = tempnam(sys_get_temp_dir(), 'cv2fa');
        $r = $passwordStep($jar);
        t_check('HTTP: correct password redirects to the 2FA step', str_ends_with($r['location'], 'login_2fa.php'));
        $r = $req('student_dashboard.php', null, $jar);
        t_check('HTTP: dashboard still locked before the second factor', str_contains($r['location'], 'login.php'));
        $page = $req('login_2fa.php', null, $jar)['body'];
        $r = $req('login_2fa.php', ['csrf_token' => $csrf($page), 'code' => '000000' === TotpService::code($secret) ? '111111' : '000000'], $jar);
        t_check('HTTP: wrong code stays on the 2FA step with an error', $r['location'] === '' && str_contains($r['body'], 'not valid'));
        $r = $req('login_2fa.php', ['csrf_token' => $csrf($r['body']), 'code' => TotpService::code($secret)], $jar);
        t_check('HTTP: correct code signs in (redirect to dashboard)', str_contains($r['location'], 'student_dashboard.php'));
        $r = $req('student_dashboard.php', null, $jar);
        t_check('HTTP: dashboard accessible after both factors', $r['location'] === '' && str_contains($r['body'], 'My Certificates'));

        // Recovery-code sign-in.
        $jar2 = tempnam(sys_get_temp_dir(), 'cv2fa');
        $passwordStep($jar2);
        $page = $req('login_2fa.php', null, $jar2)['body'];
        $r = $req('login_2fa.php', ['csrf_token' => $csrf($page), 'code' => $codes[1]], $jar2);
        t_check('HTTP: recovery code signs in', str_contains($r['location'], 'student_dashboard.php'));

        // 5 wrong codes end the attempt.
        $jar3 = tempnam(sys_get_temp_dir(), 'cv2fa');
        $passwordStep($jar3);
        $body = $req('login_2fa.php', null, $jar3)['body'];
        $last = null;
        for ($i = 0; $i < 5; $i++) {
            $last = $req('login_2fa.php', ['csrf_token' => $csrf($body), 'code' => 'zzzz-zzzz'], $jar3);
            $body = $last['body'];
        }
        t_check('HTTP: 5 wrong codes -> back to login with an error', str_contains($last['location'], 'login.php?2fa_failed=1'));
        t_check('HTTP: 2FA step unavailable afterwards', str_contains($req('login_2fa.php', null, $jar3)['location'], 'login.php'));

        proc_terminate($proc);
        proc_close($proc);
        foreach ([$jar, $jar2, $jar3] as $j) { @unlink($j); }
    } else {
        t_check('curl unavailable: HTTP checks skipped', true);
    }

    TotpService::disable($db, $uid);
    t_check('disable clears secret + recovery codes', TotpService::enabledFor($db, $uid) === false && TotpService::remainingRecoveryCodes($db, $uid) === 0);
} finally {
    $db->prepare('DELETE FROM login_attempts WHERE email = :e')->execute(['e' => $email]);
    $db->prepare('DELETE FROM remember_tokens WHERE user_id = :u')->execute(['u' => $uid]);
    $db->prepare('DELETE FROM students WHERE user_id = :u')->execute(['u' => $uid]);
    $db->prepare('DELETE FROM users WHERE id = :u')->execute(['u' => $uid]);
}

exit(t_summary('test_two_factor') ? 0 : 1);
