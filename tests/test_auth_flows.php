<?php
// tests/test_auth_flows.php
// Registration / login / forgot-password flows after the auth fixes:
//   - resuming an unfinished (unverified) registration, incl. role change
//   - "account already exists" for verified emails
//   - login message order: verify email -> awaiting approval -> rejected
//   - email normalisation + the stricter v_email() shape rules
//   - forgot -> reset is always reachable (cooldown, unknown email, no session)
//   - one password field at registration (no confirm_password)
//
// Unit part: helper functions against the isolated test DB. HTTP part:
// a php -S server whose auto_prepend_file pins DB_NAME to the test DB and
// mail to a temp spool (config.local.php only defines what is undefined),
// so every check runs end-to-end without SMTP and never touches the dev DB.

require_once __DIR__ . '/bootstrap.php';

define('MAIL_TRANSPORT', 'file');
define('MAIL_FILE_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cv_auth_mail_' . getmypid());
define('SMTP_HOST', 'localhost');
define('SMTP_PORT', 25);
define('SMTP_USERNAME', '');
define('SMTP_PASSWORD', '');
define('SMTP_ENCRYPTION', '');
define('SMTP_FROM_EMAIL', 'no-reply@certivault.test');
define('SMTP_FROM_NAME', 'CertiVault Test');
define('OTP_PEPPER', 'test-pepper');

require_once __DIR__ . '/../src/utils/helpers.php';

$db = test_db();
$tag = bin2hex(random_bytes(4));
$mk = fn(string $who) => "authflow-$tag-$who@example.com";

function af_user($db, string $email) {
    $s = $db->prepare('SELECT * FROM users WHERE email = :e');
    $s->execute(['e' => $email]);
    return $s->fetch() ?: null;
}
function af_count($db, string $sql, array $p) {
    $s = $db->prepare($sql);
    $s->execute($p);
    return (int)$s->fetchColumn();
}

try {
    echo "== Email normalisation + validation ==\n";
    t_check('normalize_email trims + lowercases', normalize_email("  Foo.Bar@Example.COM \t") === 'foo.bar@example.com');
    t_check('normalize_email: non-string -> empty', normalize_email(['x@y.com']) === '');
    t_check('v_email: plus + subdomain ok', v_email('a.b+tag@mail.example.co.in') === true);
    t_check('v_email: IDN A-label TLD ok', v_email('user@xn--p1ai.xn--p1ai') === true);
    t_check('v_email: consecutive dots rejected', v_email('a..b@example.com') !== true);
    t_check('v_email: leading dot rejected', v_email('.ab@example.com') !== true);
    t_check('v_email: trailing dot in local rejected', v_email('ab.@example.com') !== true);
    t_check('v_email: IP literal rejected', v_email('a@[127.0.0.1]') !== true);
    t_check('v_email: 1-letter TLD rejected', v_email('a@example.c') !== true);
    t_check('v_email: numeric TLD rejected', v_email('a@example.c1') !== true);
    t_check('v_email: dotless domain rejected', v_email('a@localhost') !== true);
    t_check('v_email: hyphen-edged label rejected', v_email('a@-ex.com') !== true && v_email('a@ex-.com') !== true);
    t_check('v_email: local part > 64 rejected', v_email(str_repeat('a', 65) . '@example.com') !== true);
    // Client mirror: the same regexes exist in validation.js.
    $js = (string)file_get_contents(__DIR__ . '/../public/assets/js/validation.js');
    t_check('validation.js email rule mirrors the TLD rule', str_contains($js, '[A-Za-z]{2,63}|xn--'));

    echo "== Registration resume (unit) ==\n";
    $_SESSION = [];
    $e1 = $mk('stu');
    $r = register_or_resume_account($db, 'student', $e1, 'Old!Pass123', ['full_name' => 'First Name', 'enrollment_number' => '12345']);
    t_check('new email -> created', $r['status'] === 'created' && $r['user_id'] > 0);
    $uid1 = $r['user_id'];
    t_check('first activation code sent', queue_activation_otp($db, $uid1) === 'sent' && !empty($_SESSION['otp_sent']));
    $r2 = register_or_resume_account($db, 'student', $e1, 'New!Pass456', ['full_name' => 'Second Name', 'enrollment_number' => '']);
    t_check('unverified email -> resumed (same user id)', $r2['status'] === 'resumed' && $r2['user_id'] === $uid1);
    $u = af_user($db, $e1);
    t_check('resume replaced the password', password_verify('New!Pass456', $u['password_hash']) && !password_verify('Old!Pass123', $u['password_hash']));
    t_check('resume updated the student profile (one row)', af_count($db, 'SELECT COUNT(*) FROM students WHERE user_id = :u AND full_name = "Second Name"', ['u' => $uid1]) === 1
        && af_count($db, 'SELECT COUNT(*) FROM students WHERE user_id = :u', ['u' => $uid1]) === 1);
    $_SESSION = [];
    t_check('resend right after resume hits the cooldown (limits survive resume)', queue_activation_otp($db, $uid1) === 'cooldown' && ($_SESSION['otp_cooldown_seconds'] ?? 0) > 0);

    $r3 = register_or_resume_account($db, 'admin', strtoupper($e1), 'Inst!Pass789', ['name' => 'Switched Institute']);
    t_check('unverified student re-registering as institution -> resumed', $r3['status'] === 'resumed' && $r3['user_id'] === $uid1);
    $u = af_user($db, $e1);
    t_check('role switched to admin, student row dropped, institution pending',
        $u['role'] === 'admin'
        && af_count($db, 'SELECT COUNT(*) FROM students WHERE user_id = :u', ['u' => $uid1]) === 0
        && af_count($db, 'SELECT COUNT(*) FROM institutions WHERE user_id = :u AND status = "pending" AND name = "Switched Institute"', ['u' => $uid1]) === 1);
    t_check('uppercase variant matched the same row (no duplicate)', af_count($db, 'SELECT COUNT(*) FROM users WHERE email = :e', ['e' => $e1]) === 1);

    $db->prepare('UPDATE institutions SET status = "rejected", rejection_reason = "Not accredited" WHERE user_id = :u')->execute(['u' => $uid1]);
    register_or_resume_account($db, 'admin', $e1, 'Inst!Pass789', ['name' => 'Switched Institute 2']);
    t_check('resume keeps a super-admin rejection', af_count($db, 'SELECT COUNT(*) FROM institutions WHERE user_id = :u AND status = "rejected"', ['u' => $uid1]) === 1);
    $db->prepare('UPDATE institutions SET status = "approved", rejection_reason = NULL WHERE user_id = :u')->execute(['u' => $uid1]);
    register_or_resume_account($db, 'admin', $e1, 'Inst!Pass789', ['name' => 'Renamed Institute']);
    t_check('approval for a different name is reset to pending', af_count($db, 'SELECT COUNT(*) FROM institutions WHERE user_id = :u AND status = "pending"', ['u' => $uid1]) === 1);

    $r4 = register_or_resume_account($db, 'student', $e1, 'Back!Pass123', ['full_name' => 'Back Again', 'enrollment_number' => '']);
    t_check('institution -> student resume drops the institution row',
        $r4['status'] === 'resumed' && af_count($db, 'SELECT COUNT(*) FROM institutions WHERE user_id = :u', ['u' => $uid1]) === 0
        && af_user($db, $e1)['role'] === 'student');

    // Takeover guard: the "only the code" marker is bound to the password
    // hash, so a parallel resume by someone else (new password, same id)
    // makes the original session set the password again at activation.
    $_SESSION = [];
    mark_activation_password_known($uid1, $db);
    t_check('activation marker valid for the current password', activation_password_known($uid1, $db) !== '');
    register_or_resume_account($db, 'student', $e1, 'Attack!Pass99', ['full_name' => 'Back Again', 'enrollment_number' => '']);
    t_check('activation marker invalidated when another resume replaces the password', activation_password_known($uid1, $db) === '');
    register_or_resume_account($db, 'student', $e1, 'Back!Pass123', ['full_name' => 'Back Again', 'enrollment_number' => '']);
    $_SESSION = [];

    $db->prepare('UPDATE users SET is_verified = 1 WHERE id = :u')->execute(['u' => $uid1]);
    $r5 =register_or_resume_account($db, 'student', $e1, 'Hijack!Pass1', ['full_name' => 'Attacker', 'enrollment_number' => '']);
    t_check('verified email -> exists (nothing changed)', $r5['status'] === 'exists'
        && password_verify('Back!Pass123', af_user($db, $e1)['password_hash']));

    echo "== Password-reset guard (unit) ==\n";
    $_SESSION = [];
    t_check('guard starts open', pw_reset_blocked_for() === 0);
    for ($i = 0; $i < PW_RESET_MAX_FAILS; $i++) { pw_reset_record_failure(); }
    t_check('guard blocks after the per-session cap', pw_reset_blocked_for() > 0);
    $_SESSION['pw_reset_guard']['since'] = time() - PW_RESET_WINDOW - 1;
    t_check('guard reopens after the window', pw_reset_blocked_for() === 0);
    $_SESSION = [];
    request_password_reset_code($db, $mk('nobody'));
    t_check('unknown email still remembered in session (neutral flow)', ($_SESSION['pw_reset']['email'] ?? '') === $mk('nobody') && pw_reset_resend_wait() > 0);

    // ── HTTP end-to-end ────────────────────────────────────────────────
    if (!function_exists('curl_init')) {
        t_check('curl unavailable: HTTP checks skipped', true);
    } else {
        echo "== HTTP flows (php -S) ==\n";
        $spool = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cv_auth_http_mail_' . getmypid();
        @mkdir($spool, 0700, true);
        $prepend = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cv_auth_prepend_' . getmypid() . '.php';
        file_put_contents($prepend, '<?php '
            . "define('DB_NAME', " . var_export(getenv('CV_TEST_DB') ?: 'certivault_test', true) . ');'
            . "define('MAIL_TRANSPORT', 'file');"
            . "define('MAIL_FILE_DIR', " . var_export($spool, true) . ');');
        $port = (int)(getenv('CV_TEST_AUTH_PORT') ?: 8183);
        $log = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cv_auth_http.log';
        $env = getenv();
        $env['CV_ENV'] = 'development';
        $proc = proc_open([PHP_BINARY, '-d', 'auto_prepend_file=' . $prepend, '-S', "127.0.0.1:$port", '-t', realpath(__DIR__ . '/../public')],
            [0 => ['pipe', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']], $pipes, null, $env);
        $base = "http://127.0.0.1:$port";
        $jars = [];
        $newJar = function () use (&$jars) { $j = tempnam(sys_get_temp_dir(), 'cvauth'); $jars[] = $j; return $j; };
        $req = function (string $path, ?array $post, string $jar) use ($base) {
            $ch = curl_init($base . '/' . $path);
            $o = [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_TIMEOUT => 30,
                  CURLOPT_COOKIEJAR => $jar, CURLOPT_COOKIEFILE => $jar, CURLOPT_FOLLOWLOCATION => false];
            if ($post !== null) { $o[CURLOPT_POST] = true; $o[CURLOPT_POSTFIELDS] = http_build_query($post); }
            curl_setopt_array($ch, $o);
            $raw = (string)curl_exec($ch);
            $hs = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            curl_close($ch);
            preg_match('/^Location:\s*(\S+)/mi', substr($raw, 0, $hs), $m);
            return ['location' => $m[1] ?? '', 'body' => substr($raw, $hs)];
        };
        $up = false;
        for ($i = 0; $i < 50; $i++) { usleep(200000); if ($req('login.php', null, $newJar())['body'] !== '') { $up = true; break; } }
        t_check('HTTP: test server is up', $up);
        $csrf = fn($html) => preg_match('/name="csrf_token" value="([^"]+)"/', $html, $m) ? $m[1] : '';
        $captcha = fn($html) => preg_match('/What is (\d+) \+ (\d+)\?/', $html, $q) ? (string)((int)$q[1] + (int)$q[2]) : '';
        // GET a page, then POST its form with a fresh CSRF token + CAPTCHA answer.
        $submit = function (string $path, array $fields, string $jar) use ($req, $csrf, $captcha) {
            $page = $req($path, null, $jar)['body'];
            return $req($path, $fields + ['csrf_token' => $csrf($page), 'captcha_answer' => $captcha($page)], $jar);
        };
        $lastCode = function (string $email) use ($spool) {
            $files = glob($spool . '/*.eml') ?: [];
            usort($files, fn($a, $b) => filemtime($b) <=> filemtime($a) ?: strcmp($b, $a));
            foreach ($files as $f) {
                $body = (string)file_get_contents($f);
                if (stripos($body, 'To: ' . $email) !== false && preg_match('/>(\d{6})</', $body, $m)) { return $m[1]; }
            }
            return null;
        };
        $uidFrom = fn($loc) => preg_match('/user_id=(\d+)/', $loc, $m) ? (int)$m[1] : 0;

        // ── Registration without confirm_password + resume ──────────
        $sEmail = $mk('httpstu');
        $jar = $newJar();
        $page = $req('register_student.php', null, $jar)['body'];
        t_check('HTTP: registration form has no confirm-password field', !str_contains($page, 'confirm_password') && str_contains($page, 'name="password"'));
        $r = $submit('register_student.php', ['full_name' => 'Http Student', 'enrollment_number' => '', 'email' => strtoupper($sEmail), 'password' => 'Http!Pass123'], $jar);
        $sUid = $uidFrom($r['location']);
        t_check('HTTP: registration accepted without confirm_password -> activation', str_contains($r['location'], 'activate_account.php') && $sUid > 0);
        t_check('HTTP: stored email normalised to lowercase', ($u = af_user($db, $sEmail)) && $u['email'] === $sEmail);
        $act = $req('activate_account.php?user_id=' . $sUid, null, $jar)['body'];
        t_check('HTTP: activation asks only for the code (password already chosen)', str_contains($act, 'name="otp_code"') && !str_contains($act, 'name="password"'));

        $jarB = $newJar(); // "later, from another visit": fresh session
        $r = $submit('register_student.php', ['full_name' => 'Http Student Again', 'enrollment_number' => '', 'email' => $sEmail, 'password' => 'Http!Pass456'], $jarB);
        t_check('HTTP: re-registering an unverified email resumes it (same id)', $uidFrom($r['location']) === $sUid);
        $act = $req('activate_account.php?user_id=' . $sUid, null, $jarB)['body'];
        t_check('HTTP: resume notice + cooldown text instead of a dead end',
            str_contains($act, 'unfinished registration') && str_contains($act, 'less than a minute ago'));
        // Takeover guard: the FIRST session's password was replaced by the
        // resume, so it may no longer activate with "only the code" (it
        // would otherwise activate the account with the other password).
        $act0 = $req('activate_account.php?user_id=' . $sUid, null, $jar)['body'];
        t_check('HTTP: earlier session must set a password after another resume', str_contains($act0, 'name="password"') && str_contains($act0, 'name="confirm_password"'));
        $code = $lastCode($sEmail);
        $r = $req('activate_account.php', ['csrf_token' => $csrf($act), 'user_id' => $sUid, 'otp_code' => (string)$code], $jarB);
        t_check('HTTP: student activation with the emailed code', $r['location'] === 'login.php?activated=1');
        $r = $submit('login.php', ['email' => '  ' . strtoupper($sEmail) . ' ', 'password' => 'Http!Pass456'], $newJar());
        t_check('HTTP: login with resumed password + messy email casing', str_contains($r['location'], 'student_dashboard.php'));

        $r = $submit('register_student.php', ['full_name' => 'Someone Else', 'enrollment_number' => '', 'email' => $sEmail, 'password' => 'Other!Pass1'], $newJar());
        t_check('HTTP: verified email -> "already exists" with login + reset links',
            $r['location'] === '' && str_contains($r['body'], 'An account with this email already exists')
            && str_contains($r['body'], 'href="login.php"') && str_contains($r['body'], 'href="forgot_password.php"'));
        t_check('HTTP: non-secret fields kept after a failed submit', str_contains($r['body'], 'value="Someone Else"') && !str_contains($r['body'], 'Other!Pass1'));

        // ── Institution: login message order ───────────────────────
        $iEmail = $mk('httpinst');
        $jarI = $newJar();
        $r = $submit('register_institution.php', ['name' => 'Http Institute', 'email' => $iEmail, 'password' => 'Inst!Pass123'], $jarI);
        $iUid = $uidFrom($r['location']);
        t_check('HTTP: institution registration -> activation', $iUid > 0);
        $jarL = $newJar();
        $r = $submit('login.php', ['email' => $iEmail, 'password' => 'Inst!Pass123'], $jarL);
        t_check('HTTP: unverified institution is told to verify email (not "pending approval")',
            str_contains($r['body'], 'Please verify your email first') && !str_contains($r['body'], 'awaiting approval')
            && str_contains($r['body'], 'name="resend_activation"'));
        $r = $req('login.php', ['csrf_token' => $csrf($r['body']), 'resend_activation' => '1'], $jarL);
        t_check('HTTP: "Continue activation" leads to the code page', $uidFrom($r['location']) === $iUid);
        $act = $req('activate_account.php?user_id=' . $iUid, null, $jarL)['body'];
        t_check('HTTP: activation after login needs no second password', !str_contains($act, 'name="password"'));
        $r = $req('activate_account.php', ['csrf_token' => $csrf($act), 'user_id' => $iUid, 'otp_code' => (string)$lastCode($iEmail)], $jarL);
        t_check('HTTP: institution activation redirects with awaiting-approval flag', str_contains($r['location'], 'awaiting_approval=1'));
        $page = $req($r['location'], null, $jarL)['body'];
        t_check('HTTP: post-activation page says approval is pending', str_contains($page, 'awaiting approval'));
        $r = $submit('login.php', ['email' => $iEmail, 'password' => 'Inst!Pass123'], $newJar());
        t_check('HTTP: verified + pending institution -> awaiting approval message',
            str_contains($r['body'], 'Your email is verified. Your institution is awaiting approval'));
        $db->prepare('UPDATE institutions SET status = "rejected", rejection_reason = "Accreditation documents missing" WHERE user_id = :u')->execute(['u' => $iUid]);
        $r = $submit('login.php', ['email' => $iEmail, 'password' => 'Inst!Pass123'], $newJar());
        t_check('HTTP: rejected institution -> rejected message with reason',
            str_contains($r['body'], 'was rejected') && str_contains($r['body'], 'Accreditation documents missing'));
        $r = $req('login.php', ['csrf_token' => $csrf($r['body']), 'resend_activation' => '1'], $newJar());
        t_check('HTTP: resend_activation without a proven password does nothing', $r['location'] === 'login.php' || $r['location'] === '');

        // ── Forgot -> reset always reachable ───────────────────────
        $nobody = $mk('ghost');
        $jarF = $newJar();
        $r = $submit('forgot_password.php', ['email' => $nobody], $jarF);
        t_check('HTTP: forgot with unknown email still moves to the code step', $r['location'] === 'reset_password.php');
        $page = $req('reset_password.php', null, $jarF)['body'];
        t_check('HTTP: reset page has code field + remembered email + neutral text',
            str_contains($page, 'name="otp_code"') && str_contains($page, 'value="' . $nobody . '"') && str_contains($page, 'If an account exists'));
        $r = $req('reset_password.php', ['csrf_token' => $csrf($page), 'action' => 'reset', 'email' => $nobody, 'otp_code' => '123456',
            'password' => 'Ghost!Pass123', 'confirm_password' => 'Ghost!Pass123'], $jarF);
        t_check('HTTP: unknown email + code -> generic failure', $r['location'] === '' && str_contains($r['body'], 'not valid for this email address'));
        $r = $req('reset_password.php', ['csrf_token' => $csrf($r['body']), 'action' => 'resend', 'email' => $nobody], $jarF);
        t_check('HTTP: resend inside 60 s shows the wait time', str_contains($r['body'], 'Please wait') && str_contains($r['body'], 'id="resendBtn"'));

        $jarF2 = $newJar();
        $r1 = $submit('forgot_password.php', ['email' => $sEmail], $jarF2);
        $r2 = $submit('forgot_password.php', ['email' => $sEmail], $jarF2); // DB cooldown now active
        t_check('HTTP: forgot for a real account -> code step, also during cooldown',
            $r1['location'] === 'reset_password.php' && $r2['location'] === 'reset_password.php');
        $code = $lastCode($sEmail);
        t_check('HTTP: reset code delivered', is_string($code));

        $jarN = $newJar(); // no forgot-password session at all
        $page = $req('reset_password.php', null, $jarN)['body'];
        t_check('HTTP: reset page without a session is usable (no "Session Expired")',
            !str_contains($page, 'Session Expired') && str_contains($page, 'name="email"') && str_contains($page, 'name="otp_code"'));
        $r = $req('reset_password.php', ['csrf_token' => $csrf($page), 'action' => 'reset', 'email' => $sEmail, 'otp_code' => (string)$code,
            'password' => 'Reset!Pass789', 'confirm_password' => 'Mismatch!789'], $jarN);
        t_check('HTTP: reset keeps the confirm (compare) check', str_contains($r['body'], 'Passwords do not match'));
        $r = $req('reset_password.php', ['csrf_token' => $csrf($r['body']), 'action' => 'reset', 'email' => strtoupper($sEmail), 'otp_code' => (string)$code,
            'password' => 'Reset!Pass789', 'confirm_password' => 'Reset!Pass789'], $jarN);
        t_check('HTTP: reset via email + code without prior session', $r['location'] === 'login.php?password_reset=1');
        $r = $submit('login.php', ['email' => $sEmail, 'password' => 'Reset!Pass789'], $newJar());
        t_check('HTTP: login with the new password', str_contains($r['location'], 'student_dashboard.php'));

        $page = $req('forgot_password.php', null, $newJar())['body'];
        t_check('HTTP: forgot page offers "Already have a code?"', str_contains($page, 'Already have a code?') && str_contains($page, 'href="reset_password.php"'));

        proc_terminate($proc);
        proc_close($proc);
        foreach ($jars as $j) { @unlink($j); }
        @unlink($prepend);
        foreach (glob($spool . '/*.eml') ?: [] as $f) { @unlink($f); }
        @rmdir($spool);
    }
} finally {
    $ids = $db->prepare('SELECT id FROM users WHERE email LIKE :p');
    $ids->execute(['p' => "authflow-$tag-%"]);
    foreach ($ids->fetchAll(PDO::FETCH_COLUMN) as $id) {
        $db->prepare('DELETE FROM users WHERE id = :u')->execute(['u' => $id]); // cascades profile, OTP, tokens
    }
    $db->prepare('DELETE FROM login_attempts WHERE email LIKE :p')->execute(['p' => "authflow-$tag-%"]);
    foreach (glob(MAIL_FILE_DIR . '/*.eml') ?: [] as $f) { @unlink($f); }
    @rmdir(MAIL_FILE_DIR);
}

exit(t_summary('test_auth_flows') ? 0 : 1);
