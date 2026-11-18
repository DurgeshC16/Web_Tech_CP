<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/TotpService.php';

$error = '';
$errors = [];
$success = '';
$show_resend = false;
$email = '';

if (empty($_SESSION['user_id']) && !empty($_COOKIE[REMEMBER_COOKIE])) {
    // ── Remember-me auto-login (selector + hashed validator) ──────
    $db = Database::getInstance();
    $rm_user = consume_remember_token($db);
    if ($rm_user !== null) {
        $allowed = true;
        if ($rm_user['role'] === 'admin') {
            $instStmt = $db->prepare('SELECT status FROM institutions WHERE user_id = :user_id LIMIT 1');
            $instStmt->execute(['user_id' => $rm_user['id']]);
            $inst = $instStmt->fetch();
            if (!$inst || $inst['status'] !== 'approved') {
                $allowed = false;
            }
        }
        if ($allowed) {
            establish_authenticated_session($rm_user);
            redirect_to_dashboard($rm_user['role']);
        }
        // Privilege lost since the token was issued: revoke persistence.
        revoke_user_remember_tokens($db, $rm_user['id']);
    }
}

$info = '';
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['activated'])) {
    if (isset($_GET['awaiting_approval'])) {
        // Institution accounts: email verified, but sign-in only works
        // after the super admin approves the institution.
        $success = 'Your email is verified.';
        $info = 'Your institution is now awaiting approval by the CertiVault administrator. You will be able to log in once it is approved.';
    } else {
        $success = 'Account activated successfully! You can now login.';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['password_reset'])) {
    $success = 'Password updated successfully! You can now login with your new password.';
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['expired'])) {
    $error = 'Your session expired. Please log in again.';
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['2fa_failed'])) {
    $error = 'Too many invalid two-factor codes. Please sign in again.';
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['denied'])) {
    $error = 'Your institution account is no longer approved. Please contact the administrator.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    // ── POST-based resend handler ──────────────────────────────────
    // Only honoured for the account whose password was just proven in this
    // session (stored below as pending_activation_user), so this button can
    // no longer be used to probe arbitrary addresses for user ids.
    if (isset($_POST['resend_activation'])) {
        $pending_uid = (int)($_SESSION['pending_activation_user'] ?? 0);
        $db = Database::getInstance();
        $resend_user = null;
        if ($pending_uid > 0) {
            $stmt = $db->prepare('SELECT id, is_verified FROM users WHERE id = :id LIMIT 1');
            $stmt->execute(['id' => $pending_uid]);
            $resend_user = $stmt->fetch();
        }
        if ($resend_user && !(int)$resend_user['is_verified']) {
            unset($_SESSION['pending_activation_user']);
            queue_activation_otp($db, (int)$resend_user['id']); // cooldown/limit still lead to the code page
            redirect('activate_account.php?user_id=' . (int)$resend_user['id']);
        }
        // Unknown / already verified / no proven password: back to login.
        redirect('login.php');
    }

    // ── Normal login handler ───────────────────────────────────────
    // Trimmed + lowercased so "User@Example.com " matches the stored
    // address and the per-email rate limit can't be split by case.
    $email = normalize_email($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $errors = [];

    // Mode-aware CAPTCHA: reCAPTCHA v2 when keys are configured,
    // offline arithmetic fallback otherwise.
    if (!validate_captcha($errors)) {
        $error = 'Please correct the highlighted fields below.';
    } else {
        if (($e = v_required($email, 'Email')) !== true) { $errors['email'] = $e; }
        elseif (($e = v_email($email)) !== true) { $errors['email'] = $e; }
        if (($e = v_required($password, 'Password')) !== true) { $errors['password'] = $e; }

        if (empty($errors)) {
        $db = Database::getInstance();
        $client_ip = login_client_ip();
        if (($lock_remaining = login_lockout_remaining($db, $email, $client_ip)) > 0) {
            $lock_mins = (int)ceil($lock_remaining / 60);
            $error = 'Too many failed login attempts for this email address. Please try again in '
                . $lock_mins . ' minute' . ($lock_mins === 1 ? '' : 's') . '.';
        } else {
        $stmt = $db->prepare('SELECT id, password_hash, role, is_verified, failed_login_attempts, locked_until FROM users WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();

        // Lockout check: block before even verifying the password
        if ($user && !empty($user['locked_until']) && strtotime($user['locked_until']) > time()) {
            $error = 'Account temporarily locked due to too many failed login attempts. Please try again after ' . $user['locked_until'] . '.';
            $user = null;
        } elseif ($user && password_verify($password, $user['password_hash'])) {
            // Order matters: email verification comes FIRST for every role.
            // (It used to be checked after institution approval, so an
            // unverified institution was told "pending approval or
            // rejected" and never offered the activation step.)
            if ((int)$user['is_verified'] === 0) {
                $error = 'Please verify your email first — enter the 6-digit code we emailed you.';
                $show_resend = true;
                // The password was just proven: the activation page then
                // only asks for the code, and the resend button below is
                // bound to this account (not to a posted email address).
                $_SESSION['pending_activation_user'] = (int)$user['id'];
                mark_activation_password_known((int)$user['id'], $db);
                $user = null; // prevent login
            } elseif ($user['role'] === 'admin') {
                // Verified institution: is it approved yet?
                $instStmt = $db->prepare('SELECT status, rejection_reason FROM institutions WHERE user_id = :user_id LIMIT 1');
                $instStmt->execute(['user_id' => $user['id']]);
                $inst = $instStmt->fetch();

                if (!$inst) {
                    $error = 'No institution profile is linked to this account. Please contact the CertiVault administrator.';
                    $user = null;
                } elseif ($inst['status'] === 'pending') {
                    $error = 'Your email is verified. Your institution is awaiting approval by the CertiVault administrator.';
                    $user = null;
                } elseif ($inst['status'] === 'rejected') {
                    $reason = trim((string)($inst['rejection_reason'] ?? ''));
                    $error = 'Your institution registration was rejected by the CertiVault administrator.'
                        . ($reason !== '' ? ' Reason: ' . $reason : '')
                        . ' Please contact the administrator if you believe this is a mistake.';
                    $user = null;
                } elseif ($inst['status'] !== 'approved') {
                    $error = 'Your institution account is not approved. Please contact the CertiVault administrator.';
                    $user = null;
                }
            }

            if ($user) {
                // Successful login: reset brute-force counters (per-account
                // backstop + per email+IP window) and rotate the session.
                $db->prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = :id')
                   ->execute(['id' => $user['id']]);
                clear_login_attempts($db, $email, $client_ip);

                // Two-factor step: accounts with TOTP enabled must also
                // pass login_2fa.php before a session is established.
                if (TotpService::enabledFor($db, (int)$user['id'])) {
                    session_regenerate_id(true);
                    $_SESSION['2fa_pending'] = [
                        'user_id' => (int)$user['id'], 'role' => $user['role'], 'email' => $email,
                        'remember_me' => !empty($_POST['remember_me']), 'remember_email' => !empty($_POST['remember_email']),
                        'expires' => time() + 300, 'attempts' => 0,
                    ];
                    redirect('login_2fa.php');
                }
                finish_login($db, $user, $email, !empty($_POST['remember_me']), !empty($_POST['remember_email']));
            }
        } else {
            $error = 'Invalid email or password.';

            // Email+IP window for this failure (generic message: no oracle).
            record_failed_login_attempt($db, $email, $client_ip);

            // Track failed attempts against an existing account; lock after 5
            if ($user) {
                $attempts = (int)$user['failed_login_attempts'] + 1;
                if ($attempts >= 5) {
                    $lockUntil = date('Y-m-d H:i:s', time() + 900); // 15 minutes
                    $db->prepare('UPDATE users SET failed_login_attempts = 0, locked_until = :lock WHERE id = :id')
                       ->execute(['lock' => $lockUntil, 'id' => $user['id']]);
                    $error = 'Too many failed login attempts. Your account has been locked for 15 minutes.';
                } else {
                    $db->prepare('UPDATE users SET failed_login_attempts = :a WHERE id = :id')
                       ->execute(['a' => $attempts, 'id' => $user['id']]);
                }
            }
        }
        } // end rate-limit else
        } // end empty($errors)
    }
}
?>
<?php $page_title = 'Login - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main" class="auth-page">
    <div class="auth-split auth-shell">
        <div class="auth-main">
        <div class="auth-card">
            <div class="auth-card-head">
                <span class="auth-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><rect x="4" y="10" width="16" height="11" rx="2.5"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><path d="M12 14.5v2.5"/></svg>
                </span>
                <h1>Welcome back</h1>
                <p class="auth-sub">Sign in to manage, share and verify your certificates.</p>
            </div>
            <?php if ($error): ?>
                <div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">Please correct the highlighted fields below.</div>
            <?php endif; ?>
            <?php $remembered_email = $_COOKIE['cv_email'] ?? ''; ?>
            <?php if ($show_resend): ?>
                <form method="POST" action="" class="auth-resend-activation">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                    <input type="hidden" name="resend_activation" value="1">
                    <button type="submit" class="btn btn-secondary btn-block" data-continue-activation>Continue activation (send me a code)</button>
                </form>
            <?php endif; ?>
            <?php if ($success): ?>
                <div class="alert alert-success" role="status"><?= htmlspecialchars($success) ?></div>
            <?php endif; ?>
            <?php if ($info): ?>
                <div class="alert alert-info"><?= htmlspecialchars($info) ?></div>
            <?php endif; ?>

            <form method="POST" action="" class="auth-form" data-loading>
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <div class="form-group">
                    <label for="login_email">Email</label>
                    <input type="email" name="email" id="login_email" autocomplete="username" placeholder="you@example.com" value="<?= htmlspecialchars($email !== '' ? $email : $remembered_email) ?>" data-validate="required|email" required>
                    <?php render_field_error($errors, 'email'); ?>
                </div>
                <div class="form-group">
                    <div class="auth-label-row">
                        <label for="login_password">Password</label>
                        <a href="forgot_password.php" class="auth-label-link">Forgot password?</a>
                    </div>
                    <input type="password" name="password" id="login_password" autocomplete="current-password" data-validate="required" required>
                    <?php render_field_error($errors, 'password'); ?>
                </div>
                <div class="auth-options">
                    <label class="checkbox-row"><input type="checkbox" name="remember_email" value="1" <?= $remembered_email !== '' ? 'checked' : '' ?>> <span>Remember my email</span></label>
                    <label class="checkbox-row"><input type="checkbox" name="remember_me" value="1"> <span>Keep me signed in on this device (30 days)</span></label>
                </div>
                <div class="form-group auth-captcha">
                    <?= captcha_field_html($errors) ?>
                </div>
                <button type="submit" class="btn btn-primary btn-lg btn-block">
                    Login
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
                </button>
            </form>

            <div class="auth-divider"><span>New to CertiVault?</span></div>
            <div class="auth-alt-links">
                <a href="register_student.php" class="btn btn-secondary">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M22 10L12 5 2 10l10 5 10-5z"/><path d="M6 12v5c3 2 9 2 12 0v-5"/></svg>
                    Register as Student
                </a>
                <a href="register_institution.php" class="btn btn-secondary">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 21h18M5 21V10M19 21V10M9 21v-6h6v6M2 10l10-6 10 6"/></svg>
                    Register as Institution
                </a>
            </div>
        </div>
        </div>

        <aside class="auth-aside" aria-labelledby="authAsideTitle">
            <span class="auth-eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span> Secure sign-in</span>
            <h2 id="authAsideTitle">Certificates you can prove, in seconds.</h2>
            <p>Every CertiVault certificate is digitally signed by its institution, so anyone can check it is genuine &mdash; no phone calls, no paperwork.</p>
            <ul class="auth-points">
                <li data-reveal="left" data-reveal-delay="1"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg></span><span><strong>Tamper-evident</strong> signatures on every record</span></li>
                <li data-reveal="left" data-reveal-delay="2"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M14 14h3v3h-3zM21 14v.01M14 21h.01M17 21h4v-4"/></svg></span><span><strong>QR verification</strong> anyone can run instantly</span></li>
                <li data-reveal="left" data-reveal-delay="3"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><rect x="6" y="2" width="12" height="20" rx="3"/><path d="M11 18h2"/></svg></span><span><strong>Two-factor sign-in</strong> with any authenticator app</span></li>
            </ul>
            <div class="auth-stats">
                <div class="auth-stat"><span class="auth-stat-num" data-count-to="2048">2048</span><span class="auth-stat-label">bit RSA signing keys</span></div>
                <div class="auth-stat"><span class="auth-stat-num" data-count-to="256">256</span><span class="auth-stat-label">bit SHA fingerprints</span></div>
                <div class="auth-stat"><span class="auth-stat-num" data-count-to="30" data-count-suffix="s">30s</span><span class="auth-stat-label">2FA code window</span></div>
            </div>
            <svg class="auth-aside-art" viewBox="0 0 200 200" aria-hidden="true" focusable="false"><g fill="none" stroke="#fff" stroke-width="2"><circle cx="100" cy="100" r="92" stroke-opacity=".35"/><circle cx="100" cy="100" r="70" stroke-opacity=".5" stroke-dasharray="4 8"/><path d="M100 48l38 14v28c0 25-16 43-38 50-22-7-38-25-38-50V62z" stroke-width="5" stroke-linejoin="round"/><path d="M82 98l13 13 24-26" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/></g></svg>
        </aside>
    </div>
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
