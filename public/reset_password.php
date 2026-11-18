<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

// Step 2 of the forgot-password flow: email + emailed code + new password.
//
// This page is ALWAYS usable — with or without a session from
// forgot_password.php. The session only pre-fills the email; if it
// expired (or the user arrives via "Already have a code?") they simply
// type their email next to the code. Anti-enumeration: every outcome for
// an unknown/unverified address looks exactly like a wrong code for a
// real one. Brute force is bounded by verify_otp() (a code dies after 5
// wrong tries) plus a per-session failure cap (pw_reset_blocked_for()).

$error = '';
$errors = [];
$info = '';
$db = Database::getInstance();

$email = normalize_email($_SESSION['pw_reset']['email'] ?? '');

if (($_SESSION['pw_reset_flash'] ?? '') === 'requested') {
    $info = "If an account exists for " . $email . ", we've emailed it a 6-digit code (valid for 10 minutes). "
        . "Enter it below with your new password. No email after a minute? Check your spam folder or use 'Resend code'.";
}
unset($_SESSION['pw_reset_flash']);

$GENERIC_FAIL = 'That code is not valid for this email address, or it has expired. Check the most recent email from CertiVault, or request a new code.';
$LOCKED_FAIL = 'Too many incorrect attempts — this code has been invalidated. Please request a new code.';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    $email = normalize_email($_POST['email'] ?? '');
    $action = (string)($_POST['action'] ?? 'reset');
    $errors = [];

    if (($e = v_required($email, 'Email')) !== true) { $errors['email'] = $e; }
    elseif (($e = v_email($email)) !== true) { $errors['email'] = $e; }

    if ($action === 'resend') {
        // ── Resend code (POST + CSRF, neutral, 60 s per-session timer) ──
        if (!empty($errors)) {
            $error = 'Please enter a valid email address to receive a new code.';
        } elseif (!mail_delivery_configured() && !otp_dev_logging_enabled()) {
            $error = smtp_not_configured_message();
        } elseif (($wait = pw_reset_resend_wait()) > 0) {
            $error = 'Please wait ' . $wait . ' second' . ($wait === 1 ? '' : 's') . ' before requesting another code.';
        } else {
            request_password_reset_code($db, $email);
            $info = "If an account exists for " . $email . ", we've emailed it a new 6-digit code. Codes sent earlier no longer work.";
        }
    } else {
        // ── Reset: verify code, then set the new password ────────────
        $code = trim((string)($_POST['otp_code'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        $confirm_password = (string)($_POST['confirm_password'] ?? '');

        if (($e = v_required($code, 'Verification Code')) !== true) { $errors['otp_code'] = $e; }
        elseif (($e = v_otp($code)) !== true) { $errors['otp_code'] = $e; }
        if (($e = v_required($password, 'New Password')) !== true) { $errors['password'] = $e; }
        elseif (($e = v_password_strong($password)) !== true) { $errors['password'] = $e; }
        if (($e = v_compare($password, $confirm_password, 'Passwords')) !== true) { $errors['confirm_password'] = $e; }

        if (($blocked = pw_reset_blocked_for()) > 0) {
            $mins = (int)ceil($blocked / 60);
            $error = 'Too many failed reset attempts from this browser. Please try again in ' . $mins . ' minute' . ($mins === 1 ? '' : 's') . '.';
        } elseif (!empty($errors)) {
            $error = 'Please correct the highlighted fields below.';
        } else {
            $stmt = $db->prepare('SELECT id FROM users WHERE email = :email AND is_verified = 1 LIMIT 1');
            $stmt->execute(['email' => $email]);
            $reset_user_id = (int)($stmt->fetchColumn() ?: 0);
            $result = $reset_user_id > 0 ? verify_otp($db, $reset_user_id, 'password_reset', $code) : 'no_account';

            if ($result === 'ok') {
                // Update password hash
                $hash = password_hash($password, PASSWORD_BCRYPT);
                $db->prepare('UPDATE users SET password_hash = :hash, failed_login_attempts = 0, locked_until = NULL WHERE id = :id')
                   ->execute(['hash' => $hash, 'id' => $reset_user_id]);

                // Credential changed: kill all persistent logins.
                revoke_user_remember_tokens($db, $reset_user_id);

                // Invalidate all remaining OTPs for this user
                $db->prepare('UPDATE otp_codes SET used = 1 WHERE user_id = :uid AND used = 0')
                   ->execute(['uid' => $reset_user_id]);

                // Clean up session and regenerate
                unset($_SESSION['pw_reset'], $_SESSION['pw_reset_bad'], $_SESSION['pw_reset_guard'],
                      $_SESSION['password_reset_user_id'], $_SESSION['password_reset_expires']);
                session_regenerate_id(true);

                redirect('login.php?password_reset=1');
            }

            pw_reset_record_failure();
            // Per-email failure count in this session: the 5th miss shows
            // the "invalidated" text for unknown addresses too, mirroring
            // verify_otp()'s lock on real ones.
            $bad = $_SESSION['pw_reset_bad'] ?? [];
            $bad[$email] = (int)($bad[$email] ?? 0) + 1;
            $_SESSION['pw_reset_bad'] = $bad;
            $error = ($result === 'locked' || $bad[$email] === 5) ? $LOCKED_FAIL : $GENERIC_FAIL;
        }
    }
}

$resend_wait = pw_reset_resend_wait();
?>
<?php $page_title = 'Reset Password - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main" class="auth-page">
    <div class="auth-split auth-shell">
        <div class="auth-main">
        <div class="auth-card">
            <ol class="stepper auth-stepper" aria-label="Password reset progress">
                <li class="is-done"><a href="forgot_password.php">Request a code</a></li>
                <li class="is-current" aria-current="step">Choose a new password</li>
            </ol>
            <div class="auth-card-head">
                <span class="auth-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><rect x="9" y="11" width="6" height="5" rx="1"/><path d="M10.5 11V9.5a1.5 1.5 0 0 1 3 0V11"/></svg>
                </span>
                <h1>Reset Password</h1>
                <p class="auth-sub"><span class="visually-hidden">Step 2 of 2: </span>Enter your email, the 6-digit code we emailed you, and your new password.</p>
            </div>
            <?php if ($error): ?>
                <div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <?php if ($info): ?>
                <div class="alert alert-success" role="status"><?= htmlspecialchars($info) ?></div>
            <?php endif; ?>

            <form method="POST" action="" id="resetForm" class="auth-form" data-loading>
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <div class="form-group">
                    <label for="rp_email">Email</label>
                    <input type="email" name="email" id="rp_email" autocomplete="username" placeholder="you@example.com" value="<?= htmlspecialchars($email) ?>" data-validate="required|email" required>
                    <?php render_field_error($errors, 'email'); ?>
                </div>
                <div class="form-group auth-otp-group">
                    <label for="otp_code">Verification Code</label>
                    <input type="text" name="otp_code" id="otp_code" maxlength="6" inputmode="numeric" autocomplete="one-time-code" class="otp-input otp-slots" aria-describedby="otp_code_hint" data-validate="required|otp" required>
                    <small id="otp_code_hint" class="help-text">The 6 digits from the email we sent you.</small>
                    <?php render_field_error($errors, 'otp_code'); ?>
                </div>
                <div class="form-group">
                    <label for="password">New Password</label>
                    <input type="password" name="password" id="password" autocomplete="new-password" data-validate="required|min:8|max:72|strong" required>
                    <?php render_field_error($errors, 'password'); ?>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
                    <input type="password" name="confirm_password" id="confirm_password" autocomplete="new-password" data-validate="required|match:#password" required>
                    <?php render_field_error($errors, 'confirm_password'); ?>
                </div>
                <!-- First submit button = the Enter-key default. -->
                <button type="submit" name="action" value="reset" class="btn btn-primary btn-lg btn-block">Reset Password</button>
                <!-- Resend posts the same form (email included) but skips the
                     client-side checks of the code/password fields. -->
                <div class="auth-resend">
                    <span class="auth-resend-text">Didn't get the code?</span>
                    <button type="submit" name="action" value="resend" formnovalidate class="btn btn-secondary" id="resendBtn" <?php if ($resend_wait > 0) echo 'data-wait="' . (int)$resend_wait . '"'; ?>>Resend code</button>
                    <?php if ($resend_wait > 0): ?>
                        <small class="field-note" id="resendCountdown">You can request another code in <?= (int)$resend_wait ?> second<?= $resend_wait === 1 ? '' : 's' ?>.</small>
                    <?php endif; ?>
                </div>
            </form>
            <p class="auth-foot">Don't have a code yet? <a href="forgot_password.php">Request one</a></p>
            <p class="auth-foot auth-foot-tight"><a href="login.php" class="auth-back-link"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M19 12H5M11 18l-6-6 6-6"/></svg> Back to Login</a></p>
        </div>
        </div>

        <aside class="auth-aside" aria-labelledby="authAsideTitle">
            <span class="auth-eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span> Almost there</span>
            <h2 id="authAsideTitle">Pick a password you have never used here.</h2>
            <p>A strong password is long and unique. The meter under the field turns green as you meet each rule.</p>
            <ul class="auth-points">
                <li data-reveal="left" data-reveal-delay="1"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M4 7h16M4 12h10M4 17h7"/></svg></span><span><strong>8&ndash;72 characters</strong> &mdash; longer is stronger</span></li>
                <li data-reveal="left" data-reveal-delay="2"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M4 18L9 6l5 12M6 14h6M16 10h5M18.5 7.5v5"/></svg></span><span><strong>Mix it up:</strong> upper and lower case, a digit and a symbol</span></li>
                <li data-reveal="left" data-reveal-delay="3"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg></span><span><strong>Codes expire</strong> after a few wrong tries, so guessing is pointless</span></li>
            </ul>
            <svg class="auth-aside-art" viewBox="0 0 200 200" aria-hidden="true" focusable="false"><g fill="none" stroke="#fff" stroke-width="2"><circle cx="100" cy="100" r="92" stroke-opacity=".35"/><circle cx="100" cy="100" r="70" stroke-opacity=".5" stroke-dasharray="4 8"/><rect x="62" y="92" width="76" height="56" rx="10" stroke-width="5"/><path d="M76 92V78a24 24 0 0 1 48 0v14M100 112v14" stroke-width="5" stroke-linecap="round"/></g></svg>
        </aside>
    </div>
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
