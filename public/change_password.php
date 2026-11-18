<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

// Any logged-in role can access this page (same guard as everywhere else:
// require_role enforces login + idle/absolute timeout + no-store headers).
require_role(['admin', 'student', 'super_admin']);
if ($_SESSION['role'] === 'admin') {
    require_approved_institution();
}

$db = Database::getInstance();
$error = '';
$errors = [];
$info = '';
$step = $_SESSION['change_pw_step'] ?? 1;

// Fetch user email for notification
$stmt = $db->prepare('SELECT email FROM users WHERE id = :id LIMIT 1');
$stmt->execute(['id' => $_SESSION['user_id']]);
$user_email = $stmt->fetchColumn();
$masked = mask_email($user_email);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    if ($step === 1) {
        // ── Step 1: Current password + new password ────────────────
        $current_password = $_POST['current_password'] ?? '';
        $new_password = $_POST['new_password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        $errors = [];

        if (($e = v_required($current_password, 'Current Password')) !== true) { $errors['current_password'] = $e; }
        if (($e = v_required($new_password, 'New Password')) !== true) { $errors['new_password'] = $e; }
        elseif (($e = v_password_strong($new_password)) !== true) { $errors['new_password'] = $e; }
        if (($e = v_compare($new_password, $confirm_password, 'New passwords')) !== true) { $errors['confirm_password'] = $e; }

        if (!empty($errors)) {
            $error = 'Please correct the highlighted fields below.';
        } else {
            // Verify current password
            $stmt = $db->prepare('SELECT password_hash FROM users WHERE id = :id LIMIT 1');
            $stmt->execute(['id' => $_SESSION['user_id']]);
            $current_hash = $stmt->fetchColumn();

            if (!password_verify($current_password, $current_hash)) {
                $error = 'Current password is incorrect.';
            } elseif (password_verify($new_password, $current_hash)) {
                $error = 'New password must be different from your current password.';
            } else {
                // Send OTP for confirmation
                $otp_result = create_otp($db, $_SESSION['user_id'], 'password_change');
                if ($otp_result === 'sent') {
                    // Store the pending new hash in session
                    $_SESSION['change_pw_new_hash'] = password_hash($new_password, PASSWORD_BCRYPT);
                    $_SESSION['change_pw_step'] = 2;
                    $step = 2;
                    $info = "We've sent a verification code to " . $masked . ".";
                } elseif ($otp_result === 'cooldown') {
                    $sec = otp_cooldown_remaining($db, $_SESSION['user_id'], 'password_change');
                    $error = 'A code was sent recently. Try again in ' . max($sec, 1) . ' second' . ($sec === 1 ? '' : 's') . '.';
                } elseif ($otp_result === 'limit') {
                    $error = 'Too many codes requested. Please try again later.';
                } elseif ($otp_result === 'smtp_not_configured') {
                    $error = smtp_not_configured_message();
                } else {
                    $error = "We couldn't send the verification email right now. Please try again in a minute.";
                }
            }
        }
    } elseif ($step === 2) {
        // ── Step 2: OTP verification ───────────────────────────────
        $code = trim($_POST['otp_code'] ?? '');
        $errors = [];

        if (($e = v_required($code, 'Verification Code')) !== true) { $errors['otp_code'] = $e; }
        elseif (($e = v_otp($code)) !== true) { $errors['otp_code'] = $e; }

        if (!empty($errors)) {
            $error = 'Please correct the highlighted fields below.';
        } else {
            $result = verify_otp($db, $_SESSION['user_id'], 'password_change', $code);
            if ($result === 'ok') {
                $new_hash = $_SESSION['change_pw_new_hash'] ?? '';
                if (empty($new_hash)) {
                    $error = 'Session expired. Please start over.';
                    unset($_SESSION['change_pw_step'], $_SESSION['change_pw_new_hash']);
                    $step = 1;
                } else {
                    // Apply the password change
                    $db->prepare('UPDATE users SET password_hash = :hash WHERE id = :id')
                       ->execute(['hash' => $new_hash, 'id' => $_SESSION['user_id']]);

                    // Credential changed: kill all persistent logins.
                    revoke_user_remember_tokens($db, $_SESSION['user_id']);

                    // Invalidate all remaining OTPs for this user
                    $db->prepare('UPDATE otp_codes SET used = 1 WHERE user_id = :uid AND used = 0')
                       ->execute(['uid' => $_SESSION['user_id']]);

                    // Clean up session
                    unset($_SESSION['change_pw_step'], $_SESSION['change_pw_new_hash']);
                    session_regenerate_id(true);

                    // Send notification email
                    send_notification_email(
                        $user_email,
                        'Your CertiVault password was changed',
                        'Password Changed',
                        'Your CertiVault password was changed successfully. If you did not make this change, please reset your password immediately.'
                    );

                    $info = 'Your password has been changed successfully.';
                    $step = 1; // Reset to step 1 (shows success on the form page)
                }
            } elseif ($result === 'expired') {
                $error = 'This verification code has expired. Please start over.';
                unset($_SESSION['change_pw_step'], $_SESSION['change_pw_new_hash']);
                $step = 1;
            } elseif ($result === 'locked') {
                $error = 'Too many incorrect attempts. This code has been invalidated. Please start over.';
                unset($_SESSION['change_pw_step'], $_SESSION['change_pw_new_hash']);
                $step = 1;
            } elseif ($result === 'none') {
                $error = 'No active verification code. Please start over.';
                unset($_SESSION['change_pw_step'], $_SESSION['change_pw_new_hash']);
                $step = 1;
            } else {
                $error = 'Incorrect verification code.';
            }
        }
    }
}

// Allow cancelling step 2 back to step 1
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['cancel'])) {
    unset($_SESSION['change_pw_step'], $_SESSION['change_pw_new_hash']);
    $step = 1;
}
?>
<?php $page_title = 'Change Password - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<?php $cp_done = ($step === 1 && $info !== '' && $error === ''); // presentation only: step 2 just succeeded ?>
<main id="main" class="auth-page">
    <div class="auth-split auth-shell">
        <div class="auth-main">
        <div class="auth-card">
            <div class="auth-card-top">
                <a href="index.php" data-history-back class="btn btn-secondary btn-sm">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M19 12H5M11 18l-6-6 6-6"/></svg>
                    Back
                </a>
            </div>
            <ol class="stepper auth-stepper" aria-label="Password change progress">
                <li class="<?= ($step === 2 || $cp_done) ? 'is-done' : 'is-current' ?>"<?= ($step === 1 && !$cp_done) ? ' aria-current="step"' : '' ?>>New password</li>
                <li class="<?= $cp_done ? 'is-done' : ($step === 2 ? 'is-current' : '') ?>"<?= $step === 2 ? ' aria-current="step"' : '' ?>>Confirm code</li>
                <li class="<?= $cp_done ? 'is-done' : '' ?>"<?= $cp_done ? ' aria-current="step"' : '' ?>>Done</li>
            </ol>
            <div class="auth-card-head">
                <span class="auth-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2"/></svg>
                </span>
                <h1>Change Password</h1>
                <?php if ($step === 2): ?>
                    <p class="auth-sub">Enter the 6-digit code sent to <strong class="auth-email-chip"><?= htmlspecialchars($masked) ?></strong>.</p>
                <?php else: ?>
                    <p class="auth-sub">Confirm your current password, then choose a new one. We'll email you a code to approve the change.</p>
                <?php endif; ?>
            </div>
            <?php if ($error): ?>
                <div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <?php if ($info): ?>
                <div class="alert alert-success" role="status"><?= htmlspecialchars($info) ?></div>
            <?php endif; ?>

            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">Please correct the highlighted fields below.</div>
            <?php endif; ?>

            <?php if ($step === 1): ?>
            <form method="POST" action="" class="auth-form" data-loading>
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <div class="form-group">
                    <label for="current_password">Current Password</label>
                    <input type="password" name="current_password" id="current_password" autocomplete="current-password" data-validate="required" required>
                    <?php render_field_error($errors, 'current_password'); ?>
                </div>
                <div class="form-group">
                    <label for="new_password">New Password</label>
                    <input type="password" name="new_password" id="new_password" autocomplete="new-password" data-validate="required|min:8|max:72|strong" required>
                    <?php render_field_error($errors, 'new_password'); ?>
                </div>
                <div class="form-group">
                    <label for="confirm_password">Confirm New Password</label>
                    <input type="password" name="confirm_password" id="confirm_password" autocomplete="new-password" data-validate="required|match:#new_password" required>
                    <?php render_field_error($errors, 'confirm_password'); ?>
                </div>
                <button type="submit" class="btn btn-primary btn-lg btn-block">
                    Continue
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M5 12h14M13 6l6 6-6 6"/></svg>
                </button>
            </form>
            <?php elseif ($step === 2): ?>
            <form method="POST" action="" class="auth-form" data-loading>
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <div class="form-group auth-otp-group">
                    <label for="cp_otp_code">Verification Code</label>
                    <input type="text" name="otp_code" id="cp_otp_code" maxlength="6" inputmode="numeric" autocomplete="one-time-code" class="otp-input otp-slots" data-validate="required|otp" required>
                    <?php render_field_error($errors, 'otp_code'); ?>
                </div>
                <button type="submit" class="btn btn-primary btn-lg btn-block">Confirm Password Change</button>
            </form>
            <p class="auth-foot"><a href="change_password.php?cancel=1">Cancel and start over</a></p>
            <?php endif; ?>
        </div>
        </div>

        <aside class="auth-aside" aria-labelledby="authAsideTitle">
            <span class="auth-eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span> Account security</span>
            <h2 id="authAsideTitle">Keep your account yours.</h2>
            <p>Changing your password signs out every device that was remembered, and we email you when it happens.</p>
            <ul class="auth-points">
                <li data-reveal="left" data-reveal-delay="1"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="M3 7.5l9 6 9-6"/></svg></span><span><strong>Email confirmation</strong> for every change</span></li>
                <li data-reveal="left" data-reveal-delay="2"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M4 7h16M4 12h10M4 17h7"/></svg></span><span><strong>Unique and long</strong> beats clever and short</span></li>
                <li data-reveal="left" data-reveal-delay="3"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><rect x="6" y="2" width="12" height="20" rx="3"/><path d="M11 18h2"/></svg></span><span><strong>Add a second factor:</strong> <a href="two_factor.php">set up two-factor authentication</a></span></li>
            </ul>
            <svg class="auth-aside-art" viewBox="0 0 200 200" aria-hidden="true" focusable="false"><g fill="none" stroke="#fff" stroke-width="2"><circle cx="100" cy="100" r="92" stroke-opacity=".35"/><circle cx="100" cy="100" r="70" stroke-opacity=".5" stroke-dasharray="4 8"/><circle cx="78" cy="118" r="22" stroke-width="5"/><path d="M94 102l46-46M126 70l14 14M114 82l10 10" stroke-width="5" stroke-linecap="round"/></g></svg>
        </aside>
    </div>
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
