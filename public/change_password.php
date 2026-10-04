<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

// Any logged-in role can access this page
if (!isset($_SESSION['user_id']) || !isset($_SESSION['role'])) {
    redirect('login.php');
}
check_session_expiry();
send_no_store_headers();
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
                    $error = 'Please wait at least 60 seconds before requesting a new code.';
                } elseif ($otp_result === 'limit') {
                    $error = 'Too many codes requested. Please try again later.';
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
<main id="main">
    <div class="auth-wrap">
    <div class="auth-card">
        <div class="page-head">
            <div class="auth-brand">
            <svg width="40" height="40" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="16" cy="16" r="9" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M16 10 L18.2 14.2 L22.5 14.8 L19.2 17.8 L20.2 22 L16 19.6 L11.8 22 L12.8 17.8 L9.5 14.8 L13.8 14.2 Z" fill="currentColor"/></svg>
            <div class="brand-name">CertiVault</div>
        </div>
        <h2>Change Password</h2>
            <a href="javascript:history.back()" class="btn btn-secondary">Back</a>
        </div>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($info): ?>
            <div class="alert alert-success"><?= htmlspecialchars($info) ?></div>
        <?php endif; ?>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">Please correct the highlighted fields below.</div>
        <?php endif; ?>

        <?php if ($step === 1): ?>
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <div class="form-group">
                <label>Current Password:</label>
                <input type="password" name="current_password" data-validate="required" required>
                <?php render_field_error($errors, 'current_password'); ?>
            </div>
            <div class="form-group">
                <label>New Password:</label>
                <input type="password" name="new_password" id="new_password" data-validate="required|min:8|max:72|strong" required>
                <?php render_field_error($errors, 'new_password'); ?>
            </div>
            <div class="form-group">
                <label>Confirm New Password:</label>
                <input type="password" name="confirm_password" data-validate="required|match:#new_password" required>
                <?php render_field_error($errors, 'confirm_password'); ?>
            </div>
            <button type="submit" class="btn btn-primary">Continue</button>
        </form>
        <?php elseif ($step === 2): ?>
        <p>Enter the 6-digit code sent to <strong><?= htmlspecialchars($masked) ?></strong>.</p>
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <div class="form-group">
                <label>Verification Code:</label>
                <input type="text" name="otp_code" maxlength="6" inputmode="numeric" autocomplete="one-time-code" class="otp-input" data-validate="required|otp" required>
                <?php render_field_error($errors, 'otp_code'); ?>
            </div>
            <button type="submit" class="btn btn-primary">Confirm Password Change</button>
        </form>
        <p><a href="change_password.php?cancel=1">Cancel and start over</a></p>
        <?php endif; ?>
    </div>
    <script src="assets/js/validation.js"></script>
</div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
