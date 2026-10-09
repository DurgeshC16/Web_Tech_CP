<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';
$errors = [];
$db = Database::getInstance();

// Require the session value set by forgot_password.php
$reset_user_id = $_SESSION['password_reset_user_id'] ?? 0;
$reset_expires = $_SESSION['password_reset_expires'] ?? 0;

if (!$reset_user_id || $reset_expires < time()) {
    unset($_SESSION['password_reset_user_id'], $_SESSION['password_reset_expires']);
    show_error_page('Session Expired', 'Your password reset session has expired. Please start again from the forgot password page.');
}

// Fetch user for masked email display
$stmt = $db->prepare('SELECT id, email FROM users WHERE id = :id LIMIT 1');
$stmt->execute(['id' => $reset_user_id]);
$user = $stmt->fetch();
if (!$user) {
    unset($_SESSION['password_reset_user_id'], $_SESSION['password_reset_expires']);
    show_error_page('Error', 'Invalid reset session.');
}

$masked = mask_email($user['email']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    $code = trim($_POST['otp_code'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $errors = [];

    if (($e = v_required($code, 'Verification Code')) !== true) { $errors['otp_code'] = $e; }
    elseif (($e = v_otp($code)) !== true) { $errors['otp_code'] = $e; }
    if (($e = v_required($password, 'New Password')) !== true) { $errors['password'] = $e; }
    elseif (($e = v_password_strong($password)) !== true) { $errors['password'] = $e; }
    if (($e = v_compare($password, $confirm_password, 'Passwords')) !== true) { $errors['confirm_password'] = $e; }

    if (!empty($errors)) {
        $error = 'Please correct the highlighted fields below.';
    } else {
        $result = verify_otp($db, $reset_user_id, 'password_reset', $code);
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
            unset($_SESSION['password_reset_user_id'], $_SESSION['password_reset_expires']);
            session_regenerate_id(true);

            redirect('login.php?password_reset=1');
        } elseif ($result === 'expired') {
            $error = 'This verification code has expired. Please start again.';
        } elseif ($result === 'locked') {
            $error = 'Too many incorrect attempts. This code has been invalidated. Please start again.';
        } elseif ($result === 'none') {
            $error = 'No active verification code. Please start again from the forgot password page.';
        } else {
            $error = 'Incorrect verification code.';
        }
    }
}
?>
<?php $page_title = 'Reset Password - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="auth-wrap">
    <div class="auth-card">
        <div class="auth-brand">
            <svg width="40" height="40" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="16" cy="16" r="9" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M16 10 L18.2 14.2 L22.5 14.8 L19.2 17.8 L20.2 22 L16 19.6 L11.8 22 L12.8 17.8 L9.5 14.8 L13.8 14.2 Z" fill="currentColor"/></svg>
            <div class="brand-name">CertiVault</div>
        </div>
        <h2>Reset Password</h2>
        <p>Enter the 6-digit code sent to <strong><?= htmlspecialchars($masked) ?></strong> and set your new password.</p>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">Please correct the highlighted fields below.</div>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <div class="form-group">
                <label>Verification Code:</label>
                <input type="text" name="otp_code" maxlength="6" inputmode="numeric" autocomplete="one-time-code" class="otp-input" data-validate="required|otp" required>
                <?php render_field_error($errors, 'otp_code'); ?>
            </div>
            <div class="form-group">
                <label>New Password:</label>
                <input type="password" name="password" id="password" data-validate="required|min:8|max:72|strong" required>
                <?php render_field_error($errors, 'password'); ?>
            </div>
            <div class="form-group">
                <label>Confirm New Password:</label>
                <input type="password" name="confirm_password" data-validate="required|match:#password" required>
                <?php render_field_error($errors, 'confirm_password'); ?>
            </div>
            <button type="submit" class="btn btn-primary">Reset Password</button>
        </form>
        <p><a href="forgot_password.php">Start over</a></p>
    </div>
    <script src="assets/js/validation.js"></script>
</div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
