<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';
$errors = [];
$info = '';
$email = normalize_email($_SESSION['pw_reset']['email'] ?? '');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    $email = normalize_email($_POST['email'] ?? '');
    $errors = [];

    // SMTP not configured: a deterministic message for ANY submitted email.
    // Checked before the user lookup so the error itself reveals nothing
    // about whether an account exists.
    if (!mail_delivery_configured() && !otp_dev_logging_enabled()) {
        $error = smtp_not_configured_message();
    } elseif (!validate_captcha($errors)) {
        $error = 'Please correct the highlighted fields below.';
    } else {
        if (($e = v_required($email, 'Email')) !== true) { $errors['email'] = $e; }
        elseif (($e = v_email($email)) !== true) { $errors['email'] = $e; }
        if (!empty($errors)) {
            $error = 'Please correct the highlighted fields below.';
        } else {
            $db = Database::getInstance();
            // Sends a code only to a verified account; cooldown / hourly
            // limit / delivery failures are handled silently. Whatever
            // happened, ALWAYS continue to the code-entry step with the
            // same neutral wording (no account enumeration). The email is
            // remembered in the session, never in the URL.
            request_password_reset_code($db, $email);
            $_SESSION['pw_reset_flash'] = 'requested';
            redirect('reset_password.php');
        }
    }
}
?>
<?php $page_title = 'Forgot Password - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="auth-wrap">
    <div class="auth-card">
        <div class="auth-brand">
            <svg width="40" height="40" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="16" cy="16" r="9" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M16 10 L18.2 14.2 L22.5 14.8 L19.2 17.8 L20.2 22 L16 19.6 L11.8 22 L12.8 17.8 L9.5 14.8 L13.8 14.2 Z" fill="currentColor"/></svg>
            <div class="brand-name">CertiVault</div>
        </div>
        <h2>Forgot Password</h2>
        <p><strong>Step 1 of 2:</strong> enter your email address and we'll send you a 6-digit verification code. On the next step you enter that code and choose a new password.</p>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($info): ?>
            <div class="alert alert-success"><?= htmlspecialchars($info) ?></div>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <div class="form-group">
                <label for="fp_email">Email:</label>
                <input type="email" name="email" id="fp_email" autocomplete="email" value="<?= htmlspecialchars($email) ?>" data-validate="required|email" required>
                <?php render_field_error($errors, 'email'); ?>
            </div>
            <div class="form-group">
                <?= captcha_field_html($errors) ?>
            </div>
            <button type="submit" class="btn btn-primary">Send Reset Code</button>
        </form>
        <div class="alert alert-info" data-have-code>
            <strong>Already have a code?</strong>
            <a href="reset_password.php">Enter it here</a> together with your email and a new password.
        </div>
        <p><a href="login.php">Back to Login</a></p>
    </div>
    <script src="assets/js/validation.js"></script>
</div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
