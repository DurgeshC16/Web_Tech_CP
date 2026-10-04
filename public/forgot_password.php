<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';
$errors = [];
$info = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    $email = sanitize_input($_POST['email'] ?? '');
    $errors = [];

    $captcha = trim($_POST['captcha_answer'] ?? '');
    if (($e = v_range($captcha, 2, 18, 'CAPTCHA answer')) !== true) {
        $errors['captcha_answer'] = $e;
        $error = 'Please correct the highlighted fields below.';
    } elseif (!verify_captcha()) {
        $error = 'Incorrect CAPTCHA answer. Please try again.';
    } else {
        if (($e = v_required($email, 'Email')) !== true) { $errors['email'] = $e; }
        elseif (($e = v_email($email)) !== true) { $errors['email'] = $e; }
        if (!empty($errors)) {
            $error = 'Please correct the highlighted fields below.';
        } else {
        $db = Database::getInstance();
        $stmt = $db->prepare('SELECT id, is_verified FROM users WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();

        // ALWAYS show the same neutral message whether or not the account exists
        $info = "If an account exists for that email, we've sent a verification code.";

        // Only send an OTP to verified accounts
        if ($user && (int)$user['is_verified'] === 1) {
            $otp_result = create_otp($db, $user['id'], 'password_reset');
            if ($otp_result === 'sent') {
                // Store the target user in the session (not in the URL)
                $_SESSION['password_reset_user_id'] = $user['id'];
                $_SESSION['password_reset_expires'] = time() + 900; // 15 minutes
                redirect('reset_password.php');
            } elseif ($otp_result === 'cooldown') {
                $info = "If an account exists for that email, we've sent a verification code. Please wait at least 60 seconds before requesting again.";
            } elseif ($otp_result === 'limit') {
                $info = "If an account exists for that email, we've sent a verification code. Too many requests — please try again later.";
            }
            // On mail_failed, still show neutral message (already set above)
        }
        // For non-existent or unverified accounts, just show the neutral message
        }
        }
    }
?>
<?php generate_captcha(); ?>
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
        <p>Enter your email address and we'll send you a verification code to reset your password.</p>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($info): ?>
            <div class="alert alert-success"><?= htmlspecialchars($info) ?></div>
        <?php endif; ?>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">Please correct the highlighted fields below.</div>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <div class="form-group">
                <label>Email:</label>
                <input type="email" name="email" value="<?= htmlspecialchars($email ?? '') ?>" data-validate="required|email" required>
                <?php render_field_error($errors, 'email'); ?>
            </div>
            <div class="form-group">
                <label>CAPTCHA:</label> <span class="captcha-chip"><?= htmlspecialchars($_SESSION['captcha_question'] ?? '') ?></span>
                <input type="text" name="captcha_answer" data-validate="required|number|min:2|max:18" required autocomplete="off">
                <?php render_field_error($errors, 'captcha_answer'); ?>
            </div>
            <button type="submit" class="btn btn-primary">Send Reset Code</button>
        </form>
        <p><a href="login.php">Back to Login</a></p>
    </div>
    <script src="assets/js/validation.js"></script>
</div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
