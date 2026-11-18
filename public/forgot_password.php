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
<main id="main" class="auth-page">
    <div class="auth-split auth-shell">
        <div class="auth-main">
        <div class="auth-card">
            <ol class="stepper auth-stepper" aria-label="Password reset progress">
                <li class="is-current" aria-current="step">Request a code</li>
                <li>Choose a new password</li>
            </ol>
            <div class="auth-card-head">
                <span class="auth-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2"/></svg>
                </span>
                <h1>Forgot Password</h1>
                <p class="auth-sub"><span class="visually-hidden">Step 1 of 2: </span>Enter your email address and we'll send you a 6-digit verification code. On the next step you enter that code and choose a new password.</p>
            </div>
            <?php if ($error): ?>
                <div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <?php if ($info): ?>
                <div class="alert alert-success" role="status"><?= htmlspecialchars($info) ?></div>
            <?php endif; ?>

            <form method="POST" action="" class="auth-form" data-loading>
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <div class="form-group">
                    <label for="fp_email">Email</label>
                    <input type="email" name="email" id="fp_email" autocomplete="email" placeholder="you@example.com" value="<?= htmlspecialchars($email) ?>" data-validate="required|email" required>
                    <?php render_field_error($errors, 'email'); ?>
                </div>
                <div class="form-group auth-captcha">
                    <?= captcha_field_html($errors) ?>
                </div>
                <button type="submit" class="btn btn-primary btn-lg btn-block">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4z"/></svg>
                    Send Reset Code
                </button>
            </form>
            <div class="alert alert-info auth-have-code" data-have-code>
                <span><strong>Already have a code?</strong>
                <a href="reset_password.php">Enter it here</a> together with your email and a new password.</span>
            </div>
            <p class="auth-foot"><a href="login.php" class="auth-back-link"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M19 12H5M11 18l-6-6 6-6"/></svg> Back to Login</a></p>
        </div>
        </div>

        <aside class="auth-aside" aria-labelledby="authAsideTitle">
            <span class="auth-eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span> Account recovery</span>
            <h2 id="authAsideTitle">Locked out? Back in two steps.</h2>
            <p>We never send your password by email. Instead you get a short-lived code that proves the inbox is yours.</p>
            <ol class="auth-flow">
                <li data-reveal="left" data-reveal-delay="1"><span class="auth-flow-num" aria-hidden="true">1</span><span><strong>Request a code</strong> sent to your registered email</span></li>
                <li data-reveal="left" data-reveal-delay="2"><span class="auth-flow-num" aria-hidden="true">2</span><span><strong>Enter the code</strong> and choose a new password</span></li>
                <li data-reveal="left" data-reveal-delay="3"><span class="auth-flow-num" aria-hidden="true">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M5 13l4 4L19 7"/></svg>
                </span><span><strong>Sign in</strong> &mdash; remembered devices are signed out for safety</span></li>
            </ol>
            <div class="auth-stats">
                <div class="auth-stat"><span class="auth-stat-num" data-count-to="10">10</span><span class="auth-stat-label">minutes a code stays valid</span></div>
                <div class="auth-stat"><span class="auth-stat-num" data-count-to="6">6</span><span class="auth-stat-label">digit code</span></div>
            </div>
            <svg class="auth-aside-art" viewBox="0 0 200 200" aria-hidden="true" focusable="false"><g fill="none" stroke="#fff" stroke-width="2"><circle cx="100" cy="100" r="92" stroke-opacity=".35"/><circle cx="100" cy="100" r="70" stroke-opacity=".5" stroke-dasharray="4 8"/><rect x="52" y="66" width="96" height="68" rx="10" stroke-width="5"/><path d="M52 76l48 32 48-32" stroke-width="5" stroke-linejoin="round"/></g></svg>
        </aside>
    </div>
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
