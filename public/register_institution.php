<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';
$errors = [];
$success = '';
$account_exists = false;
$name = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    // Non-secret fields are kept and re-rendered on any failure (wrong
    // CAPTCHA, validation error, existing account); the password never is.
    $name = sanitize_input($_POST['name'] ?? '');
    $email = normalize_email($_POST['email'] ?? '');
    $password = (string)($_POST['password'] ?? '');

    // Mode-aware CAPTCHA: reCAPTCHA v2 when keys are configured,
    // offline arithmetic fallback otherwise.
    if (!validate_captcha($errors)) {
        $error = 'Please correct the highlighted fields below.';
    } else {
        if (($e = v_required($name, 'Institution Name')) !== true) { $errors['name'] = $e; }
        elseif (($e = v_length($name, 2, 100, 'Institution Name')) !== true) { $errors['name'] = $e; }
        if (($e = v_required($email, 'Email')) !== true) { $errors['email'] = $e; }
        elseif (($e = v_email($email)) !== true) { $errors['email'] = $e; }
        // One password field (+ show/hide toggle) — no confirmation box at
        // registration. The Compare validator (v_compare) still guards the
        // reset / change / activation-without-known-password forms.
        if (($e = v_required($password, 'Password')) !== true) { $errors['password'] = $e; }
        elseif (($e = v_password_strong($password)) !== true) { $errors['password'] = $e; }

        if (empty($errors)) {
            $db = Database::getInstance();
            try {
                // Creates the account, or resumes an unfinished (never
                // activated) registration for the same email — including
                // one that was started as a student.
                $reg = register_or_resume_account($db, 'admin', $email, $password, ['name' => $name]);
            } catch (Throwable $e) {
                error_log('CertiVault registration failed: ' . $e->getMessage());
                $reg = ['status' => 'error'];
            }
            if ($reg['status'] === 'created' || $reg['status'] === 'resumed') {
                if ($reg['status'] === 'resumed') {
                    $_SESSION['registration_resumed'] = true;
                }
                mark_activation_password_known($reg['user_id'], $db);
                queue_activation_otp($db, $reg['user_id']);
                redirect('activate_account.php?user_id=' . (int)$reg['user_id']);
            } elseif ($reg['status'] === 'exists') {
                $account_exists = true;
                $errors['email'] = 'An account with this email already exists.';
            } elseif ($reg['status'] === 'blocked') {
                $error = 'This email has an unfinished registration that cannot be replaced automatically. Please contact the administrator.';
            } else {
                $error = 'Registration failed. Please try again.';
            }
        }
    }
}
?>
<?php $page_title = 'Institution Registration - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="auth-wrap">
    <div class="auth-card">
        <div class="auth-brand">
            <svg width="40" height="40" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="16" cy="16" r="9" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M16 10 L18.2 14.2 L22.5 14.8 L19.2 17.8 L20.2 22 L16 19.6 L11.8 22 L12.8 17.8 L9.5 14.8 L13.8 14.2 Z" fill="currentColor"/></svg>
            <div class="brand-name">CertiVault</div>
        </div>
        <h2>Institution Registration</h2>
        <p class="text-muted">After you verify your email, the CertiVault administrator reviews and approves your institution before you can issue certificates.</p>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>
        <?php if ($account_exists): ?>
            <div class="alert alert-info" role="alert" data-account-exists>
                An account with this email already exists.
                <a href="login.php">Log in</a> or <a href="forgot_password.php">reset your password</a>.
            </div>
        <?php elseif (!empty($errors)): ?>
            <div class="alert alert-danger">Please correct the highlighted fields below.</div>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <div class="form-group">
                <label for="inst_name">Institution Name:</label>
                <input type="text" name="name" id="inst_name" autocomplete="organization" value="<?= htmlspecialchars($name) ?>" data-validate="required|min:2|max:100" required>
                <?php render_field_error($errors, 'name'); ?>
            </div>
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" name="email" id="email" autocomplete="email" value="<?= htmlspecialchars($email) ?>" data-validate="required|email" required>
                <?php render_field_error($errors, 'email'); ?>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" name="password" id="password" autocomplete="new-password" aria-describedby="password_hint" data-validate="required|min:8|max:72|strong" required>
                <small id="password_hint" class="help-text">8–72 characters with an uppercase letter, a lowercase letter, a digit and a special character. Use the eye button to check what you typed.</small>
                <?php render_field_error($errors, 'password'); ?>
            </div>
            <div class="form-group">
                <?= captcha_field_html($errors) ?>
            </div>
            <button type="submit" class="btn btn-primary">Register</button>
        </form>
        <p>Already have an account? <a href="login.php">Login here</a></p>
        <p class="text-muted">Started registering before but never entered the emailed code? Just register again with the same email — we'll pick up where you left off.</p>
    </div>
    <script src="assets/js/validation.js"></script>
</div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
