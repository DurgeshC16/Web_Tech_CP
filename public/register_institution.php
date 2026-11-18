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
<main id="main" class="auth-page">
    <div class="auth-split auth-shell">
        <div class="auth-main">
        <div class="auth-card auth-card-wide">
            <nav class="tabs auth-role-tabs" aria-label="Account type">
                <a href="register_student.php" class="tab">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M22 10L12 5 2 10l10 5 10-5z"/><path d="M6 12v5c3 2 9 2 12 0v-5"/></svg>
                    Student
                </a>
                <a href="register_institution.php" class="tab active" aria-current="page">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 21h18M5 21V10M19 21V10M9 21v-6h6v6M2 10l10-6 10 6"/></svg>
                    Institution
                </a>
            </nav>
            <div class="auth-card-head">
                <h1>Institution Registration</h1>
                <p class="auth-sub">After you verify your email, the CertiVault administrator reviews and approves your institution before you can issue certificates.</p>
            </div>
            <ol class="stepper auth-stepper" aria-label="Registration progress">
                <li class="is-current" aria-current="step">Your details</li>
                <li>Verify email</li>
                <li>Admin review</li>
            </ol>
            <?php if ($error): ?>
                <div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <?php if ($success): ?>
                <div class="alert alert-success" role="status"><?= htmlspecialchars($success) ?></div>
            <?php endif; ?>
            <?php if ($account_exists): ?>
                <div class="alert alert-info" role="alert" data-account-exists>
                    An account with this email already exists.
                    <a href="login.php">Log in</a> or <a href="forgot_password.php">reset your password</a>.
                </div>
            <?php elseif (!empty($errors)): ?>
                <div class="alert alert-danger">Please correct the highlighted fields below.</div>
            <?php endif; ?>

            <form method="POST" action="" class="auth-form" data-loading>
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <div class="form-group">
                    <label for="inst_name">Institution Name</label>
                    <input type="text" name="name" id="inst_name" autocomplete="organization" placeholder="e.g. Northbridge University" value="<?= htmlspecialchars($name) ?>" data-validate="required|min:2|max:100" required>
                    <?php render_field_error($errors, 'name'); ?>
                </div>
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" name="email" id="email" autocomplete="email" placeholder="registrar@institution.edu" value="<?= htmlspecialchars($email) ?>" data-validate="required|email" required>
                    <?php render_field_error($errors, 'email'); ?>
                </div>
                <div class="form-group auth-password-group">
                    <label for="password">Password</label>
                    <input type="password" name="password" id="password" autocomplete="new-password" aria-describedby="password_hint" data-validate="required|min:8|max:72|strong" required>
                    <small id="password_hint" class="help-text">8–72 characters with an uppercase letter, a lowercase letter, a digit and a special character. Use the eye button to check what you typed.</small>
                    <?php render_field_error($errors, 'password'); ?>
                </div>
                <div class="form-group auth-captcha">
                    <?= captcha_field_html($errors) ?>
                </div>
                <button type="submit" class="btn btn-primary btn-lg btn-block">Register</button>
            </form>
            <p class="auth-foot">Already have an account? <a href="login.php">Login here</a></p>
            <p class="auth-note">Started registering before but never entered the emailed code? Just register again with the same email — we'll pick up where you left off.</p>
        </div>
        </div>

        <aside class="auth-aside" aria-labelledby="authAsideTitle">
            <span class="auth-eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span> For institutions</span>
            <h2 id="authAsideTitle">Issue certificates nobody can forge.</h2>
            <p>Your institution gets its own signing key. Every certificate you issue carries a signature and a QR code that anyone can check.</p>
            <ul class="auth-points">
                <li data-reveal="left" data-reveal-delay="1"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2"/></svg></span><span><strong>Dedicated signing key</strong> for your institution</span></li>
                <li data-reveal="left" data-reveal-delay="2"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M4 6h16M4 12h16M4 18h10"/></svg></span><span><strong>Single or bulk issuance</strong> from one dashboard</span></li>
                <li data-reveal="left" data-reveal-delay="3"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M3 3v18h18"/><path d="M7 15l4-4 3 3 5-6"/></svg></span><span><strong>Audit logs and analytics</strong> for every verification</span></li>
            </ul>
            <div class="auth-stats">
                <div class="auth-stat"><span class="auth-stat-num" data-count-to="2048">2048</span><span class="auth-stat-label">bit RSA signing keys</span></div>
                <div class="auth-stat"><span class="auth-stat-num" data-count-to="3">3</span><span class="auth-stat-label">steps to approval</span></div>
            </div>
            <svg class="auth-aside-art" viewBox="0 0 200 200" aria-hidden="true" focusable="false"><g fill="none" stroke="#fff" stroke-width="2"><circle cx="100" cy="100" r="92" stroke-opacity=".35"/><circle cx="100" cy="100" r="70" stroke-opacity=".5" stroke-dasharray="4 8"/><path d="M50 150h100M60 150V96M140 150V96M84 150v-28h32v28M44 96l56-34 56 34" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></g></svg>
        </aside>
    </div>
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
