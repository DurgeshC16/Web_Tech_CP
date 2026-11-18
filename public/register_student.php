<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';
$errors = [];
$success = '';
$account_exists = false;
$fullName = '';
$enrollment = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    // Non-secret fields are kept and re-rendered on any failure (wrong
    // CAPTCHA, validation error, existing account); the password never is.
    $fullName = sanitize_input($_POST['full_name'] ?? '');
    $enrollment = sanitize_input($_POST['enrollment_number'] ?? '');
    $email = normalize_email($_POST['email'] ?? '');
    $password = (string)($_POST['password'] ?? '');

    // Mode-aware CAPTCHA: reCAPTCHA v2 when keys are configured,
    // offline arithmetic fallback otherwise.
    if (!validate_captcha($errors)) {
        $error = 'Please correct the highlighted fields below.';
    } else {
        if (($e = v_required($fullName, 'Full Name')) !== true) { $errors['full_name'] = $e; }
        elseif (($e = v_person_name($fullName)) !== true) { $errors['full_name'] = $e; }
        if ($enrollment !== '') {
            if (($e = v_length($enrollment, 5, 20, 'Enrollment number')) !== true) { $errors['enrollment_number'] = $e; }
            elseif (($e = v_number($enrollment, 0)) !== true || !ctype_digit($enrollment)) { $errors['enrollment_number'] = 'Enrollment number must contain digits only.'; }
        }
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
                // activated) registration for the same email.
                $reg = register_or_resume_account($db, 'student', $email, $password, [
                    'full_name' => $fullName,
                    'enrollment_number' => $enrollment,
                ]);
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
<?php $page_title = 'Student Registration - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main" class="auth-page">
    <div class="auth-split auth-shell">
        <div class="auth-main">
        <div class="auth-card auth-card-wide">
            <nav class="tabs auth-role-tabs" aria-label="Account type">
                <a href="register_student.php" class="tab active" aria-current="page">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M22 10L12 5 2 10l10 5 10-5z"/><path d="M6 12v5c3 2 9 2 12 0v-5"/></svg>
                    Student
                </a>
                <a href="register_institution.php" class="tab">
                    <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M3 21h18M5 21V10M19 21V10M9 21v-6h6v6M2 10l10-6 10 6"/></svg>
                    Institution
                </a>
            </nav>
            <div class="auth-card-head">
                <h1>Student Registration</h1>
                <p class="auth-sub">Create your account to collect and share your certificates.</p>
            </div>
            <ol class="stepper auth-stepper" aria-label="Registration progress">
                <li class="is-current" aria-current="step">Your details</li>
                <li>Verify email</li>
                <li>Sign in</li>
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
                <div class="form-row">
                    <div class="form-group">
                        <label for="full_name">Full Name</label>
                        <input type="text" name="full_name" id="full_name" autocomplete="name" placeholder="As on your certificates" value="<?= htmlspecialchars($fullName) ?>" data-validate="required|personname" required>
                        <?php render_field_error($errors, 'full_name'); ?>
                    </div>
                    <div class="form-group">
                        <label for="enrollment_number">Enrollment Number <span class="auth-optional">(Optional)</span></label>
                        <input type="text" name="enrollment_number" id="enrollment_number" inputmode="numeric" placeholder="Digits only" value="<?= htmlspecialchars($enrollment) ?>" data-validate="enrollment">
                        <?php render_field_error($errors, 'enrollment_number'); ?>
                    </div>
                </div>
                <div class="form-group">
                    <label for="email">Email</label>
                    <input type="email" name="email" id="email" autocomplete="email" placeholder="you@example.com" value="<?= htmlspecialchars($email) ?>" data-validate="required|email" required>
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
            <span class="auth-eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span> For students</span>
            <h2 id="authAsideTitle">Your achievements, verifiable anywhere.</h2>
            <p>Keep every certificate your institution issues in one place and prove it is genuine with a single link or QR code.</p>
            <ul class="auth-points">
                <li data-reveal="left" data-reveal-delay="1"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M4 4h16v13H4z"/><path d="M8 21h8M12 17v4M8 9h8M8 12h5"/></svg></span><span><strong>All certificates</strong> in one dashboard</span></li>
                <li data-reveal="left" data-reveal-delay="2"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/><path d="M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/></svg></span><span><strong>Share links</strong> employers can verify</span></li>
                <li data-reveal="left" data-reveal-delay="3"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg></span><span><strong>Private</strong> and protected by email verification</span></li>
            </ul>
            <div class="auth-stats">
                <div class="auth-stat"><span class="auth-stat-num" data-count-to="3">3</span><span class="auth-stat-label">quick steps</span></div>
                <div class="auth-stat"><span class="auth-stat-num" data-count-to="6">6</span><span class="auth-stat-label">digit email code</span></div>
                <div class="auth-stat"><span class="auth-stat-num" data-count-to="1">1</span><span class="auth-stat-label">link to share proof</span></div>
            </div>
            <svg class="auth-aside-art" viewBox="0 0 200 200" aria-hidden="true" focusable="false"><g fill="none" stroke="#fff" stroke-width="2"><circle cx="100" cy="100" r="92" stroke-opacity=".35"/><circle cx="100" cy="100" r="70" stroke-opacity=".5" stroke-dasharray="4 8"/><path d="M160 86L100 58 40 86l60 28 60-28z" stroke-width="5" stroke-linejoin="round"/><path d="M64 98v28c18 12 54 12 72 0V98M160 86v34" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></g></svg>
        </aside>
    </div>
    <script src="assets/js/validation.js"></script>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
