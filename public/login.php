<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';
$errors = [];
$success = '';
$show_resend = false;
$resend_email = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['activated'])) {
    $success = 'Account activated successfully! You can now login.';
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['password_reset'])) {
    $success = 'Password updated successfully! You can now login with your new password.';
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['expired'])) {
    $error = 'Your session expired. Please log in again.';
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['denied'])) {
    $error = 'Your institution account is no longer approved. Please contact the administrator.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    // ── POST-based resend handler ──────────────────────────────────
    if (isset($_POST['resend_activation'])) {
        $resend_email_input = sanitize_input($_POST['resend_email'] ?? '');
        $db = Database::getInstance();
        $stmt = $db->prepare('SELECT id, is_verified FROM users WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $resend_email_input]);
        $resend_user = $stmt->fetch();
        if ($resend_user && !(int)$resend_user['is_verified']) {
            $otp_result = create_otp($db, $resend_user['id'], 'activation');
            if ($otp_result === 'sent') {
                $_SESSION['otp_sent'] = true;
            } elseif ($otp_result === 'cooldown') {
                $_SESSION['otp_cooldown'] = true;
            } else {
                $_SESSION['otp_send_failed'] = true;
            }
            redirect('activate_account.php?user_id=' . $resend_user['id']);
        }
        // If user doesn't exist or is already verified, just redirect to login
        redirect('login.php');
    }

    // ── Normal login handler ───────────────────────────────────────
    $email = sanitize_input($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
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
        if (($e = v_required($password, 'Password')) !== true) { $errors['password'] = $e; }

        if (empty($errors)) {
        $db = Database::getInstance();
        $stmt = $db->prepare('SELECT id, password_hash, role, is_verified, failed_login_attempts, locked_until FROM users WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();

        // Lockout check: block before even verifying the password
        if ($user && !empty($user['locked_until']) && strtotime($user['locked_until']) > time()) {
            $error = 'Account temporarily locked due to too many failed login attempts. Please try again after ' . $user['locked_until'] . '.';
            $user = null;
        } elseif ($user && password_verify($password, $user['password_hash'])) {
            // Check institution approval status if admin
            if ($user['role'] === 'admin') {
                $instStmt = $db->prepare('SELECT status FROM institutions WHERE user_id = :user_id LIMIT 1');
                $instStmt->execute(['user_id' => $user['id']]);
                $inst = $instStmt->fetch();

                if (!$inst || $inst['status'] !== 'approved') {
                    $error = 'Your institution account is pending approval or rejected.';
                    $user = null; // nullify to prevent login
                }
            }

            if ($user && (int)$user['is_verified'] === 0) {
                $error = 'Please verify your account first — check your email for the code.';
                $show_resend = true;
                $resend_email = $email;
                $user = null; // prevent login
            }

            if ($user) {
                // Successful login: reset brute-force counter
                $db->prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = :id')
                   ->execute(['id' => $user['id']]);

                // Prevent session fixation + start fresh lifetime tracking
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['login_time'] = time();
                $_SESSION['last_activity'] = time();

                // Remember-my-email cookie (email only, never a token)
                $secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
                if (!empty($_POST['remember_email'])) {
                    setcookie('cv_email', $email, [
                        'expires'  => time() + 30 * 24 * 3600,
                        'path'     => '/',
                        'secure'   => $secure,
                        'httponly' => true,
                        'samesite' => 'Strict',
                    ]);
                } else {
                    setcookie('cv_email', '', [
                        'expires'  => time() - 3600,
                        'path'     => '/',
                        'secure'   => $secure,
                        'httponly' => true,
                        'samesite' => 'Strict',
                    ]);
                }

                redirect_to_dashboard($user['role']);
            }
        } else {
            $error = 'Invalid email or password.';

            // Track failed attempts against an existing account; lock after 5
            if ($user) {
                $attempts = (int)$user['failed_login_attempts'] + 1;
                if ($attempts >= 5) {
                    $lockUntil = date('Y-m-d H:i:s', time() + 900); // 15 minutes
                    $db->prepare('UPDATE users SET failed_login_attempts = 0, locked_until = :lock WHERE id = :id')
                       ->execute(['lock' => $lockUntil, 'id' => $user['id']]);
                    $error = 'Too many failed login attempts. Your account has been locked for 15 minutes.';
                } else {
                    $db->prepare('UPDATE users SET failed_login_attempts = :a WHERE id = :id')
                       ->execute(['a' => $attempts, 'id' => $user['id']]);
                }
            }
        }
        } // end empty($errors)
    }
}
?>
<?php generate_captcha(); ?>
<?php $page_title = 'Login - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="auth-wrap">
    <div class="auth-card">
        <div class="auth-brand">
            <svg width="40" height="40" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="16" cy="16" r="9" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M16 10 L18.2 14.2 L22.5 14.8 L19.2 17.8 L20.2 22 L16 19.6 L11.8 22 L12.8 17.8 L9.5 14.8 L13.8 14.2 Z" fill="currentColor"/></svg>
            <div class="brand-name">CertiVault</div>
        </div>
        <h2>Login to CertiVault</h2>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">Please correct the highlighted fields below.</div>
        <?php endif; ?>
        <?php $remembered_email = $_COOKIE['cv_email'] ?? ''; ?>
        <?php if ($show_resend): ?>
            <form method="POST" action="" class="inline-form" style="margin-bottom:12px;">
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <input type="hidden" name="resend_email" value="<?= htmlspecialchars($resend_email) ?>">
                <input type="hidden" name="resend_activation" value="1">
                <button type="submit" class="btn btn-secondary">Resend verification code</button>
            </form>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <div class="form-group">
                <label>Email:</label>
                <input type="email" name="email" value="<?= htmlspecialchars($email !== '' ? $email : $remembered_email) ?>" data-validate="required|email" required>
                <?php render_field_error($errors, 'email'); ?>
            </div>
            <div class="form-group">
                <label><input type="checkbox" name="remember_email" value="1" style="width:auto;" <?= $remembered_email !== '' ? 'checked' : '' ?>> Remember my email</label>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" data-validate="required" required>
                <?php render_field_error($errors, 'password'); ?>
            </div>
            <div class="form-group">
                <label>CAPTCHA:</label> <span class="captcha-chip"><?= htmlspecialchars($_SESSION['captcha_question'] ?? '') ?></span>
                <input type="text" name="captcha_answer" data-validate="required|number|min:2|max:18" required autocomplete="off">
                <?php render_field_error($errors, 'captcha_answer'); ?>
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
        <p><a href="forgot_password.php">Forgot password?</a></p>
        <p>Don't have an account? <a href="register_student.php">Register as Student</a> or <a href="register_institution.php">Register as Institution</a></p>
    </div>
    <script src="assets/js/validation.js"></script>
</div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
