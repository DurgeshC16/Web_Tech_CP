<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';
$success = '';
$show_resend = false;
$resend_email = '';

// Resend-activation-code handler (linked from login / activation errors)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['resend'])) {
    $db = Database::getInstance();
    $stmt = $db->prepare('SELECT id, is_verified FROM users WHERE email = :email LIMIT 1');
    $stmt->execute(['email' => sanitize_input($_GET['resend'])]);
    $resend_user = $stmt->fetch();
    if ($resend_user && !(int)$resend_user['is_verified']) {
        create_otp($db, $resend_user['id'], 'activation'); // invalidates any old unused code first
        redirect('activate_account.php?user_id=' . $resend_user['id']);
    }
    redirect('login.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['activated'])) {
    $success = 'Account activated successfully! You can now login.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    $email = sanitize_input($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (!verify_captcha()) {
        $error = 'Incorrect CAPTCHA answer. Please try again.';
    } elseif (empty($email) || empty($password)) {
        $error = 'Email and password are required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Please provide a valid email address.';
    } else {
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

                // Prevent session fixation
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['role'] = $user['role'];
                
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
    }
}
?>
<?php generate_captcha(); ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <?php require_once __DIR__ . '/../src/partials/head_fonts.php'; ?>
</head>
<body>
    <div class="container shell-narrow">
        <h2>Login to CertiVault</h2>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($show_resend): ?>
            <p><a href="login.php?resend=<?= urlencode($resend_email) ?>">Resend verification code</a></p>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <div class="form-group">
                <label>Email:</label>
                <input type="email" name="email" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <div class="form-group">
                <label>CAPTCHA: <?= htmlspecialchars($_SESSION['captcha_question'] ?? '') ?></label>
                <input type="text" name="captcha_answer" required autocomplete="off">
            </div>
            <button type="submit" class="btn btn-primary">Login</button>
        </form>
        <p>Don't have an account? <a href="register_student.php">Register as Student</a> or <a href="register_institution.php">Register as Institution</a></p>
    </div>
</body>
</html>
