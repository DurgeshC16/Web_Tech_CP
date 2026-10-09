<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';
$errors = [];
$success = '';
$name = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    $name = sanitize_input($_POST['name'] ?? '');
    $email = sanitize_input($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // Mode-aware CAPTCHA: reCAPTCHA v2 when keys are configured,
    // offline arithmetic fallback otherwise.
    if (!validate_captcha($errors)) {
        $error = 'Please correct the highlighted fields below.';
    } else {
        if (($e = v_required($name, 'Institution Name')) !== true) { $errors['name'] = $e; }
        elseif (($e = v_length($name, 2, 100, 'Institution Name')) !== true) { $errors['name'] = $e; }
        if (($e = v_required($email, 'Email')) !== true) { $errors['email'] = $e; }
        elseif (($e = v_email($email)) !== true) { $errors['email'] = $e; }
        if (($e = v_required($password, 'Password')) !== true) { $errors['password'] = $e; }
        elseif (($e = v_password_strong($password)) !== true) { $errors['password'] = $e; }
        if (($e = v_compare($password, $confirm_password, 'Passwords')) !== true) { $errors['confirm_password'] = $e; }

        if (empty($errors)) {
        $db = Database::getInstance();
        
        // Check if email exists
        $stmt = $db->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $email]);
        if ($stmt->fetch()) {
            $error = 'Email already registered.';
        } else {
            try {
                $db->beginTransaction();
                
                $hash = password_hash($password, PASSWORD_BCRYPT);
                $stmt = $db->prepare('INSERT INTO users (email, password_hash, role) VALUES (:email, :hash, "admin")');
                $stmt->execute(['email' => $email, 'hash' => $hash]);
                $user_id = $db->lastInsertId();
                
                $stmt = $db->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:user_id, :name, "pending")');
                $stmt->execute(['user_id' => $user_id, 'name' => $name]);
                
                $db->commit();
                $otp_result = create_otp($db, $user_id, 'activation');
                if ($otp_result === 'sent') {
                    $_SESSION['otp_sent'] = true;
                } else {
                    $_SESSION['otp_send_failed'] = true;
                }
                redirect('activate_account.php?user_id=' . $user_id);
            } catch (Exception $e) {
                $db->rollBack();
                $error = 'Registration failed. Please try again.';
            }
        }
        } // end empty($errors)
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
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>
        
        <?php if (!empty($errors)): ?>
            <div class="alert alert-danger">Please correct the highlighted fields below.</div>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <div class="form-group">
                <label>Institution Name:</label>
                <input type="text" name="name" value="<?= htmlspecialchars($name) ?>" data-validate="required|min:2|max:100" required>
                <?php render_field_error($errors, 'name'); ?>
            </div>
            <div class="form-group">
                <label>Email:</label>
                <input type="email" name="email" value="<?= htmlspecialchars($email) ?>" data-validate="required|email" required>
                <?php render_field_error($errors, 'email'); ?>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" id="password" data-validate="required|min:8|max:72|strong" required>
                <?php render_field_error($errors, 'password'); ?>
            </div>
            <div class="form-group">
                <label>Confirm Password:</label>
                <input type="password" name="confirm_password" data-validate="required|match:#password" required>
                <?php render_field_error($errors, 'confirm_password'); ?>
            </div>
            <div class="form-group">
                <?= captcha_field_html($errors) ?>
            </div>
            <button type="submit" class="btn btn-primary">Register</button>
        </form>
        <p>Already have an account? <a href="login.php">Login here</a></p>
    </div>
    <script src="assets/js/validation.js"></script>
</div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
