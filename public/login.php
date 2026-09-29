<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    $email = sanitize_input($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($email) || empty($password)) {
        $error = 'Email and password are required.';
    } else {
        $db = Database::getInstance();
        $stmt = $db->prepare('SELECT id, password_hash, role FROM users WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();
        
        if ($user && password_verify($password, $user['password_hash'])) {
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
            
            if ($user) {
                // Prevent session fixation
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['role'] = $user['role'];
                
                redirect_to_dashboard($user['role']);
            }
        } else {
            $error = 'Invalid email or password.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container">
        <h2>Login to CertiVault</h2>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
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
            <button type="submit" class="btn">Login</button>
        </form>
        <p>Don't have an account? <a href="register_student.php">Register as Student</a> or <a href="register_institution.php">Register as Institution</a></p>
    </div>
</body>
</html>
