<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    $name = sanitize_input($_POST['name'] ?? '');
    $email = sanitize_input($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    
    if (empty($name) || empty($email) || empty($password)) {
        $error = 'All fields are required.';
    } else {
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
                $success = 'Registration successful! Your account is pending approval.';
            } catch (Exception $e) {
                $db->rollBack();
                $error = 'Registration failed. Please try again.';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Institution Registration - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container">
        <h2>Institution Registration</h2>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success"><?= htmlspecialchars($success) ?></div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <div class="form-group">
                <label>Institution Name:</label>
                <input type="text" name="name" required>
            </div>
            <div class="form-group">
                <label>Email:</label>
                <input type="email" name="email" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn">Register</button>
        </form>
        <p>Already have an account? <a href="login.php">Login here</a></p>
    </div>
</body>
</html>
