<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';
$user_id = (int)($_POST['user_id'] ?? $_GET['user_id'] ?? 0);
$db = Database::getInstance();

$stmt = $db->prepare('SELECT id, email, is_verified FROM users WHERE id = :id LIMIT 1');
$stmt->execute(['id' => $user_id]);
$user = $stmt->fetch();

if (!$user || $user_id === 0) {
    show_error_page('Error', 'Invalid activation link.');
}

if ($user['is_verified']) {
    redirect('login.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    $code = trim($_POST['otp_code'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // Fetch the latest unused activation code for this user to give precise errors
    $stmt = $db->prepare("SELECT otp_code, expires_at FROM otp_codes WHERE user_id = :uid AND purpose = 'activation' AND used = 0 ORDER BY id DESC LIMIT 1");
    $stmt->execute(['uid' => $user_id]);
    $otp = $stmt->fetch();

    if (empty($code) || empty($password) || empty($confirm_password)) {
        $error = 'All fields are required.';
    } elseif ($password !== $confirm_password) {
        $error = 'Passwords do not match.';
    } elseif (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters.';
    } elseif (!$otp) {
        $error = 'No active verification code. Please request a new one.';
    } elseif (strtotime($otp['expires_at']) < time()) {
        $error = 'This verification code has expired. Please request a new one.';
    } elseif ($code !== $otp['otp_code']) {
        $error = 'Incorrect verification code.';
    } else {
        $db->beginTransaction();
        try {
            $stmt = $db->prepare("UPDATE otp_codes SET used = 1 WHERE user_id = :uid AND purpose = 'activation' AND used = 0");
            $stmt->execute(['uid' => $user_id]);

            $hash = password_hash($password, PASSWORD_BCRYPT);
            $stmt = $db->prepare('UPDATE users SET is_verified = 1, password_hash = :hash WHERE id = :id');
            $stmt->execute(['hash' => $hash, 'id' => $user_id]);

            $db->commit();
            unset($_SESSION['dev_otp_display']);
            redirect('login.php?activated=1');
        } catch (Exception $e) {
            $db->rollBack();
            $error = 'Activation failed. Please try again.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Activate Account - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container">
        <h2>Activate Your Account</h2>
        <p>Enter the 6-digit code sent to <strong><?= htmlspecialchars($user['email']) ?></strong> and set your password.</p>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php
        // DEV/DEMO ONLY: because local SMTP is not guaranteed, show the OTP
        // directly on screen. Strictly guarded by $is_production — never in
        // production (CV_ENV=production).
        if (!$is_production && isset($_SESSION['dev_otp_display'])): ?>
            <div class="alert alert-success">
                <strong>Dev mode — your verification code is:</strong>
                <?= htmlspecialchars($_SESSION['dev_otp_display']) ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <input type="hidden" name="user_id" value="<?= (int)$user_id ?>">
            <div class="form-group">
                <label>Verification Code:</label>
                <input type="text" name="otp_code" maxlength="6" required autocomplete="off">
            </div>
            <div class="form-group">
                <label>Set Password:</label>
                <input type="password" name="password" required>
            </div>
            <div class="form-group">
                <label>Confirm Password:</label>
                <input type="password" name="confirm_password" required>
            </div>
            <button type="submit" class="btn">Activate Account</button>
        </form>
        <p>Need a new code? <a href="login.php?resend=<?= urlencode($user['email']) ?>">Resend verification code</a></p>
    </div>
</body>
</html>
