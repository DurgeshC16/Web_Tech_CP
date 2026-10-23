<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';
$errors = [];
$info = '';
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

$masked = mask_email($user['email']);

// Flash messages set by registration or resend pages
if (!empty($_SESSION['otp_send_failed'])) {
    $error = "We couldn't send the verification email right now. Please try again in a minute using 'Resend verification code'.";
    unset($_SESSION['otp_send_failed']);
} elseif (!empty($_SESSION['otp_smtp_unconfigured'])) {
    $error = 'Email delivery is not set up on this server. Contact the administrator.';
    unset($_SESSION['otp_smtp_unconfigured']);
} elseif (!empty($_SESSION['otp_cooldown_seconds'])) {
    $sec = (int)$_SESSION['otp_cooldown_seconds'];
    $error = 'A verification code was sent recently. Try again in ' . $sec . ' second' . ($sec === 1 ? '' : 's') . '.';
    unset($_SESSION['otp_cooldown_seconds']);
} elseif (!empty($_SESSION['otp_sent'])) {
    $info = "We've sent a 6-digit code to " . $masked . ".";
    unset($_SESSION['otp_sent']);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    // ── Resend handler (POST-based with CSRF) ──────────────────────
    if (isset($_POST['resend_otp'])) {
        $otp_result = create_otp($db, $user_id, 'activation');
        if ($otp_result === 'sent') {
            $info = "We've sent a new 6-digit code to " . $masked . ".";
        } elseif ($otp_result === 'cooldown') {
            $sec = otp_cooldown_remaining($db, $user_id, 'activation');
            $error = 'A code was sent recently. Try again in ' . max($sec, 1) . ' second' . ($sec === 1 ? '' : 's') . '.';
        } elseif ($otp_result === 'limit') {
            $error = 'Too many codes requested. Please try again later.';
        } elseif ($otp_result === 'smtp_not_configured') {
            $error = 'Email delivery is not set up on this server. Contact the administrator.';
        } else {
            $error = "We couldn't send the verification email right now. Please try again in a minute.";
        }
    } else {
        // ── Activation form handler ────────────────────────────────
        $code = trim($_POST['otp_code'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm_password = $_POST['confirm_password'] ?? '';
        $errors = [];

        if (($e = v_required($code, 'Verification Code')) !== true) { $errors['otp_code'] = $e; }
        elseif (($e = v_otp($code)) !== true) { $errors['otp_code'] = $e; }
        if (($e = v_required($password, 'Password')) !== true) { $errors['password'] = $e; }
        elseif (($e = v_password_strong($password)) !== true) { $errors['password'] = $e; }
        if (($e = v_compare($password, $confirm_password, 'Passwords')) !== true) { $errors['confirm_password'] = $e; }

        if (!empty($errors)) {
            $error = 'Please correct the highlighted fields below.';
        } else {
            $result = verify_otp($db, $user_id, 'activation', $code);
            if ($result === 'ok') {
                $hash = password_hash($password, PASSWORD_BCRYPT);
                $stmt = $db->prepare('UPDATE users SET is_verified = 1, password_hash = :hash WHERE id = :id');
                $stmt->execute(['hash' => $hash, 'id' => $user_id]);
                redirect('login.php?activated=1');
            } elseif ($result === 'expired') {
                $error = 'This verification code has expired. Please request a new one.';
            } elseif ($result === 'locked') {
                $error = 'Too many incorrect attempts. This code has been invalidated. Please request a new one.';
            } elseif ($result === 'none') {
                $error = 'No active verification code. Please request a new one.';
            } else {
                $error = 'Incorrect verification code.';
            }
        }
    }
}
?>
<?php $page_title = 'Activate Account - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="auth-wrap">
    <div class="auth-card">
        <div class="auth-brand">
            <svg width="40" height="40" viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="14" fill="none" stroke="currentColor" stroke-width="2"/><circle cx="16" cy="16" r="9" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M16 10 L18.2 14.2 L22.5 14.8 L19.2 17.8 L20.2 22 L16 19.6 L11.8 22 L12.8 17.8 L9.5 14.8 L13.8 14.2 Z" fill="currentColor"/></svg>
            <div class="brand-name">CertiVault</div>
        </div>
        <h2>Activate Your Account</h2>
        <p>Enter the 6-digit code sent to <strong><?= htmlspecialchars($masked) ?></strong> and set your password.</p>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        <?php if ($info): ?>
            <div class="alert alert-success"><?= htmlspecialchars($info) ?></div>
        <?php endif; ?>

        <form method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <input type="hidden" name="user_id" value="<?= (int)$user_id ?>">
            <div class="form-group">
                <label>Verification Code:</label>
                <input type="text" name="otp_code" maxlength="6" inputmode="numeric" autocomplete="one-time-code" class="otp-input" data-validate="required|otp" required>
                <?php render_field_error($errors, 'otp_code'); ?>
            </div>
            <div class="form-group">
                <label>Set Password:</label>
                <input type="password" name="password" id="password" data-validate="required|min:8|max:72|strong" required>
                <?php render_field_error($errors, 'password'); ?>
            </div>
            <div class="form-group">
                <label>Confirm Password:</label>
                <input type="password" name="confirm_password" data-validate="required|match:#password" required>
                <?php render_field_error($errors, 'confirm_password'); ?>
            </div>
            <button type="submit" class="btn btn-primary">Activate Account</button>
        </form>
        <form method="POST" action="" style="margin-top:12px;">
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <input type="hidden" name="user_id" value="<?= (int)$user_id ?>">
            <input type="hidden" name="resend_otp" value="1">
            <?php $resend_wait = otp_cooldown_remaining($db, $user_id, 'activation'); ?>
            <button type="submit" class="btn btn-secondary" id="resendBtn" <?php if ($resend_wait > 0) echo 'data-wait="' . (int)$resend_wait . '"'; ?>>Resend verification code</button>
            <?php if ($resend_wait > 0): ?>
                <small class="field-note" style="margin-left:8px;" id="resendCountdown">Try again in <?= (int)$resend_wait ?> second<?= $resend_wait === 1 ? '' : 's' ?>.</small>
            <?php endif; ?>
        </form>
    </div>
    <script src="assets/js/validation.js"></script>
    <script>
    (function () {
        var btn = document.getElementById('resendBtn');
        if (!btn) return;
        var seconds = parseInt(btn.getAttribute('data-wait') || '0', 10);
        if (!(seconds > 0)) return;
        var label = btn.textContent;
        var note = document.getElementById('resendCountdown');
        var t = setInterval(function () {
            seconds--;
            if (seconds <= 0) {
                clearInterval(t);
                btn.disabled = false;
                btn.textContent = label;
                btn.removeAttribute('aria-disabled');
                if (note) note.textContent = '';
                return;
            }
            btn.disabled = true;
            btn.setAttribute('aria-disabled', 'true');
            btn.textContent = 'Try again in ' + seconds + ' second' + (seconds === 1 ? '' : 's');
            if (note) note.textContent = 'You can resend after the cooldown — a code was just sent.';
        }, 1000);
        btn.disabled = true;
        btn.setAttribute('aria-disabled', 'true');
        btn.textContent = 'Try again in ' + seconds + ' second' + (seconds === 1 ? '' : 's');
    })();
    </script>
</div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
