<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$error = '';
$errors = [];
$info = '';
$notice = '';
$user_id = (int)($_POST['user_id'] ?? $_GET['user_id'] ?? 0);
$db = Database::getInstance();

$stmt = $db->prepare('SELECT id, email, role, is_verified FROM users WHERE id = :id LIMIT 1');
$stmt->execute(['id' => $user_id]);
$user = $stmt->fetch();

if (!$user || $user_id === 0) {
    show_error_page('Error', 'Invalid activation link.');
}

if ($user['is_verified']) {
    redirect('login.php');
}

$masked = mask_email($user['email']);
$is_institution = ($user['role'] === 'admin');

// The password was already chosen in THIS browser session (registration
// form, or proven at login) -> only the emailed code is needed here, so
// nobody types a password + confirmation twice. In every other case
// (account created by an institution during issuance, activation opened
// on another device) the user sets a password now, with a confirmation
// field (Compare validator).
// activation_password_known() returns the stored password-hash fingerprint
// (truthy) only while it still matches the account (see helpers.php).
$password_known = activation_password_known($user_id, $db);

if (!empty($_SESSION['registration_resumed'])) {
    $notice = 'We found your unfinished registration for this email and updated it with the details you just entered.';
    unset($_SESSION['registration_resumed']);
}

// Flash messages set by registration or resend pages
if (!empty($_SESSION['otp_send_failed'])) {
    $error = "We couldn't send the verification email right now. Please try again in a minute using 'Resend verification code'.";
    unset($_SESSION['otp_send_failed']);
} elseif (!empty($_SESSION['otp_smtp_unconfigured'])) {
    $error = smtp_not_configured_message();
    unset($_SESSION['otp_smtp_unconfigured']);
} elseif (!empty($_SESSION['otp_cooldown_seconds'])) {
    $sec = (int)$_SESSION['otp_cooldown_seconds'];
    $info = 'A verification code was sent to ' . $masked . ' less than a minute ago — enter that code below, or request a new one in '
        . $sec . ' second' . ($sec === 1 ? '' : 's') . '.';
    unset($_SESSION['otp_cooldown_seconds']);
} elseif (!empty($_SESSION['otp_limit'])) {
    $error = 'Too many codes were requested for this email in the last hour. Enter the most recent code you received, or try again later.';
    unset($_SESSION['otp_limit']);
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
            $error = smtp_not_configured_message();
        } else {
            $error = "We couldn't send the verification email right now. Please try again in a minute.";
        }
    } else {
        // ── Activation form handler ────────────────────────────────
        $code = trim((string)($_POST['otp_code'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        $confirm_password = (string)($_POST['confirm_password'] ?? '');
        $errors = [];

        if (($e = v_required($code, 'Verification Code')) !== true) { $errors['otp_code'] = $e; }
        elseif (($e = v_otp($code)) !== true) { $errors['otp_code'] = $e; }
        if (!$password_known) {
            if (($e = v_required($password, 'Password')) !== true) { $errors['password'] = $e; }
            elseif (($e = v_password_strong($password)) !== true) { $errors['password'] = $e; }
            if (($e = v_compare($password, $confirm_password, 'Passwords')) !== true) { $errors['confirm_password'] = $e; }
        }

        if (!empty($errors)) {
            $error = 'Please correct the highlighted fields below.';
        } else {
            $result = verify_otp($db, $user_id, 'activation', $code);
            if ($result === 'ok') {
                $activated = true;
                if ($password_known) {
                    // Atomic re-check: the password must still be the one this
                    // session chose (a parallel "resume" may have replaced it).
                    $upd = $db->prepare('UPDATE users SET is_verified = 1 WHERE id = :id AND is_verified = 0 AND SHA2(password_hash, 256) = :fp');
                    $upd->execute(['id' => $user_id, 'fp' => $password_known]);
                    $activated = $upd->rowCount() === 1;
                } else {
                    $hash = password_hash($password, PASSWORD_BCRYPT);
                    $db->prepare('UPDATE users SET is_verified = 1, password_hash = :hash WHERE id = :id')
                       ->execute(['hash' => $hash, 'id' => $user_id]);
                }
                unset($_SESSION['activation_pw_known'][$user_id]);
                if (!$activated) {
                    // The code was consumed but the registration changed
                    // underneath us: make the code holder set the password.
                    $password_known = '';
                    $error = 'The registration for this email was changed while you were activating. Please request a new code and set your password.';
                } elseif ($is_institution) {
                    // Institutions still need super-admin approval: say so
                    // instead of implying they can sign in straight away.
                    $st = $db->prepare('SELECT status FROM institutions WHERE user_id = :u LIMIT 1');
                    $st->execute(['u' => $user_id]);
                    if ($st->fetchColumn() !== 'approved') {
                        redirect('login.php?activated=1&awaiting_approval=1');
                    }
                    redirect('login.php?activated=1');
                } else {
                    redirect('login.php?activated=1');
                }
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
        <?php if ($password_known): ?>
            <p>Enter the 6-digit code sent to <strong><?= htmlspecialchars($masked) ?></strong> to verify your email. Your password is the one you just chose.</p>
        <?php else: ?>
            <p>Enter the 6-digit code sent to <strong><?= htmlspecialchars($masked) ?></strong> and set your password.</p>
        <?php endif; ?>
        <?php if ($is_institution): ?>
            <p class="text-muted">After verification, the CertiVault administrator reviews your institution; you can sign in once it is approved.</p>
        <?php endif; ?>
        <?php if ($notice): ?>
            <div class="alert alert-info"><?= htmlspecialchars($notice) ?></div>
        <?php endif; ?>
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
                <label for="otp_code">Verification Code:</label>
                <input type="text" name="otp_code" id="otp_code" maxlength="6" inputmode="numeric" autocomplete="one-time-code" class="otp-input" data-validate="required|otp" required>
                <?php render_field_error($errors, 'otp_code'); ?>
            </div>
            <?php if (!$password_known): ?>
            <div class="form-group">
                <label for="password">Set Password:</label>
                <input type="password" name="password" id="password" autocomplete="new-password" data-validate="required|min:8|max:72|strong" required>
                <?php render_field_error($errors, 'password'); ?>
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm Password:</label>
                <input type="password" name="confirm_password" id="confirm_password" autocomplete="new-password" data-validate="required|match:#password" required>
                <?php render_field_error($errors, 'confirm_password'); ?>
            </div>
            <?php endif; ?>
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
</div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
