<?php
// public/login_2fa.php — second login step for accounts with TOTP 2FA.
// Reached only after a correct password (login.php stores a short-lived
// $_SESSION['2fa_pending']); accepts a 6-digit authenticator code or a
// single-use recovery code. 5 attempts / 5 minutes, then back to login.
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/TotpService.php';

$db = Database::getInstance();
$pending = $_SESSION['2fa_pending'] ?? null;
if (!$pending || ($pending['expires'] ?? 0) < time()) {
    unset($_SESSION['2fa_pending']);
    redirect('login.php?expired=1');
}

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    $code = trim((string)($_POST['code'] ?? ''));
    $_SESSION['2fa_pending']['attempts'] = (int)$pending['attempts'] + 1;
    $used = $code !== '' ? TotpService::verifyForUser($db, (int)$pending['user_id'], $code) : null;

    if ($used !== null) {
        unset($_SESSION['2fa_pending']);
        if ($used === 'recovery') {
            error_log('[CertiVault] 2FA recovery code used for user_id ' . (int)$pending['user_id']);
        }
        finish_login($db, ['id' => $pending['user_id'], 'role' => $pending['role']], (string)$pending['email'],
            (bool)$pending['remember_me'], (bool)$pending['remember_email']);
    }
    if ($_SESSION['2fa_pending']['attempts'] >= 5) {
        unset($_SESSION['2fa_pending']);
        record_failed_login_attempt($db, (string)$pending['email'], login_client_ip());
        redirect('login.php?2fa_failed=1');
    }
    $error = 'That code is not valid. Use the current 6-digit code from your authenticator app, or one of your recovery codes.';
}

$page_title = 'Two-factor verification - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main">
    <div class="container shell-narrow">
        <form method="POST" class="card" id="twoFactorLogin" autocomplete="off">
            <h2 class="card-title">Two-factor verification</h2>
            <p class="text-muted">Enter the 6-digit code from your authenticator app. Lost your phone? Enter one of your recovery codes instead.</p>
            <?php if ($error): ?><div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div><?php endif; ?>
            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
            <div class="form-group">
                <label for="code">Authentication code</label>
                <input type="text" id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
                       maxlength="12" required autofocus placeholder="123456 or abcd-efgh">
            </div>
            <button type="submit" class="btn btn-primary btn-block">Verify and sign in</button>
            <p class="text-muted small text-center"><a href="login.php">Cancel and go back to login</a></p>
        </form>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
