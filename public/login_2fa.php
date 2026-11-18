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
<main id="main" class="auth-page">
    <div class="auth-split auth-shell">
        <div class="auth-main">
        <div class="auth-card">
            <ol class="stepper auth-stepper" aria-label="Sign-in progress">
                <li class="is-done">Password</li>
                <li class="is-current" aria-current="step">Authenticator code</li>
            </ol>
            <form method="POST" class="auth-form" id="twoFactorLogin" autocomplete="off" data-loading>
                <div class="auth-card-head">
                    <span class="auth-icon auth-icon-pulse" aria-hidden="true">
                        <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><rect x="6" y="2" width="12" height="20" rx="3"/><path d="M11 18h2"/><path d="M9.5 9.5l2 2 3.5-3.5"/></svg>
                    </span>
                    <h1>Two-factor verification</h1>
                    <p class="auth-sub">Enter the 6-digit code from your authenticator app. Lost your phone? Enter one of your recovery codes instead.</p>
                </div>
                <?php if ($error): ?><div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div><?php endif; ?>
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <div class="form-group auth-otp-group">
                    <label for="code">Authentication code</label>
                    <input type="text" id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
                           maxlength="12" required autofocus placeholder="123456 or abcd-efgh" class="code-input">
                </div>
                <button type="submit" class="btn btn-primary btn-lg btn-block">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>
                    Verify and sign in
                </button>
                <p class="auth-foot"><a href="login.php" class="auth-back-link"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M19 12H5M11 18l-6-6 6-6"/></svg> Cancel and go back to login</a></p>
            </form>
        </div>
        </div>

        <aside class="auth-aside" aria-labelledby="authAsideTitle">
            <span class="auth-eyebrow"><span class="eyebrow-dot" aria-hidden="true"></span> One more step</span>
            <h2 id="authAsideTitle">Your password was right. Now prove it's you.</h2>
            <p>This account is protected by two-factor authentication, so a stolen password alone is not enough to sign in.</p>
            <ul class="auth-points">
                <li data-reveal="left" data-reveal-delay="1"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span><span><strong>Codes refresh</strong> every 30 seconds in your app</span></li>
                <li data-reveal="left" data-reveal-delay="2"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2"/></svg></span><span><strong>Recovery codes</strong> work once each, if your phone is lost</span></li>
                <li data-reveal="left" data-reveal-delay="3"><span class="auth-point-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/></svg></span><span><strong>5 attempts</strong> in 5 minutes, then sign in again</span></li>
            </ul>
            <svg class="auth-aside-art" viewBox="0 0 200 200" aria-hidden="true" focusable="false"><g fill="none" stroke="#fff" stroke-width="2"><circle cx="100" cy="100" r="92" stroke-opacity=".35"/><circle cx="100" cy="100" r="70" stroke-opacity=".5" stroke-dasharray="4 8"/><rect x="70" y="44" width="60" height="112" rx="14" stroke-width="5"/><path d="M92 140h16M86 94l10 10 18-18" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></g></svg>
        </aside>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
