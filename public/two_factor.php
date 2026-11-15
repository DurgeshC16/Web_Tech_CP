<?php
// public/two_factor.php — set up, manage or turn off TOTP two-factor
// authentication for the signed-in account (any role).
//   start   → new secret kept in the session; QR (two_factor_qr.php) + key
//   confirm → the user proves the app works with a current code → enabled,
//             10 recovery codes shown ONCE
//   regen   → new recovery codes (needs a current code)
//   disable → needs the account password AND a current code / recovery code
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/TotpService.php';

require_role(['admin', 'student', 'super_admin']);
if ($_SESSION['role'] === 'admin') {
    require_approved_institution();
}

$db = Database::getInstance();
$userId = (int)$_SESSION['user_id'];
$u = $db->prepare('SELECT email, password_hash FROM users WHERE id = :id');
$u->execute(['id' => $userId]);
$account = $u->fetch();

$error = '';
$message = '';
$newCodes = null;
$setup = $_SESSION['totp_setup'] ?? null;
if ($setup && $setup['created'] < time() - 900) {
    unset($_SESSION['totp_setup']);
    $setup = null;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    $action = $_POST['action'] ?? '';
    $enabled = TotpService::enabledFor($db, $userId);

    if ($action === 'start' && !$enabled) {
        $setup = ['secret' => TotpService::generateSecret(), 'created' => time()];
        $_SESSION['totp_setup'] = $setup;
    } elseif ($action === 'confirm' && !$enabled && $setup) {
        $step = TotpService::verifyCode($setup['secret'], (string)($_POST['code'] ?? ''));
        if ($step === null) {
            $error = 'That code did not match. Check the time on your phone and enter the current 6-digit code.';
        } else {
            $newCodes = TotpService::enable($db, $userId, $setup['secret'], $step);
            unset($_SESSION['totp_setup']);
            $setup = null;
            $message = 'Two-factor authentication is on. Save your recovery codes now — they are shown only once.';
            send_notification_email($account['email'], 'Two-factor authentication enabled', 'Two-factor authentication is now on',
                'Two-factor authentication was enabled for your CertiVault account. You will need your authenticator app (or a recovery code) to sign in.');
        }
    } elseif ($action === 'regen' && $enabled) {
        if (TotpService::verifyForUser($db, $userId, (string)($_POST['code'] ?? '')) !== 'totp') {
            $error = 'Enter a current code from your authenticator app to create new recovery codes.';
        } else {
            $newCodes = TotpService::replaceRecoveryCodes($db, $userId);
            $message = 'New recovery codes created. The old ones no longer work.';
        }
    } elseif ($action === 'disable' && $enabled) {
        if (!password_verify((string)($_POST['password'] ?? ''), (string)$account['password_hash'])) {
            $error = 'Your password is incorrect.';
        } elseif (TotpService::verifyForUser($db, $userId, (string)($_POST['code'] ?? '')) === null) {
            $error = 'Enter a current authenticator code or an unused recovery code.';
        } else {
            TotpService::disable($db, $userId);
            $message = 'Two-factor authentication is off.';
            send_notification_email($account['email'], 'Two-factor authentication disabled', 'Two-factor authentication was turned off',
                'Two-factor authentication was turned off for your CertiVault account. If this was not you, change your password immediately.');
        }
    }
}

$enabled = TotpService::enabledFor($db, $userId);
$remaining = $enabled ? TotpService::remainingRecoveryCodes($db, $userId) : 0;
$page_title = 'Two-factor authentication - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main">
    <div class="container shell-narrow">
        <h2>Two-factor authentication</h2>
        <?php if ($error): ?><div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <?php if ($message): ?><div class="alert alert-success" role="status"><?= htmlspecialchars($message) ?></div><?php endif; ?>

        <?php if ($newCodes): ?>
            <div class="card" id="recoveryCodes">
                <h3 class="card-title">Your recovery codes</h3>
                <p class="text-muted">Each code works once. Store them somewhere safe (a password manager or printed copy).</p>
                <ul class="recovery-codes"><?php foreach ($newCodes as $c): ?><li><code><?= htmlspecialchars($c) ?></code></li><?php endforeach; ?></ul>
            </div>
        <?php endif; ?>

        <?php if ($enabled): ?>
            <div class="card">
                <p><strong class="credential-pass">✓ Two-factor authentication is on.</strong>
                   Signing in needs your password and a code from your authenticator app.</p>
                <p class="text-muted">Unused recovery codes: <strong id="recoveryRemaining"><?= (int)$remaining ?></strong></p>
                <form method="POST" class="form-inline-stack">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                    <input type="hidden" name="action" value="regen">
                    <div class="form-group">
                        <label for="regenCode">Current authenticator code</label>
                        <input type="text" id="regenCode" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" required>
                    </div>
                    <button type="submit" class="btn btn-secondary">Create new recovery codes</button>
                </form>
            </div>
            <form method="POST" class="card" data-confirm="Turn off two-factor authentication?">
                <h3 class="card-title">Turn off</h3>
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <input type="hidden" name="action" value="disable">
                <div class="form-group">
                    <label for="disablePassword">Password</label>
                    <input type="password" id="disablePassword" name="password" autocomplete="current-password" required>
                </div>
                <div class="form-group">
                    <label for="disableCode">Authenticator code or recovery code</label>
                    <input type="text" id="disableCode" name="code" autocomplete="one-time-code" maxlength="12" required>
                </div>
                <button type="submit" class="btn btn-danger">Turn off two-factor authentication</button>
            </form>

        <?php elseif ($setup): ?>
            <div class="card" id="totpSetup">
                <h3 class="card-title">1. Scan this QR code</h3>
                <p class="text-muted">Use Google Authenticator, Microsoft Authenticator, Aegis, 1Password or any TOTP app.</p>
                <p class="text-center"><img src="two_factor_qr.php" width="220" height="220" alt="QR code for your authenticator app" class="totp-qr"></p>
                <p class="text-muted small">Can't scan? Enter this key manually: <code id="totpSecret"><?= htmlspecialchars(trim(chunk_split($setup['secret'], 4, ' '))) ?></code></p>
                <h3 class="card-title">2. Enter the 6-digit code</h3>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                    <input type="hidden" name="action" value="confirm">
                    <div class="form-group">
                        <label for="confirmCode">Code from the app</label>
                        <input type="text" id="confirmCode" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" required autofocus>
                    </div>
                    <button type="submit" class="btn btn-primary btn-block">Turn on two-factor authentication</button>
                </form>
            </div>

        <?php else: ?>
            <div class="card">
                <p>Protect your account with a second step at sign-in: a code from an authenticator app on your phone.
                   <?= $_SESSION['role'] !== 'student' ? '<strong>Strongly recommended for institution and platform administrators.</strong>' : '' ?></p>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                    <input type="hidden" name="action" value="start">
                    <button type="submit" class="btn btn-primary" id="startTotp">Set up two-factor authentication</button>
                </form>
            </div>
        <?php endif; ?>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
