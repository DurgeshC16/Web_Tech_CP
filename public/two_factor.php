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
<main id="main" class="tfa-page">
    <div class="container shell-wide">
        <div class="page-head tfa-head">
            <div class="tfa-head-title">
                <span class="auth-icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>
                </span>
                <div>
                    <h1>Two-factor authentication</h1>
                    <p class="page-head-sub">A second step at sign-in: a code from an authenticator app on your phone.</p>
                </div>
            </div>
            <div class="page-head-actions">
                <?php if ($enabled): ?>
                    <span class="badge-status badge-valid">On</span>
                <?php elseif ($setup): ?>
                    <span class="badge-status badge-pending">Setup in progress</span>
                <?php else: ?>
                    <span class="badge-status badge-invalid">Off</span>
                <?php endif; ?>
            </div>
        </div>
        <?php if ($error): ?><div class="alert alert-danger" role="alert"><?= htmlspecialchars($error) ?></div><?php endif; ?>
        <?php if ($message): ?><div class="alert alert-success" role="status"><?= htmlspecialchars($message) ?></div><?php endif; ?>

        <div class="dashboard-grid tfa-grid">
            <div class="stack tfa-main">
        <?php if ($newCodes): ?>
            <section class="card card-gradient tfa-codes" id="recoveryCodes" aria-labelledby="recoveryCodesTitle">
                <div class="card-head">
                    <h2 class="card-title" id="recoveryCodesTitle">Your recovery codes</h2>
                    <span class="badge-status badge-warn">Shown once</span>
                </div>
                <p class="text-muted">Each code works once. Store them somewhere safe (a password manager or printed copy).</p>
                <ul class="recovery-codes"><?php foreach ($newCodes as $c): ?><li><code><?= htmlspecialchars($c) ?></code></li><?php endforeach; ?></ul>
                <div class="card-actions tfa-codes-actions">
                    <button type="button" class="btn btn-primary" data-copy="<?= htmlspecialchars(implode("\n", $newCodes)) ?>" data-copy-message="Recovery codes copied">
                        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
                        Copy all codes
                    </button>
                    <button type="button" class="btn btn-secondary" data-print>
                        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M6 9V3h12v6"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M6 14h12v7H6z"/></svg>
                        Print codes
                    </button>
                    <span class="tfa-print-hint text-muted text-sm">Printing prints only these codes.</span>
                </div>
            </section>
        <?php endif; ?>

        <?php if ($enabled): ?>
            <section class="card card-accent-valid tfa-status" aria-labelledby="tfaStatusTitle">
                <div class="tfa-status-row">
                    <span class="tfa-status-icon" aria-hidden="true">
                        <svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M5 13l4 4L19 7"/></svg>
                    </span>
                    <div>
                        <h2 class="card-title" id="tfaStatusTitle">Two-factor authentication is on.</h2>
                        <p class="mb-0">Signing in needs your password and a code from your authenticator app.</p>
                    </div>
                </div>
                <div class="tfa-remaining">
                    <div class="tfa-remaining-label">
                        <span>Unused recovery codes</span>
                        <span><strong id="recoveryRemaining"><?= (int)$remaining ?></strong> <span class="text-muted">of 10</span></span>
                    </div>
                    <meter class="tfa-meter" min="0" max="10" low="3" optimum="10" value="<?= (int)$remaining ?>" aria-label="Unused recovery codes"><?= (int)$remaining ?> of 10</meter>
                </div>
                <form method="POST" class="form-inline-stack tfa-regen">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                    <input type="hidden" name="action" value="regen">
                    <div class="form-group">
                        <label for="regenCode">Current authenticator code</label>
                        <input type="text" id="regenCode" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" required class="code-input code-input-sm">
                    </div>
                    <button type="submit" class="btn btn-secondary">Create new recovery codes</button>
                </form>
            </section>
            <form method="POST" class="card card-accent-danger tfa-danger" data-confirm="Turn off two-factor authentication?">
                <h2 class="card-title">Turn off</h2>
                <p class="text-muted text-sm">You will need your password and an authenticator or recovery code. Your account will then be protected by your password only.</p>
                <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                <input type="hidden" name="action" value="disable">
                <div class="form-row">
                    <div class="form-group">
                        <label for="disablePassword">Password</label>
                        <input type="password" id="disablePassword" name="password" autocomplete="current-password" required>
                    </div>
                    <div class="form-group">
                        <label for="disableCode">Authenticator code or recovery code</label>
                        <input type="text" id="disableCode" name="code" autocomplete="one-time-code" maxlength="12" required>
                    </div>
                </div>
                <div>
                    <button type="submit" class="btn btn-danger">Turn off two-factor authentication</button>
                </div>
            </form>

        <?php elseif ($setup): ?>
            <section class="card tfa-setup" id="totpSetup" aria-label="Set up your authenticator app">
                <div class="tfa-setup-grid">
                    <div class="tfa-setup-step">
                        <h2 class="card-title"><span class="tfa-step-num" aria-hidden="true">1</span> Scan this QR code</h2>
                        <p class="text-muted">Use Google Authenticator, Microsoft Authenticator, Aegis, 1Password or any TOTP app.</p>
                        <div class="tfa-qr-frame" data-tilt>
                            <img src="two_factor_qr.php" width="220" height="220" alt="QR code for your authenticator app" class="totp-qr">
                        </div>
                        <p class="text-muted text-sm mb-2">Can't scan? Enter this key manually:</p>
                        <div class="tfa-key">
                            <code id="totpSecret"><?= htmlspecialchars(trim(chunk_split($setup['secret'], 4, ' '))) ?></code>
                            <button type="button" class="btn btn-secondary btn-sm" data-copy-target="totpSecret" data-copy-message="Setup key copied">
                                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
                                Copy key
                            </button>
                        </div>
                    </div>
                    <div class="tfa-setup-step">
                        <h2 class="card-title"><span class="tfa-step-num" aria-hidden="true">2</span> Enter the 6-digit code</h2>
                        <p class="text-muted">Your app now shows a CertiVault entry with a code that changes every 30 seconds.</p>
                        <form method="POST" data-loading>
                            <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                            <input type="hidden" name="action" value="confirm">
                            <div class="form-group">
                                <label for="confirmCode">Code from the app</label>
                                <input type="text" id="confirmCode" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" required autofocus class="code-input">
                            </div>
                            <button type="submit" class="btn btn-primary btn-block">Turn on two-factor authentication</button>
                        </form>
                    </div>
                </div>
            </section>

        <?php else: ?>
            <section class="card tfa-intro" aria-labelledby="tfaIntroTitle">
                <h2 class="card-title" id="tfaIntroTitle">Add a second lock to your account</h2>
                <p>Protect your account with a second step at sign-in: a code from an authenticator app on your phone.
                   <?= $_SESSION['role'] !== 'student' ? '<strong>Strongly recommended for institution and platform administrators.</strong>' : '' ?></p>
                <ul class="tfa-benefits">
                    <li><span class="tfa-benefit-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><path d="M12 3l8 3v6c0 5-3.4 8.6-8 10-4.6-1.4-8-5-8-10V6z"/></svg></span>Blocks sign-in with a stolen password</li>
                    <li><span class="tfa-benefit-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span>Takes about a minute to set up</li>
                    <li><span class="tfa-benefit-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" focusable="false"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2"/></svg></span>10 single-use recovery codes as a backup</li>
                </ul>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                    <input type="hidden" name="action" value="start">
                    <button type="submit" class="btn btn-primary btn-lg" id="startTotp">Set up two-factor authentication</button>
                </form>
            </section>
        <?php endif; ?>
            </div>

            <aside class="card tfa-aside" aria-labelledby="tfaAsideTitle">
                <h2 class="card-title" id="tfaAsideTitle">How it works</h2>
                <ol class="tfa-how">
                    <li><strong>Install an app</strong> such as Google Authenticator, Microsoft Authenticator, Aegis or 1Password.</li>
                    <li><strong>Scan the QR code</strong> we show you, then type the 6-digit code to confirm.</li>
                    <li><strong>Keep your recovery codes</strong> safe &mdash; each one signs you in once if you lose your phone.</li>
                </ol>
                <p class="text-muted text-sm mb-0">Turning two-factor authentication on or off sends a notification to your email address.</p>
            </aside>
        </div>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
</body>
</html>
