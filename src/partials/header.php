<?php
// src/partials/header.php — shared site header with role-aware nav.
// Requires helpers.php (session, csrf) to already be loaded.
//
// Hooks kept for JS/tests: #navToggle (aria-expanded, aria-controls),
// #primaryNav (.open toggled by theme.js), #themeToggle (theme.js),
// the POST logout form with its CSRF token.
// Variables are prefixed $cv_hdr_ because this file runs in page scope.
$role = $_SESSION['role'] ?? null;
$cv_hdr_current = basename((string)($_SERVER['SCRIPT_NAME'] ?? ''));
$cv_hdr_link = static function (string $href, string $label) use ($cv_hdr_current): string {
    $active = $href === $cv_hdr_current;
    return '<a href="' . htmlspecialchars($href) . '"'
        . ($active ? ' class="is-active" aria-current="page"' : '')
        . '>' . htmlspecialchars($label) . '</a>';
};
// Account links (password, 2FA) sit next to Logout as icon buttons on wide
// screens (label kept as visually-hidden text + title) and as full text
// rows inside the mobile drawer.
$cv_hdr_icon_link = static function (string $href, string $label, string $paths) use ($cv_hdr_current): string {
    $active = $href === $cv_hdr_current;
    return '<a href="' . htmlspecialchars($href) . '" class="nav-icon-link' . ($active ? ' is-active' : '') . '"'
        . ($active ? ' aria-current="page"' : '') . ' title="' . htmlspecialchars($label) . '">'
        . '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' . $paths . '</svg>'
        . '<span class="nav-icon-label">' . htmlspecialchars($label) . '</span></a>';
};
$cv_hdr_role_labels = ['student' => 'Student', 'admin' => 'Institution admin', 'super_admin' => 'Super admin'];
$cv_hdr_dark = current_theme() === 'dark';
?>
<a class="skip-link" href="#main">Skip to content</a>
<header class="site-header<?= $role === 'admin' ? ' is-dense' : ($role === 'student' ? ' is-mid' : '') ?>" id="siteHeader" role="banner">
    <div class="header-inner">
        <a href="index.php" class="wordmark" aria-label="CertiVault home">
            <svg class="wordmark-seal" width="34" height="34" viewBox="0 0 64 64" aria-hidden="true" focusable="false">
                <defs>
                    <linearGradient id="cvLogoGrad" x1="0" y1="0" x2="1" y2="1">
                        <stop offset="0" stop-color="#4f46e5"/>
                        <stop offset=".55" stop-color="#7c3aed"/>
                        <stop offset="1" stop-color="#0891b2"/>
                    </linearGradient>
                </defs>
                <rect width="64" height="64" rx="16" fill="url(#cvLogoGrad)"/>
                <path d="M32 12l16 6v12c0 10.5-6.8 18.6-16 22-9.2-3.4-16-11.5-16-22V18z" fill="none" stroke="#fff" stroke-width="3.5" stroke-linejoin="round"/>
                <path d="M24.5 32.5l5.5 5.5 10-11" fill="none" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
            <span class="wordmark-text">CertiVault</span>
        </a>

        <nav class="primary-nav" id="primaryNav" aria-label="Primary">
            <?php if (!$role): ?>
                <?= $cv_hdr_link('index.php', 'Home') ?>
                <?= $cv_hdr_link('verify.php', 'Verify') ?>
                <?= $cv_hdr_link('offline_verify.php', 'Check a credential file') ?>
                <?= $cv_hdr_link('login.php', 'Login') ?>
                <?= $cv_hdr_link('register_student.php', 'Register') ?>
            <?php elseif ($role === 'student'): ?>
                <?= $cv_hdr_link('student_dashboard.php', 'My Certificates') ?>
                <?php if (defined('ATTESTED_EXTERNAL_CREDENTIALS_ENABLED') && ATTESTED_EXTERNAL_CREDENTIALS_ENABLED): ?><?= $cv_hdr_link('external_credentials.php', 'External credentials') ?><?php endif; ?>
                <?= $cv_hdr_link('verify.php', 'Verify') ?>
            <?php elseif ($role === 'admin'): ?>
                <?= $cv_hdr_link('admin_dashboard.php', 'Dashboard') ?>
                <?php if (defined('ATTESTED_EXTERNAL_CREDENTIALS_ENABLED') && ATTESTED_EXTERNAL_CREDENTIALS_ENABLED): ?><?= $cv_hdr_link('attest_external_credentials.php', 'Attestation queue') ?><?php endif; ?>
                <?= $cv_hdr_link('issue_certificate.php', 'Issue') ?>
                <?= $cv_hdr_link('bulk_issue.php', 'Bulk issue') ?>
                <?= $cv_hdr_link('audit_logs.php', 'Audit Logs') ?>
                <?= $cv_hdr_link('analytics.php', 'Analytics') ?>
            <?php elseif ($role === 'super_admin'): ?>
                <?= $cv_hdr_link('super_admin.php', 'Dashboard') ?>
            <?php endif; ?>

            <?php if (defined('CERTIFICATE_TRANSPARENCY_ENABLED') && CERTIFICATE_TRANSPARENCY_ENABLED): ?><?= $cv_hdr_link('institutions.php', 'Institution keys') ?><?php endif; ?>

            <?php if ($role): ?>
                <div class="nav-account">
                    <span class="role-chip" title="Signed in"><span class="role-chip-dot" aria-hidden="true"></span><?= htmlspecialchars($cv_hdr_role_labels[$role] ?? ucfirst(str_replace('_', ' ', (string)$role))) ?></span>
                    <?= $cv_hdr_icon_link('change_password.php', 'Change Password', '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/><path d="M12 15v2"/>') ?>
                    <?= $cv_hdr_icon_link('two_factor.php', 'Two-factor auth', '<path d="M12 3l8 3v6c0 4.6-3.3 8.4-8 9.5-4.7-1.1-8-4.9-8-9.5V6z"/><path d="M9 12l2 2 4-4"/>') ?>
                    <form method="POST" action="logout.php" class="nav-logout">
                        <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                        <button type="submit" class="btn btn-ghost btn-sm">Logout</button>
                    </form>
                </div>
            <?php endif; ?>
        </nav>

        <div class="header-actions">
            <button type="button" class="btn btn-ghost btn-sm theme-toggle" id="themeToggle"
                    aria-label="<?= $cv_hdr_dark ? 'Switch to light theme' : 'Switch to dark theme' ?>"
                    aria-pressed="<?= $cv_hdr_dark ? 'true' : 'false' ?>"
                    title="<?= $cv_hdr_dark ? 'Switch to light theme' : 'Switch to dark theme' ?>">
                <svg class="icon-moon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>
                <svg class="icon-sun" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><g fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4.5"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></g></svg>
            </button>
            <button class="nav-toggle" id="navToggle" type="button" aria-expanded="false" aria-controls="primaryNav" aria-label="Toggle navigation">
                <span></span><span></span><span></span>
            </button>
        </div>
    </div>
</header>
