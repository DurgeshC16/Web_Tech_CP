<?php
// src/partials/header.php — shared site header with role-aware nav.
// Requires helpers.php (session, csrf) to already be loaded.
$role = $_SESSION['role'] ?? null;
?>
<a class="skip-link" href="#main">Skip to content</a>
<header class="site-header" role="banner">
    <div class="header-inner">
        <a href="index.php" class="wordmark" aria-label="CertiVault home">
            <svg class="wordmark-seal" width="28" height="28" viewBox="0 0 32 32" aria-hidden="true">
                <circle cx="16" cy="16" r="14" fill="none" stroke="currentColor" stroke-width="2"/>
                <circle cx="16" cy="16" r="9" fill="none" stroke="currentColor" stroke-width="1.5"/>
                <path d="M16 10 L18.2 14.2 L22.5 14.8 L19.2 17.8 L20.2 22 L16 19.6 L11.8 22 L12.8 17.8 L9.5 14.8 L13.8 14.2 Z" fill="currentColor"/>
            </svg>
            <span>CertiVault</span>
        </a>

        <button class="nav-toggle" id="navToggle" aria-expanded="false" aria-controls="primaryNav" aria-label="Toggle navigation">
            <span></span><span></span><span></span>
        </button>

        <nav class="primary-nav" id="primaryNav" aria-label="Primary">
            <?php if (!$role): ?>
                <a href="index.php">Home</a>
                <a href="verify.php">Verify</a>
                <a href="login.php">Login</a>
                <a href="register_student.php">Register</a>
            <?php elseif ($role === 'student'): ?>
                <a href="student_dashboard.php">My Certificates</a>
                <a href="verify.php">Verify</a>
                <a href="change_password.php">Change Password</a>
            <?php elseif ($role === 'admin'): ?>
                <a href="admin_dashboard.php">Dashboard</a>
                <a href="issue_certificate.php">Issue</a>
                <a href="audit_logs.php">Audit Logs</a>
                <a href="change_password.php">Change Password</a>
            <?php elseif ($role === 'super_admin'): ?>
                <a href="super_admin.php">Dashboard</a>
                <a href="change_password.php">Change Password</a>
            <?php endif; ?>

            <?php if ($role): ?>
                <form method="POST" action="logout.php" class="nav-logout">
                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                    <button type="submit" class="btn btn-ghost btn-sm">Logout</button>
                </form>
            <?php endif; ?>

            <button type="button" class="btn btn-ghost btn-sm theme-toggle" id="themeToggle" aria-label="Toggle dark mode">
                <?= current_theme() === 'dark' ? 'Light' : 'Dark' ?>
            </button>
        </nav>
    </div>
</header>
