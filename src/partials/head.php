<?php
// src/partials/head.php — shared <head> for every page.
// Caller sets $page_title (string) before including; optionally
// $body_class (string, extra classes for <body>).
// Requires helpers.php (session, csrf, security headers) to already be loaded.
//
// Stylesheets (order matters): design system style.css -> components.css ->
// features.css, then the four small page stylesheets. Keep every static
// asset under ~56 KB: PHP's built-in server (php -S, used by the test
// suites) intermittently stalls on larger static files.
send_security_headers();
$page_title = $page_title ?? 'CertiVault';
// <body class="page-<script-name>"> lets the page stylesheets scope rules,
// e.g. body.page-admin-dashboard. Derived from the script name only.
$cv_page_slug = str_replace('_', '-', strtolower(basename((string)($_SERVER['SCRIPT_NAME'] ?? 'index.php'), '.php')));
$cv_page_slug = preg_replace('/[^a-z0-9-]/', '', $cv_page_slug) ?: 'index';
$cv_body_class = trim('page-' . $cv_page_slug . ' ' . (isset($body_class) ? (string)$body_class : ''));
?>
<!DOCTYPE html>
<html lang="en" data-theme="<?= htmlspecialchars(current_theme()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="CertiVault — issue tamper-evident, digitally signed certificates and verify them instantly with a QR code or certificate ID.">
    <meta name="theme-color" content="<?= current_theme() === 'dark' ? '#0a0f1e' : '#4f46e5' ?>">
    <title><?= htmlspecialchars($page_title) ?></title>
    <link rel="icon" href="assets/img/favicon.svg" type="image/svg+xml">
    <?php require __DIR__ . '/head_fonts.php'; ?>
    <link rel="stylesheet" href="assets/css/style.css">
    <link rel="stylesheet" href="assets/css/components.css">
    <link rel="stylesheet" href="assets/css/features.css">
    <link rel="stylesheet" href="assets/css/pages/auth.css">
    <link rel="stylesheet" href="assets/css/pages/verify.css">
    <link rel="stylesheet" href="assets/css/pages/student.css">
    <link rel="stylesheet" href="assets/css/pages/admin.css">
    <script src="assets/js/theme.js"></script>
    <script src="assets/js/ui.js" defer></script>
</head>
<body class="<?= htmlspecialchars($cv_body_class) ?>">
