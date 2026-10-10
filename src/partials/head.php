<?php
// src/partials/head.php — shared <head> for every page.
// Caller sets $page_title (string) before including.
// Requires helpers.php (session, csrf, security headers) to already be loaded.
send_security_headers();
$page_title = $page_title ?? 'CertiVault';
?>
<!DOCTYPE html>
<html lang="en" data-theme="<?= htmlspecialchars(current_theme()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($page_title) ?></title>
    <link rel="stylesheet" href="assets/css/style.css">
    <?php require __DIR__ . '/head_fonts.php'; ?>
    <script src="assets/js/theme.js"></script>
</head>
<body>
