<?php
require_once __DIR__ . '/../src/utils/helpers.php';

// Logout is POST + CSRF only. A plain GET just redirects — it must
// never terminate the session (e.g. via a prefetched link).
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect('login.php');
}

validate_csrf_token($_POST['csrf_token'] ?? '');

destroy_session();
redirect('login.php');
