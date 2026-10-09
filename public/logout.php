<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';

// Logout is POST + CSRF only. A plain GET just redirects — it must
// never terminate the session (e.g. via a prefetched link).
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    redirect('login.php');
}

validate_csrf_token($_POST['csrf_token'] ?? '');

// Revokes the remember-me token (DB row + cookie), clears $_SESSION,
// expires the session cookie, and destroys the session.
destroy_session(Database::getInstance());
redirect('login.php');
