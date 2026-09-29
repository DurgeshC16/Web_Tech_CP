<?php
// src/utils/helpers.php
// ─────────────────────────────────────────────────────────────────────
// Session, CSRF, sanitization, role-check middleware
// ─────────────────────────────────────────────────────────────────────

// ── Secure Session Configuration ────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', '1');     // JS cannot read the cookie
    ini_set('session.cookie_samesite', 'Strict'); // Mitigate CSRF via cookie scope
    ini_set('session.use_strict_mode', '1');      // Reject uninitialized session IDs
    // If served over HTTPS, also mark cookie as Secure
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        ini_set('session.cookie_secure', '1');
    }
    session_start();
}

/**
 * Generate a CSRF token if one doesn't exist.
 */
function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Validate CSRF token from POST request.
 * Uses hash_equals() to prevent timing attacks.
 */
function validate_csrf_token($token) {
    if (empty($token) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        http_response_code(403);
        die('<div style="font-family:sans-serif;padding:40px;text-align:center;"><h2>403 — Forbidden</h2><p>CSRF token validation failed. Please go back and try again.</p></div>');
    }
}

/**
 * Sanitize input data.
 */
function sanitize_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

/**
 * Redirect to a specific URL and terminate.
 */
function redirect($url) {
    header("Location: " . $url);
    exit();
}

/**
 * Require a specific role to access a page.
 * If not logged in, redirect to login.
 * If wrong role, redirect to their respective dashboard.
 */
function require_role($required_role) {
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['role'])) {
        redirect('login.php');
    }

    $current_role = $_SESSION['role'];
    
    // If it's an array of roles (e.g. ['admin', 'super_admin'])
    if (is_array($required_role)) {
        if (!in_array($current_role, $required_role)) {
            redirect_to_dashboard($current_role);
        }
    } else {
        if ($current_role !== $required_role) {
            redirect_to_dashboard($current_role);
        }
    }
}

function redirect_to_dashboard($role) {
    if ($role === 'admin') {
        redirect('admin_dashboard.php');
    } elseif ($role === 'student') {
        redirect('student_dashboard.php');
    } elseif ($role === 'super_admin') {
        redirect('super_admin.php');
    } else {
        redirect('login.php');
    }
}

/**
 * Render a user-friendly error page without leaking internals.
 */
function show_error_page($title, $message) {
    http_response_code(500);
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Error - CertiVault</title><link rel="stylesheet" href="assets/css/style.css"></head><body>';
    echo '<div class="container" style="max-width:500px;text-align:center;margin-top:60px;">';
    echo '<h2>' . htmlspecialchars($title) . '</h2>';
    echo '<p>' . htmlspecialchars($message) . '</p>';
    echo '<a href="login.php" class="btn">Go to Login</a>';
    echo '</div></body></html>';
    exit();
}
