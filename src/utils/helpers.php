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
    // Remove null bytes and control characters (except tab/newline/carriage return).
    // NOTE: no htmlspecialchars() here — output-time escaping is handled at
    // every render point. Encoding at input time caused double-escaping
    // (e.g. "O'Brien" stored as "O&#039;Brien", then rendered as "O&amp;#039;Brien").
    $data = str_replace("\0", '', $data);
    $data = preg_replace('/[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $data);
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
 * Generate a new arithmetic CAPTCHA and store the expected answer
 * in the session. Call once per page render (GET or after a POST).
 */
function generate_captcha() {
    $a = random_int(1, 9);
    $b = random_int(1, 9);
    $_SESSION['captcha_answer'] = $a + $b;
    $_SESSION['captcha_question'] = 'What is ' . $a . ' + ' . $b . '?';
}

/**
 * Verify the submitted CAPTCHA answer. The session value is unset after
 * one attempt (pass or fail) so it cannot be replayed.
 *
 * To swap in Google reCAPTCHA later, you only need to change:
 *   1) Config: add your reCAPTCHA site key + secret key constants here,
 *   2) Client: in each form add <script src="https://www.google.com/recaptcha/api.js" async defer></script>
 *      and <div class="g-recaptcha" data-sitekey="YOUR_SITE_KEY"></div>,
 *   3) Server: replace this function body with a POST of the secret key and
 *      $_POST['g-recaptcha-response'] to https://www.google.com/recaptcha/api/siteverify,
 *      returning true only when the JSON response has "success": true.
 */
function verify_captcha() {
    $expected = $_SESSION['captcha_answer'] ?? null;
    unset($_SESSION['captcha_answer'], $_SESSION['captcha_question']);
    $submitted = $_POST['captcha_answer'] ?? null;
    return $expected !== null && $submitted !== null && ctype_digit(trim((string)$submitted)) && (int)$submitted === $expected;
}

/**
 * Build a PHPMailer instance pre-configured with the application's SMTP
 * settings.  Both create_otp() and scripts/test_smtp.php use this so
 * the connection parameters are defined in exactly one place.
 *
 * @return \PHPMailer\PHPMailer\PHPMailer  Ready-to-use mailer (caller still
 *                                         needs to set From, addAddress, etc.)
 */
function create_smtp_mailer() {
    require_once __DIR__ . '/PHPMailer/Exception.php';
    require_once __DIR__ . '/PHPMailer/SMTP.php';
    require_once __DIR__ . '/PHPMailer/PHPMailer.php';

    $mail = new \PHPMailer\PHPMailer\PHPMailer(true);
    $mail->isSMTP();
    $mail->Host       = SMTP_HOST;
    $mail->SMTPAuth   = true;
    $mail->Username   = SMTP_USERNAME;
    $mail->Password   = SMTP_PASSWORD;
    $mail->SMTPSecure = SMTP_ENCRYPTION; // 'tls' or 'ssl'
    $mail->Port       = SMTP_PORT;

    return $mail;
}

/**
 * Create a fresh one-time code for a user. Any previous unused codes for the
 * same user+purpose are invalidated first. A 6-digit code is stored with a
 * 15-minute expiry.
 */
function create_otp($db, $user_id, $purpose = 'activation') {
    global $is_production;

    $stmt = $db->prepare('UPDATE otp_codes SET used = 1 WHERE user_id = :uid AND purpose = :p AND used = 0');
    $stmt->execute(['uid' => $user_id, 'p' => $purpose]);

    $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $expires = date('Y-m-d H:i:s', time() + 900); // 15 minutes
    $stmt = $db->prepare('INSERT INTO otp_codes (user_id, otp_code, purpose, expires_at) VALUES (:uid, :code, :p, :exp)');
    $stmt->execute(['uid' => $user_id, 'code' => $code, 'p' => $purpose, 'exp' => $expires]);

    // Best-effort email delivery via PHPMailer over SMTP. In a local XAMPP/demo
    // environment SMTP may not be configured, so we deliberately do NOT block
    // the user flow on delivery — the code is still usable (see dev fallback).
    $stmt = $db->prepare('SELECT email FROM users WHERE id = :id');
    $stmt->execute(['id' => $user_id]);
    $user_email = $stmt->fetchColumn();

    $email_sent = false;
    $email_error = null;
    if ($user_email) {
        try {
            $mail = create_smtp_mailer();

            $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
            $mail->addAddress($user_email);
            $mail->Subject = 'CertiVault Verification Code';
            $mail->Body    = "Your CertiVault verification code is: $code\nThis code expires in 15 minutes.";
            $mail->isHTML(false); // plain-text message

            $email_sent = $mail->send();
        } catch (\Throwable $e) {
            error_log('CertiVault OTP email failed for user_id ' . $user_id . ': ' . $e->getMessage());
            $email_sent = false;
            $email_error = $e->getMessage();
        }
    }

    // DEV/DEMO TRADE-OFF (an informed decision, not an oversight): because a
    // 2-week local deadline means SMTP may never be configured, we also show
    // the code directly on the confirmation screen. This is STRICTLY guarded
    // by $is_production (CV_ENV=production) and never appears in production.
    if (!$is_production) {
        if ($email_sent) {
            $_SESSION['dev_otp_display'] = "Verification code sent to your email. (Dev mode, also shown here: $code)";
        } elseif ($email_error !== null) {
            // Dev-only: surface the real PHPMailer error so SMTP misconfiguration
            // is visible on screen without digging through php_errors.log.
            $_SESSION['dev_otp_display'] = "Could not send email (code: $code) — error: " . $email_error;
        } else {
            $_SESSION['dev_otp_display'] = "Could not send email — dev mode fallback code: $code";
        }
    }

    return $code;
}

/**
 * Validate password strength (length range).
 *
 * PASSWORD_BCRYPT silently truncates input beyond 72 bytes, so anything
 * longer provides no additional security. We enforce an 8–72 character
 * window and return a human-readable error string on failure, or true
 * on success.
 *
 * @param  string      $password  The raw password to validate.
 * @return true|string            True when valid; error message string otherwise.
 */
function validate_password_strength($password) {
    $len = strlen($password);
    if ($len < 8) {
        return 'Password must be at least 8 characters long.';
    }
    if ($len > 72) {
        return 'Password must not exceed 72 characters (bcrypt silently truncates longer input, so extra characters add no security).';
    }
    return true;
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
