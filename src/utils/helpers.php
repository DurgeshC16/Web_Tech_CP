<?php
// src/utils/helpers.php
// ─────────────────────────────────────────────────────────────────────
// Session, CSRF, sanitization, role-check middleware
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/validators.php';

// ── Session lifetime policy ─────────────────────────────────────────
const SESSION_IDLE_TIMEOUT = 1800;    // 30 minutes of inactivity
const SESSION_ABSOLUTE_LIFETIME = 28800; // 8 hours total

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
        $page_title = '403 Forbidden - CertiVault';
        require __DIR__ . '/../partials/head.php';
        require __DIR__ . '/../partials/header.php';
        echo '<main id="main"><div class="container shell-narrow"><h2>403 — Forbidden</h2><p>CSRF token validation failed. Please go back and try again.</p></div></main>';
        require __DIR__ . '/../partials/footer.php';
        echo '</body></html>';
        exit();
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
 * Enforce idle + absolute session lifetimes. Called from require_role().
 * On expiry the session is destroyed and the user is sent to login.
 */
function check_session_expiry() {
    if (!isset($_SESSION['user_id'])) {
        return;
    }
    $now = time();
    $last = $_SESSION['last_activity'] ?? 0;
    $started = $_SESSION['login_time'] ?? 0;

    if (($last && ($now - $last) > SESSION_IDLE_TIMEOUT) || ($started && ($now - $started) > SESSION_ABSOLUTE_LIFETIME)) {
        destroy_session();
        redirect('login.php?expired=1');
    }
    $_SESSION['last_activity'] = $now;
}

/**
 * Send no-store cache headers so authenticated pages are not shown
 * from the browser cache (Back button) after logout.
 */
function send_no_store_headers() {
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
}

/**
 * Fully terminate the current session: clear array, expire cookie, destroy.
 */
function destroy_session() {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
}

/**
 * Read the theme preference cookie. Defaults to 'light'; anything
 * other than light/dark is ignored (defense against cookie tampering).
 */
function current_theme() {
    $t = $_COOKIE['cv_theme'] ?? 'light';
    return $t === 'dark' ? 'dark' : 'light';
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

    // Idle / absolute lifetime enforcement + no-store on auth pages
    check_session_expiry();
    send_no_store_headers();

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
 * Require the current user to be an approved institution admin.
 * An institution rejected/unapproved after login loses access
 * immediately: the session is destroyed and they are sent to login.
 */
function require_approved_institution() {
    if (!isset($_SESSION['user_id'])) {
        redirect('login.php');
    }
    // Always call with a DB connection available.
    $db = Database::getInstance();
    $stmt = $db->prepare('SELECT status FROM institutions WHERE user_id = :uid LIMIT 1');
    $stmt->execute(['uid' => $_SESSION['user_id']]);
    $status = $stmt->fetchColumn();

    if ($status !== 'approved') {
        destroy_session();
        redirect('login.php?denied=1');
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
    $mail->Timeout    = 10;              // seconds
    $mail->SMTPDebug  = 0;               // no debug output
    $mail->CharSet    = 'UTF-8';

    return $mail;
}

/**
 * Mask an email address for safe display (e.g. "d****@gmail.com").
 *
 * @param  string $email  Full email address.
 * @return string          Masked email.
 */
function mask_email($email) {
    $parts = explode('@', $email, 2);
    $local = $parts[0];
    $domain = $parts[1] ?? '';
    if (strlen($local) <= 1) {
        $masked_local = $local . '****';
    } else {
        $masked_local = $local[0] . str_repeat('*', max(4, strlen($local) - 1));
    }
    return $masked_local . '@' . $domain;
}

/**
 * HMAC a 6-digit OTP code using the application pepper.
 *
 * @param  string $code  The raw 6-digit code.
 * @return string        64-char hex HMAC-SHA256.
 */
function hash_otp($code) {
    return hash_hmac('sha256', $code, OTP_PEPPER);
}

/**
 * Create a fresh one-time code for a user and deliver it by email.
 *
 * Any previous unused codes for the same user+purpose are invalidated first.
 * A 6-digit code is generated, HMAC-hashed before storage, and sent via email.
 *
 * Rate limits:
 *   - 60-second resend cooldown per user+purpose.
 *   - Max 5 codes per user per hour (across all purposes).
 *
 * The plaintext code is NEVER returned, stored in the session, logged, or
 * displayed anywhere except the email body.
 *
 * @param  PDO         $db            Database connection.
 * @param  int         $user_id       Target user ID.
 * @param  string      $purpose       OTP purpose ('activation', 'password_reset', 'password_change').
 * @param  string|null $activate_url  Optional activation page URL to include in the email.
 * @return string                     'sent' | 'cooldown' | 'limit' | 'mail_failed'
 */
function create_otp($db, $user_id, $purpose = 'activation', $activate_url = null) {
    // ── 60-second resend cooldown ──────────────────────────────────
    $stmt = $db->prepare(
        'SELECT created_at FROM otp_codes WHERE user_id = :uid AND purpose = :p ORDER BY id DESC LIMIT 1'
    );
    $stmt->execute(['uid' => $user_id, 'p' => $purpose]);
    $last = $stmt->fetchColumn();
    if ($last && (time() - strtotime($last)) < 60) {
        return 'cooldown';
    }

    // ── Max 5 codes per user per hour ──────────────────────────────
    $stmt = $db->prepare(
        'SELECT COUNT(*) FROM otp_codes WHERE user_id = :uid AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)'
    );
    $stmt->execute(['uid' => $user_id]);
    if ((int)$stmt->fetchColumn() >= 5) {
        return 'limit';
    }

    // ── Invalidate previous unused codes for this user+purpose ─────
    $stmt = $db->prepare('UPDATE otp_codes SET used = 1 WHERE user_id = :uid AND purpose = :p AND used = 0');
    $stmt->execute(['uid' => $user_id, 'p' => $purpose]);

    // ── Generate and store the HMAC-hashed code ────────────────────
    $code = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    $hashed = hash_otp($code);
    $expires = date('Y-m-d H:i:s', time() + 900); // 15 minutes
    $stmt = $db->prepare(
        'INSERT INTO otp_codes (user_id, otp_code, purpose, expires_at) VALUES (:uid, :code, :p, :exp)'
    );
    $stmt->execute(['uid' => $user_id, 'code' => $hashed, 'p' => $purpose, 'exp' => $expires]);

    // ── Fetch the recipient email ──────────────────────────────────
    $stmt = $db->prepare('SELECT email FROM users WHERE id = :id');
    $stmt->execute(['id' => $user_id]);
    $user_email = $stmt->fetchColumn();

    if (!$user_email) {
        error_log('CertiVault OTP: no email found for user_id ' . $user_id);
        $db->prepare('UPDATE otp_codes SET used = 1 WHERE user_id = :uid AND purpose = :p AND otp_code = :code')
           ->execute(['uid' => $user_id, 'p' => $purpose, 'code' => $hashed]);
        return 'mail_failed';
    }

    // ── Send the email ─────────────────────────────────────────────
    try {
        $mail = create_smtp_mailer();

        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        $mail->addAddress($user_email);
        $mail->Subject = 'Your CertiVault verification code';
        $mail->isHTML(true);

        // Build optional activation-link block
        $link_html = '';
        $link_text = '';
        if ($activate_url) {
            $safe_url = htmlspecialchars($activate_url, ENT_QUOTES, 'UTF-8');
            $link_html = '<p style="margin-top:16px;"><a href="' . $safe_url . '" style="display:inline-block;padding:10px 24px;background:#2563eb;color:#fff;text-decoration:none;border-radius:5px;font-size:14px;">Activate your account</a></p>';
            $link_text = "\nActivate your account here: $activate_url\n";
        }

        // HTML body
        $mail->Body = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"></head><body style="font-family:Arial,Helvetica,sans-serif;background:#f4f4f4;padding:20px;">'
            . '<div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:8px;padding:30px;text-align:center;">'
            . '<h2 style="color:#333;margin-bottom:10px;">CertiVault Verification Code</h2>'
            . '<p style="color:#555;font-size:16px;">Use the code below to verify your account:</p>'
            . '<div style="font-size:36px;font-weight:bold;letter-spacing:8px;color:#2563eb;margin:24px 0;">' . htmlspecialchars($code) . '</div>'
            . '<p style="color:#888;font-size:14px;">This code expires in <strong>15 minutes</strong>.</p>'
            . $link_html
            . '<hr style="border:none;border-top:1px solid #eee;margin:24px 0;">'
            . '<p style="color:#aaa;font-size:12px;">If you didn\'t request this, please ignore this email.</p>'
            . '</div></body></html>';

        // Plain-text alternative
        $mail->AltBody = "Your CertiVault verification code is: $code\n\n"
            . "This code expires in 15 minutes.\n"
            . $link_text . "\n"
            . "If you didn't request this, please ignore this email.";

        $mail->send();
        return 'sent';
    } catch (\Throwable $e) {
        error_log('CertiVault OTP email failed for user_id ' . $user_id . ': ' . $e->getMessage());
        $db->prepare('UPDATE otp_codes SET used = 1 WHERE user_id = :uid AND purpose = :p AND otp_code = :code')
           ->execute(['uid' => $user_id, 'p' => $purpose, 'code' => $hashed]);
        return 'mail_failed';
    }
}

/**
 * Verify a 6-digit OTP code submitted by the user.
 *
 * Uses constant-time comparison (hash_equals on the HMAC).
 * Tracks wrong attempts: after 5 failures the code is invalidated.
 *
 * @param  PDO    $db       Database connection.
 * @param  int    $user_id  Target user ID.
 * @param  string $purpose  OTP purpose.
 * @param  string $code     The raw 6-digit code submitted by the user.
 * @return string           'ok' | 'invalid' | 'expired' | 'locked' | 'none'
 */
function verify_otp($db, $user_id, $purpose, $code) {
    // Basic format check
    if (!preg_match('/^\d{6}$/', $code)) {
        return 'invalid';
    }

    // Fetch the latest unused code for this user+purpose
    $stmt = $db->prepare(
        'SELECT id, otp_code, expires_at, attempts FROM otp_codes '
        . 'WHERE user_id = :uid AND purpose = :p AND used = 0 ORDER BY id DESC LIMIT 1'
    );
    $stmt->execute(['uid' => $user_id, 'p' => $purpose]);
    $otp = $stmt->fetch();

    if (!$otp) {
        return 'none';
    }

    // Expiry check
    if (strtotime($otp['expires_at']) < time()) {
        $db->prepare('UPDATE otp_codes SET used = 1 WHERE id = :id')->execute(['id' => $otp['id']]);
        return 'expired';
    }

    // Max attempts check (already at 5 = locked)
    if ((int)$otp['attempts'] >= 5) {
        $db->prepare('UPDATE otp_codes SET used = 1 WHERE id = :id')->execute(['id' => $otp['id']]);
        return 'locked';
    }

    // Constant-time comparison via HMAC
    $submitted_hash = hash_otp($code);
    if (hash_equals($otp['otp_code'], $submitted_hash)) {
        // Success — mark as used
        $db->prepare('UPDATE otp_codes SET used = 1 WHERE id = :id')->execute(['id' => $otp['id']]);
        return 'ok';
    }

    // Wrong code — increment attempts
    $new_attempts = (int)$otp['attempts'] + 1;
    if ($new_attempts >= 5) {
        // Invalidate after 5th wrong attempt
        $db->prepare('UPDATE otp_codes SET used = 1, attempts = :a WHERE id = :id')
           ->execute(['a' => $new_attempts, 'id' => $otp['id']]);
        return 'locked';
    }
    $db->prepare('UPDATE otp_codes SET attempts = :a WHERE id = :id')
       ->execute(['a' => $new_attempts, 'id' => $otp['id']]);
    return 'invalid';
}

/**
 * Send a simple notification email (no OTP).
 *
 * @param  string $to_email  Recipient email.
 * @param  string $subject   Email subject.
 * @param  string $heading   HTML heading text.
 * @param  string $body_text Plain-text body paragraph.
 * @return bool              True if sent, false on failure.
 */
function send_notification_email($to_email, $subject, $heading, $body_text) {
    try {
        $mail = create_smtp_mailer();
        $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
        $mail->addAddress($to_email);
        $mail->Subject = $subject;
        $mail->isHTML(true);

        $mail->Body = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"></head><body style="font-family:Arial,Helvetica,sans-serif;background:#f4f4f4;padding:20px;">'
            . '<div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:8px;padding:30px;text-align:center;">'
            . '<h2 style="color:#333;margin-bottom:10px;">' . htmlspecialchars($heading) . '</h2>'
            . '<p style="color:#555;font-size:16px;">' . htmlspecialchars($body_text) . '</p>'
            . '<hr style="border:none;border-top:1px solid #eee;margin:24px 0;">'
            . '<p style="color:#aaa;font-size:12px;">If you did not perform this action, please contact support immediately.</p>'
            . '</div></body></html>';

        $mail->AltBody = $body_text . "\n\nIf you did not perform this action, please contact support immediately.";

        $mail->send();
        return true;
    } catch (\Throwable $e) {
        error_log('CertiVault notification email failed to ' . $to_email . ': ' . $e->getMessage());
        return false;
    }
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
    // Delegates to the shared validator so every existing caller
    // picks up the full policy (upper/lower/digit/special, 8–72).
    return v_password_strong($password);
}

/**
 * Render a user-friendly error page without leaking internals.
 */
function show_error_page($title, $message) {
    http_response_code(500);
    $page_title = $title . ' - CertiVault';
    require __DIR__ . '/../partials/head.php';
    require __DIR__ . '/../partials/header.php';
    echo '<main id="main">';
    echo '<div class="container shell-narrow">';
    echo '<h2>' . htmlspecialchars($title) . '</h2>';
    echo '<p>' . htmlspecialchars($message) . '</p>';
    echo '<a href="login.php" class="btn">Go to Login</a>';
    echo '</div></main>';
    require __DIR__ . '/../partials/footer.php';
    echo '</body></html>';
    exit();
}

