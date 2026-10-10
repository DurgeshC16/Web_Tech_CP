<?php
// src/utils/validators.php
// ─────────────────────────────────────────────────────────────────────
// Shared server-side validation layer. Every validator returns true on
// success or a human-readable error string on failure, so callers can
// build a per-field $errors array like:
//
//     $errors = [];
//     if (($e = v_required($name, 'Full Name')) !== true) { $errors['full_name'] = $e; }
//
// ─────────────────────────────────────────────────────────────────────

/**
 * A value is present (non-empty after trimming).
 */
function v_required($value, $label) {
    if ($value === null || trim((string)$value) === '') {
        return $label . ' is required.';
    }
    return true;
}

/**
 * Numeric value within [$min, $max] (inclusive).
 */
function v_range($number, $min, $max, $label) {
    if (!is_numeric($number)) {
        return $label . ' must be a number.';
    }
    $n = $number + 0;
    if ($n < $min || $n > $max) {
        return $label . ' must be between ' . $min . ' and ' . $max . '.';
    }
    return true;
}

/**
 * String length within [$min, $max].
 */
function v_length($string, $min, $max, $label) {
    $len = strlen((string)$string);
    if ($len < $min || $len > $max) {
        return $label . ' must be between ' . $min . ' and ' . $max . ' characters.';
    }
    return true;
}

/**
 * Two values must be identical (e.g. password vs confirm password).
 */
function v_compare($a, $b, $label) {
    if ($a !== $b) {
        return $label . ' do not match.';
    }
    return true;
}

/**
 * Valid email address, max 254 characters (RFC 5321 limit).
 */
function v_email($value) {
    $value = (string)$value;
    if (strlen($value) > 254) {
        return 'Email address must not exceed 254 characters.';
    }
    if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
        return 'Please provide a valid email address.';
    }
    return true;
}

/**
 * Numeric validation with optional bounds. Integer-only by default.
 */
function v_number($value, $min = null, $max = null, $integerOnly = true) {
    if ($integerOnly) {
        if (!preg_match('/^-?\d+$/', trim((string)$value))) {
            return 'Value must be a whole number.';
        }
        $n = (int)$value;
    } else {
        if (!is_numeric($value)) {
            return 'Value must be a number.';
        }
        $n = $value + 0;
    }
    if ($min !== null && $n < $min) {
        return 'Value must be at least ' . $min . '.';
    }
    if ($max !== null && $n > $max) {
        return 'Value must not exceed ' . $max . '.';
    }
    return true;
}

/**
 * Password policy: 8–72 chars (72 = bcrypt byte limit), at least one
 * uppercase, one lowercase, one digit, and one special character.
 */
function v_password_strong($password) {
    $password = (string)$password;
    $len = strlen($password);
    if ($len < 8) {
        return 'Password must be at least 8 characters long.';
    }
    if ($len > 72) {
        return 'Password must not exceed 72 characters (bcrypt silently truncates longer input, so extra characters add no security).';
    }
    if (!preg_match('/[A-Z]/', $password)) {
        return 'Password must contain at least one uppercase letter.';
    }
    if (!preg_match('/[a-z]/', $password)) {
        return 'Password must contain at least one lowercase letter.';
    }
    if (!preg_match('/\d/', $password)) {
        return 'Password must contain at least one digit.';
    }
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        return 'Password must contain at least one special character.';
    }
    return true;
}

/**
 * Certificate ID format: CV-YYYY-NNNNNN
 */
function v_certificate_id($value) {
    if (!preg_match('/^CV-\d{4}-\d{6}$/', (string)$value)) {
        return 'Certificate ID must match the format CV-YYYY-NNNNNN.';
    }
    return true;
}

/**
 * Person name: letters, spaces, and . ' - ; 2–100 chars.
 */
function v_person_name($value) {
    $value = (string)$value;
    $len = strlen($value);
    if ($len < 2 || $len > 100) {
        return 'Name must be between 2 and 100 characters.';
    }
    if (!preg_match("/^[A-Za-zÀ-ÿ .'\-;]+$/u", $value)) {
        return "Name may only contain letters, spaces, and the characters . ' - ;";
    }
    return true;
}

/**
 * One-time code: exactly 6 digits.
 */
function v_otp($value) {
    if (!preg_match('/^\d{6}$/', trim((string)$value))) {
        return 'Verification code must be exactly 6 digits.';
    }
    return true;
}

/**
 * Compare rule for two dates: $later must be strictly after $earlier
 * (e.g. expiry date vs issue date). Both must parse; unparseable input
 * fails closed with a field-appropriate message.
 */
function v_date_after($later, $earlier, $label) {
    $later_ts = strtotime((string)$later);
    $earlier_ts = strtotime((string)$earlier);
    if ($later_ts === false) {
        return $label . ' is not a valid date.';
    }
    if ($earlier_ts === false) {
        return 'The start date is not a valid date.';
    }
    if ($later_ts <= $earlier_ts) {
        return $label . ' must be after the issue date.';
    }
    return true;
}

/**
 * Issue date: valid date, not in the future, not before 1950.
 * Expiry (when provided) must be after the issue date.
 */
function v_date_range($issue, $expiry) {
    $issue_ts = strtotime((string)$issue);
    if ($issue_ts === false) {
        return 'Please provide a valid issue date.';
    }
    if ($issue_ts > strtotime('today')) {
        return 'Issue date cannot be in the future.';
    }
    if ($issue_ts < strtotime('1950-01-01')) {
        return 'Issue date cannot be before 1950.';
    }
    if ($expiry !== null && $expiry !== '') {
        $expiry_ts = strtotime((string)$expiry);
        if ($expiry_ts === false) {
            return 'Please provide a valid expiry date.';
        }
        if ($expiry_ts <= $issue_ts) {
            return 'Expiry date must be after the issue date.';
        }
    }
    return true;
}

/**
 * True when the request body was discarded because it exceeded
 * post_max_size (PHP then leaves $_POST and $_FILES empty, so without
 * this check the request dies later with a misleading CSRF 403).
 */
function is_post_overflow() {
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        return false;
    }
    return empty($_POST) && empty($_FILES) && (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 0;
}

/**
 * Uploaded certificate file: PDF/PNG/JPG extension + matching MIME,
 * size between 100 bytes and 5 MB.
 *
 * Every $_FILES['error'] code maps to a user-friendly message so the
 * real cause (php.ini limit, partial upload, missing tmp dir, …) is
 * never masked as a generic "file is required".
 */
function v_upload($file) {
    if (!$file || !isset($file['error'])) {
        return 'A certificate file is required.';
    }
    switch ($file['error']) {
        case UPLOAD_ERR_OK:
            break;
        case UPLOAD_ERR_INI_SIZE:
            return 'The file exceeds the server upload limit (upload_max_filesize in php.ini). Please use a smaller file (max 5 MB).';
        case UPLOAD_ERR_FORM_SIZE:
            return 'The file exceeds the form size limit (MAX_FILE_SIZE). Please use a smaller file (max 5 MB).';
        case UPLOAD_ERR_PARTIAL:
            return 'The file was only partially uploaded. Please try again.';
        case UPLOAD_ERR_NO_FILE:
            return 'A certificate file is required.';
        case UPLOAD_ERR_NO_TMP_DIR:
            return 'Server misconfiguration: temporary upload folder is missing. Please contact the administrator.';
        case UPLOAD_ERR_CANT_WRITE:
            return 'The server failed to write the uploaded file. Please try again or contact the administrator.';
        case UPLOAD_ERR_EXTENSION:
            return 'The upload was blocked by a server extension. Please try a different PDF/PNG/JPG file.';
        default:
            return 'An unknown upload error occurred. Please try again.';
    }
    if (empty($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        return 'The file upload failed (temporary file missing). Please try again.';
    }
    $ext = strtolower(pathinfo($file['name'] ?? '', PATHINFO_EXTENSION));
    if (!in_array($ext, ['pdf', 'png', 'jpg', 'jpeg'], true)) {
        return 'Only PDF, PNG, and JPG files are allowed.';
    }
    if (!function_exists('finfo_open')) {
        return 'Server misconfiguration: fileinfo extension is disabled. Please contact the administrator.';
    }
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfo === false) {
        return 'The server could not verify the file type. Please try again later.';
    }
    $mime = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    $mimeMap = [
        'pdf'  => ['application/pdf'],
        'png'  => ['image/png'],
        'jpg'  => ['image/jpeg'],
        'jpeg' => ['image/jpeg'],
    ];
    if (!in_array($mime, $mimeMap[$ext], true)) {
        return 'File content does not match an allowed type (PDF, PNG, JPG).';
    }
    if (($file['size'] ?? 0) < 100) {
        return 'File appears to be empty or corrupted (minimum 100 bytes).';
    }
    if ($file['size'] > 5 * 1024 * 1024) {
        return 'File size exceeds the 5MB limit.';
    }
    return true;
}

/**
 * Echo an inline error for a field when present in $errors.
 */
function render_field_error($errors, $key) {
    if (!empty($errors[$key])) {
        echo '<div class="field-error" role="alert">' . htmlspecialchars($errors[$key]) . '</div>';
    }
}
