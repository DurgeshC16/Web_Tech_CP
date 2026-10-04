<?php
// src/config/config.php
// ─────────────────────────────────────────────────────────────────────
// All secrets below should be set via environment variables in production.
// The defaults here are for local development ONLY.
// ─────────────────────────────────────────────────────────────────────

// ── Database ────────────────────────────────────────────────────────
define('DB_HOST', getenv('CV_DB_HOST') ?: 'localhost');
define('DB_USER', getenv('CV_DB_USER') ?: 'root');
define('DB_PASS', getenv('CV_DB_PASS') ?: '');
define('DB_NAME', getenv('CV_DB_NAME') ?: 'certivault');

// ── Application ─────────────────────────────────────────────────────
define('BASE_URL', getenv('CV_BASE_URL') ?: 'http://localhost:8081/certivault/public');

// Server-side encryption key for RSA private keys at rest.
// IMPORTANT: In production, use a proper KMS or at minimum a strong
// random value stored outside the repo (e.g. in an env var).
define('APP_ENCRYPTION_KEY', getenv('CV_ENCRYPTION_KEY') ?: 'CHANGE-ME-local-dev-only-32chars!!');

// ── Local overrides ─────────────────────────────────────────────────
// XAMPP/Apache on Windows does NOT reliably pass OS environment variables
// to PHP, so getenv() below can silently come back empty. For local dev you
// can instead copy src/config/config.local.php.example to config.local.php
// and fill in real values there — it defines the same constants directly and
// wins over the getenv() fallbacks below. config.local.php is gitignored;
// never commit real credentials.
$local_config = __DIR__ . '/config.local.php';
if (file_exists($local_config)) {
    require_once $local_config;
}

// ── SMTP (email delivery) ───────────────────────────────────────────
defined('SMTP_HOST')     || define('SMTP_HOST', getenv('SMTP_HOST') ?: 'smtp.gmail.com');
defined('SMTP_PORT')     || define('SMTP_PORT', (int)(getenv('SMTP_PORT') ?: 587));
defined('SMTP_USERNAME') || define('SMTP_USERNAME', trim(getenv('SMTP_USERNAME') ?: ''));
defined('SMTP_PASSWORD') || define('SMTP_PASSWORD', trim(getenv('SMTP_PASSWORD') ?: ''));
defined('SMTP_ENCRYPTION') || define('SMTP_ENCRYPTION', getenv('SMTP_ENCRYPTION') ?: 'tls');
defined('SMTP_FROM_EMAIL') || define('SMTP_FROM_EMAIL', getenv('SMTP_FROM_EMAIL') ?: (defined('SMTP_USERNAME') && SMTP_USERNAME !== '' ? SMTP_USERNAME : (getenv('SMTP_USERNAME') ?: 'no-reply@certivault.local')));
defined('SMTP_FROM_NAME') || define('SMTP_FROM_NAME', getenv('SMTP_FROM_NAME') ?: 'CertiVault');

// ── Error Handling ──────────────────────────────────────────────────
// In production: display_errors = Off, log_errors = On
$is_production = (getenv('CV_ENV') === 'production');
ini_set('display_errors', $is_production ? '0' : '1');
ini_set('display_startup_errors', $is_production ? '0' : '1');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/../../private_data/php_errors.log');
error_reporting(E_ALL);
