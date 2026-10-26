<?php
// src/config/config.php
// ─────────────────────────────────────────────────────────────────────
// All secrets below should be set via environment variables in production.
// The defaults here are for local development ONLY.
// ─────────────────────────────────────────────────────────────────────

// ── Local overrides (loaded FIRST so they win everywhere below) ─────
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

// ── Database ────────────────────────────────────────────────────────
define('DB_HOST', getenv('CV_DB_HOST') ?: 'localhost');
define('DB_USER', getenv('CV_DB_USER') ?: 'root');
define('DB_PASS', getenv('CV_DB_PASS') ?: '');
define('DB_NAME', getenv('CV_DB_NAME') ?: 'certivault');

// ── Application ─────────────────────────────────────────────────────
// BASE_URL feeds QR-code verify URLs, share links, and activation emails.
// An explicit CV_BASE_URL always wins (use it behind proxies or when the
// public hostname differs). Otherwise it is derived per-request as
// scheme + host + port + path up to /public, so the app works on any
// host/port/mount point with zero configuration.
function certivault_default_base_url() {
    // CLI (scripts, cron): no request to derive from — dev fallback.
    if (php_sapi_name() === 'cli' || empty($_SERVER['HTTP_HOST'])) {
        return 'http://localhost:8081/certivault/public';
    }
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') // TLS-terminating proxy
        || (($_SERVER['SERVER_PORT'] ?? '') == '443');
    $scheme = $https ? 'https' : 'http';
    // HTTP_HOST carries the non-default port (e.g. 127.0.0.1:8081).
    // Validate its shape: it is request-supplied and ends up in emails/QRs.
    $host = $_SERVER['HTTP_HOST'];
    if (!preg_match('/^[A-Za-z0-9.\-]+(?::\d+)?$/', $host)) {
        $host = 'localhost';
    }
    // Path up to and including /public, wherever the repo is mounted
    // (e.g. /certivault/public). With docroot=public there is no /public
    // in SCRIPT_NAME — then the docroot itself is the base path.
    $script = str_replace('\\', '/', $_SERVER['SCRIPT_NAME'] ?? '');
    $pos = strpos($script, '/public');
    $base_path = ($pos !== false)
        ? substr($script, 0, $pos + strlen('/public'))
        : rtrim(dirname($script), '/');
    return $scheme . '://' . $host . $base_path;
}
define('BASE_URL', getenv('CV_BASE_URL')
    ?: (defined('CV_BASE_URL') ? CV_BASE_URL : null)
    ?: certivault_default_base_url());

// Server-side encryption key for RSA private keys at rest.
// IMPORTANT: In production, use a proper KMS or at minimum a strong
// random value stored outside the repo (e.g. in an env var).
define('APP_ENCRYPTION_KEY', getenv('CV_ENCRYPTION_KEY') ?: 'CHANGE-ME-local-dev-only-32chars!!');

// HMAC pepper for OTP codes at rest. Separate from APP_ENCRYPTION_KEY so
// compromise of one secret does not expose the other.
defined('OTP_PEPPER') || define('OTP_PEPPER', getenv('CV_OTP_PEPPER') ?: 'certivault-otp-pepper-dev-only!!');

// Secret for share-link HMACs (view_certificate_student.php / share.php).
// Deliberately separate from APP_ENCRYPTION_KEY so a share-link leak does
// not compromise the key that encrypts institution private keys.
defined('SHARE_LINK_SECRET') || define('SHARE_LINK_SECRET', getenv('CV_SHARE_SECRET') ?: 'certivault-share-secret-dev-only!!');

// ── Google reCAPTCHA v2 ("I'm not a robot" checkbox) ─────────────────
// Empty by default: with no keys the forms fall back to the offline
// arithmetic CAPTCHA. Set both (env vars or config.local.php) to switch
// all four public forms to reCAPTCHA. Deliberately NOT in the production
// secret guard — empty simply means "offline fallback mode".
defined('RECAPTCHA_SITE_KEY') || define('RECAPTCHA_SITE_KEY', getenv('CV_RECAPTCHA_SITE_KEY') ?: '');
defined('RECAPTCHA_SECRET_KEY') || define('RECAPTCHA_SECRET_KEY', getenv('CV_RECAPTCHA_SECRET_KEY') ?: '');

// ── SMTP (email delivery) ───────────────────────────────────────────
// (Local overrides already loaded above; the defined() guards let
// config.local.php values win.)
defined('SMTP_HOST')     || define('SMTP_HOST', getenv('SMTP_HOST') ?: 'smtp.gmail.com');
defined('SMTP_PORT')     || define('SMTP_PORT', (int)(getenv('SMTP_PORT') ?: 587));
defined('SMTP_USERNAME') || define('SMTP_USERNAME', trim(getenv('SMTP_USERNAME') ?: ''));
defined('SMTP_PASSWORD') || define('SMTP_PASSWORD', trim(getenv('SMTP_PASSWORD') ?: ''));
defined('SMTP_ENCRYPTION') || define('SMTP_ENCRYPTION', getenv('SMTP_ENCRYPTION') ?: 'tls');
defined('SMTP_FROM_EMAIL') || define('SMTP_FROM_EMAIL', getenv('SMTP_FROM_EMAIL') ?: (defined('SMTP_USERNAME') && SMTP_USERNAME !== '' ? SMTP_USERNAME : (getenv('SMTP_USERNAME') ?: 'no-reply@certivault.local')));
defined('SMTP_FROM_NAME') || define('SMTP_FROM_NAME', getenv('SMTP_FROM_NAME') ?: 'CertiVault');

// ── Optional external certificate sources (verify.php fallback) ─────
// OFF by default; see README "External verification sources". When on,
// an ID not found locally is looked up in the configured source(s) and
// shown in a clearly separate card — never as a CertiVault VALID verdict.
defined('EXT_SOURCE_ENABLED')   || define('EXT_SOURCE_ENABLED', (bool)(getenv('CV_EXT_SOURCE_ENABLED') ?: false));
defined('EXT_ALLOWED_HOSTS')    || define('EXT_ALLOWED_HOSTS', getenv('CV_EXT_ALLOWED_HOSTS') ?: ''); // comma list, e.g. 'badges.openbadges.example.org'
defined('EXT_OB_URL_TEMPLATE')  || define('EXT_OB_URL_TEMPLATE', getenv('CV_EXT_OB_URL_TEMPLATE') ?: ''); // must contain {id}
defined('EXT_OB_SOURCE_NAME')   || define('EXT_OB_SOURCE_NAME', getenv('CV_EXT_OB_SOURCE_NAME') ?: '');
defined('EXT_DB_DSN')           || define('EXT_DB_DSN', getenv('CV_EXT_DB_DSN') ?: '');       // e.g. 'mysql:host=...;dbname=...' or 'sqlite:...'
defined('EXT_DB_USER')          || define('EXT_DB_USER', getenv('CV_EXT_DB_USER') ?: '');     // READ-ONLY user!
defined('EXT_DB_PASS')          || define('EXT_DB_PASS', getenv('CV_EXT_DB_PASS') ?: '');
defined('EXT_DB_TABLE')         || define('EXT_DB_TABLE', getenv('CV_EXT_DB_TABLE') ?: 'external_certificates');
defined('EXT_DB_ID_COLUMN')     || define('EXT_DB_ID_COLUMN', getenv('CV_EXT_DB_ID_COLUMN') ?: 'certificate_id');
defined('EXT_DB_HOLDER_COLUMN') || define('EXT_DB_HOLDER_COLUMN', getenv('CV_EXT_DB_HOLDER_COLUMN') ?: 'holder');
defined('EXT_DB_TITLE_COLUMN')  || define('EXT_DB_TITLE_COLUMN', getenv('CV_EXT_DB_TITLE_COLUMN') ?: 'title');
defined('EXT_DB_ISSUER_COLUMN') || define('EXT_DB_ISSUER_COLUMN', getenv('CV_EXT_DB_ISSUER_COLUMN') ?: 'issuer');
defined('EXT_DB_DATE_COLUMN')   || define('EXT_DB_DATE_COLUMN', getenv('CV_EXT_DB_DATE_COLUMN') ?: 'issue_date');
defined('EXT_DB_STATUS_COLUMN') || define('EXT_DB_STATUS_COLUMN', getenv('CV_EXT_DB_STATUS_COLUMN') ?: 'status');
defined('EXT_DB_LABEL')         || define('EXT_DB_LABEL', getenv('CV_EXT_DB_LABEL') ?: 'external database');
defined('EXT_RATE_LIMIT')       || define('EXT_RATE_LIMIT', (int)(getenv('CV_EXT_RATE_LIMIT') ?: 15)); // lookups / IP / 10 min
// Managed registry lookups are disabled unless explicitly enabled. Legacy
// EXT_* settings remain available as a fallback for existing installations.
defined('EXT_REGISTRY_ENABLED') || define('EXT_REGISTRY_ENABLED', (getenv('CV_EXT_REGISTRY_ENABLED') ?: '0') === '1');
// Student/institution attestation flow has its own explicit opt-in.
defined('ATTESTED_EXTERNAL_CREDENTIALS_ENABLED') || define('ATTESTED_EXTERNAL_CREDENTIALS_ENABLED', (getenv('CV_ATTESTED_CREDENTIALS_ENABLED') ?: '0') === '1');

// ── Smart Verify (verify.php / index.php; local, ON by default) ─────
// Text/file/QR pipeline. Outbound requests: NONE — external issuer
// entries are click-through links generated from an allow-listed map
// (the user's browser opens them, not the server), and the external
// source service above stays a separate, OFF-by-default feature.
defined('SMART_VERIFY_ENABLED')     || define('SMART_VERIFY_ENABLED', (getenv('CV_SMART_VERIFY') ?: '1') !== '0');
defined('SMART_EXTERNAL_LINKS')     || define('SMART_EXTERNAL_LINKS', (getenv('CV_SMART_EXTERNAL_LINKS') ?: '1') !== '0');

// ── Public status API (api_status.php; read-only, ON by default) ────
// GET api_status.php?certificate_id=… → JSON verdict + trust score.
// Read-only, rate-limited, audit-logged; disable per install with
// CV_API_ENABLED=0 (e.g. behind a firewall that exposes something else).
defined('API_ENABLED')              || define('API_ENABLED', (getenv('CV_API_ENABLED') ?: '1') !== '0');

// Transparency checkpoint signing key is deliberately file-backed and
// separate from institution signing keys and APP_ENCRYPTION_KEY.
defined('TLOG_PRIVATE_KEY_FILE') || define('TLOG_PRIVATE_KEY_FILE', getenv('CV_TLOG_PRIVATE_KEY_FILE') ?: __DIR__ . '/../../private_data/tlog/platform_private.pem');
defined('TLOG_PUBLIC_KEY_FILE')  || define('TLOG_PUBLIC_KEY_FILE', getenv('CV_TLOG_PUBLIC_KEY_FILE') ?: __DIR__ . '/../../private_data/tlog/platform_public.pem');
defined('CERTIFICATE_TRANSPARENCY_ENABLED') || define('CERTIFICATE_TRANSPARENCY_ENABLED', (getenv('CV_CERTIFICATE_TRANSPARENCY_ENABLED') ?: '0') === '1');

// ── Error Handling ──────────────────────────────────────────────────
// In production: display_errors = Off, log_errors = On
$is_production = (getenv('CV_ENV') === 'production');
defined('CV_DEBUG') || define('CV_DEBUG', false);
$debug = CV_DEBUG === true;
ini_set('display_errors', $debug ? '1' : '0');
ini_set('display_startup_errors', $debug ? '1' : '0');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/../../private_data/php_errors.log');
error_reporting(E_ALL);

// ── Production secret guard ─────────────────────────────────────────
// Refuse to run with committed default secrets in production.
if ($is_production) {
    $defaults = [
        'APP_ENCRYPTION_KEY' => 'CHANGE-ME-local-dev-only-32chars!!',
        'SHARE_LINK_SECRET'  => 'certivault-share-secret-dev-only!!',
        'OTP_PEPPER'         => 'certivault-otp-pepper-dev-only!!',
    ];
    foreach ($defaults as $name => $default) {
        if (defined($name) && constant($name) === $default) {
            error_log("[CertiVault] FATAL: $name is still the committed development default while CV_ENV=production. Set a strong value via its environment variable before deploying.");
            http_response_code(500);
            die('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Server Error</title></head><body><h1>500 — Internal Server Error</h1><p>The service is misconfigured. Please contact the site administrator.</p></body></html>');
        }
    }
}
