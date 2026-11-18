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
//
// Exception — an EXPLICITLY set process environment variable for the
// database name or the mail transport wins over config.local.php. These
// select WHICH deployment the process talks to; an operator (or a test
// harness that starts `php -S` with CV_DB_NAME=certivault_test) setting
// them on purpose must not be silently redirected to the dev database by
// a local file. Apache/XAMPP does not pass OS env vars, so ordinary local
// browsing still uses config.local.php exactly as before.
foreach (['DB_NAME' => 'CV_DB_NAME', 'MAIL_TRANSPORT' => 'CV_MAIL_TRANSPORT'] as $cv_const => $cv_env) {
    $cv_val = getenv($cv_env);
    if (is_string($cv_val) && $cv_val !== '' && !defined($cv_const)) {
        define($cv_const, $cv_val);
    }
}
unset($cv_const, $cv_env, $cv_val);
$local_config = __DIR__ . '/config.local.php';
if (file_exists($local_config)) {
    require_once $local_config;
}

// ── Trusted reverse proxy (OFF by default) ──────────────────────────
// CV_TRUST_PROXY=1 is for hosts that terminate TLS at their own proxy
// (Render: Cloudflare -> Render proxy -> container). The container then
// sees the PROXY's address in REMOTE_ADDR and plain HTTP, so every
// per-IP control (guest quota, verify rate limiter, login lockout) would
// share one bucket and secure cookies / HSTS would never switch on.
// When enabled, REMOTE_ADDR is rewritten from the first header in
// TRUST_PROXY_HEADERS that carries a valid IP, and HTTPS is set to 'on'
// when X-Forwarded-Proto is https — so no call site has to change.
//
// Header choice (see docs/13_DEPLOY_RENDER.md): Render sits behind
// Cloudflare, which OVERWRITES True-Client-IP / CF-Connecting-IP with the
// address it actually received the connection from, so a client cannot
// spoof them. X-Forwarded-For is deliberately NOT used: Render's proxy
// appends to a client-supplied X-Forwarded-For instead of replacing it,
// so its first entry is attacker-controlled. Never enable this setting
// on a server that is reachable directly (without that proxy in front).
defined('TRUST_PROXY') || define('TRUST_PROXY', (getenv('CV_TRUST_PROXY') ?: '0') === '1');
defined('TRUST_PROXY_HEADERS') || define('TRUST_PROXY_HEADERS', getenv('CV_TRUST_PROXY_HEADERS') ?: 'True-Client-IP,CF-Connecting-IP');

/**
 * Apply trusted-proxy information to a $_SERVER-shaped array.
 * Only ever reads the configured headers (never X-Forwarded-For); a header
 * whose value is not a valid IPv4/IPv6 address is ignored, leaving
 * REMOTE_ADDR unchanged. The proxy's own address is kept in
 * CV_PROXY_REMOTE_ADDR for diagnostics.
 */
function certivault_apply_trusted_proxy(array $server, string $headerList): array {
    foreach (explode(',', $headerList) as $name) {
        $name = trim($name);
        if ($name === '') {
            continue;
        }
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        $value = isset($server[$key]) && is_string($server[$key]) ? trim($server[$key]) : '';
        if ($value !== '' && filter_var($value, FILTER_VALIDATE_IP) !== false) {
            if (!isset($server['CV_PROXY_REMOTE_ADDR'])) {
                $server['CV_PROXY_REMOTE_ADDR'] = $server['REMOTE_ADDR'] ?? '';
            }
            $server['REMOTE_ADDR'] = $value;
            break;
        }
    }
    $proto = isset($server['HTTP_X_FORWARDED_PROTO']) && is_string($server['HTTP_X_FORWARDED_PROTO'])
        ? strtolower(trim(explode(',', $server['HTTP_X_FORWARDED_PROTO'])[0])) : '';
    if ($proto === 'https') {
        $server['HTTPS'] = 'on';
    }
    return $server;
}
if (TRUST_PROXY && php_sapi_name() !== 'cli') {
    $_SERVER = certivault_apply_trusted_proxy($_SERVER, TRUST_PROXY_HEADERS);
}

// ── Database ────────────────────────────────────────────────────────
// (defined() guards let config.local.php override these for local dev.)
defined('DB_HOST') || define('DB_HOST', getenv('CV_DB_HOST') ?: 'localhost');
defined('DB_USER') || define('DB_USER', getenv('CV_DB_USER') ?: 'root');
defined('DB_PASS') || define('DB_PASS', getenv('CV_DB_PASS') ?: '');
defined('DB_NAME') || define('DB_NAME', getenv('CV_DB_NAME') ?: 'certivault');
// Optional (all OFF/empty by default → the classic localhost:3306 setup):
// DB_PORT        non-default port (managed MySQL, e.g. Aiven)
// DB_SSL_CA      path to the CA certificate that signed the server's TLS cert
// DB_SSL_CA_PEM  the CA certificate itself (PEM text, e.g. pasted into a
//                hosting dashboard); written once to a temp file.
// Either CA setting turns TLS on WITH server-certificate verification.
defined('DB_PORT')       || define('DB_PORT', (int)(getenv('CV_DB_PORT') ?: 0));
defined('DB_SSL_CA')     || define('DB_SSL_CA', getenv('CV_DB_SSL_CA') ?: '');
defined('DB_SSL_CA_PEM') || define('DB_SSL_CA_PEM', getenv('CV_DB_SSL_CA_PEM') ?: '');

// ── Application ─────────────────────────────────────────────────────
// BASE_URL feeds QR-code verify URLs, share links, and activation emails.
// An explicit CV_BASE_URL always wins (use it behind proxies or when the
// public hostname differs). Otherwise it is derived per-request as
// scheme + host + port + path up to /public, so the app works on any
// host/port/mount point with zero configuration.
function certivault_default_base_url() {
    // CLI (scripts, cron): no request to derive from. Fallback = the
    // documented dev server (php -S localhost:8081 -t public); set
    // CV_BASE_URL for any other address (it is baked into QR codes).
    if (php_sapi_name() === 'cli' || empty($_SERVER['HTTP_HOST'])) {
        return 'http://localhost:8081';
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
defined('APP_ENCRYPTION_KEY') || define('APP_ENCRYPTION_KEY', getenv('CV_ENCRYPTION_KEY') ?: 'CHANGE-ME-local-dev-only-32chars!!');

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
// Sender address/name. CV_MAIL_FROM_EMAIL / CV_MAIL_FROM_NAME are
// transport-neutral aliases (used with the Brevo HTTP transport, where
// there is no SMTP username to fall back to); SMTP_FROM_* still win.
defined('SMTP_FROM_EMAIL') || define('SMTP_FROM_EMAIL', getenv('SMTP_FROM_EMAIL') ?: getenv('CV_MAIL_FROM_EMAIL') ?: (defined('SMTP_USERNAME') && SMTP_USERNAME !== '' ? SMTP_USERNAME : (getenv('SMTP_USERNAME') ?: 'no-reply@certivault.local')));
defined('SMTP_FROM_NAME') || define('SMTP_FROM_NAME', getenv('SMTP_FROM_NAME') ?: getenv('CV_MAIL_FROM_NAME') ?: 'CertiVault');

// ── Mail transport ──────────────────────────────────────────────────
// 'smtp' (default): deliver through PHPMailer/SMTP as above.
// 'brevo': deliver over HTTPS through the Brevo transactional email API
//   (https://api.brevo.com/v3/smtp/email) using BREVO_API_KEY. For hosts
//   that block outbound SMTP ports (e.g. Render's free plan). Messages are
//   still built with PHPMailer, so every caller is unchanged.
// 'file': LOCAL DEVELOPMENT ONLY. Each rendered message (including the
//   OTP) is written to private_data/mail/*.eml (outside the web root) so
//   activation/reset can be completed without an SMTP account. OTP
//   verification is unchanged. Only 'smtp' and 'brevo' (with a key) are
//   accepted while CV_ENV=production (see the guard at the end of this file).
defined('MAIL_TRANSPORT') || define('MAIL_TRANSPORT', getenv('CV_MAIL_TRANSPORT') ?: 'smtp');
defined('MAIL_FILE_DIR')  || define('MAIL_FILE_DIR', __DIR__ . '/../../private_data/mail');
defined('BREVO_API_KEY')  || define('BREVO_API_KEY', trim(getenv('CV_BREVO_API_KEY') ?: ''));
defined('BREVO_API_URL')  || define('BREVO_API_URL', 'https://api.brevo.com/v3/smtp/email');

// ── Durable file store (OFF by default) ─────────────────────────────
// 'db': every file that must survive a restart (certificate uploads and
// generated PDFs, QR images, the key-pin file, transparency checkpoint
// files) is mirrored into the stored_files table and written back to disk
// at container start (scripts/render_boot.php). For hosts with an
// ephemeral filesystem (Render free plan). Any other value: no-op.
defined('FILE_STORE') || define('FILE_STORE', getenv('CV_FILE_STORE') ?: '');

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

// ── Guest verification quota (verify.php & friends; ON by default) ───
// Visitors who are NOT logged in get GUEST_VERIFY_LIMIT free certificate
// verifications per rolling GUEST_VERIFY_WINDOW seconds; after that the
// page asks them to log in or register (GuestQuotaService). Logged-in
// users are never counted. 0 disables the quota (the per-IP rate limiter
// in VerificationService still applies). api_status.php is NOT covered —
// it has its own limiter.
defined('GUEST_VERIFY_LIMIT')  || define('GUEST_VERIFY_LIMIT', max(0, (int)(getenv('CV_GUEST_VERIFY_LIMIT') !== false && getenv('CV_GUEST_VERIFY_LIMIT') !== '' ? getenv('CV_GUEST_VERIFY_LIMIT') : 5)));
defined('GUEST_VERIFY_WINDOW') || define('GUEST_VERIFY_WINDOW', max(60, (int)(getenv('CV_GUEST_VERIFY_WINDOW_SECONDS') ?: 86400)));

// ── Public status API (api_status.php; read-only, ON by default) ────
// GET api_status.php?certificate_id=… → JSON verdict + trust score.
// Read-only, rate-limited, audit-logged; disable per install with
// CV_API_ENABLED=0 (e.g. behind a firewall that exposes something else).
defined('API_ENABLED')              || define('API_ENABLED', (getenv('CV_API_ENABLED') ?: '1') !== '0');

// Transparency checkpoint signing key is deliberately file-backed and
// separate from institution signing keys and APP_ENCRYPTION_KEY.
defined('TLOG_PRIVATE_KEY_FILE') || define('TLOG_PRIVATE_KEY_FILE', getenv('CV_TLOG_PRIVATE_KEY_FILE') ?: __DIR__ . '/../../private_data/tlog/platform_private.pem');
defined('TLOG_PUBLIC_KEY_FILE')  || define('TLOG_PUBLIC_KEY_FILE', getenv('CV_TLOG_PUBLIC_KEY_FILE') ?: __DIR__ . '/../../private_data/tlog/platform_public.pem');
// Key fingerprint pinning (KeyPinService). The pin file must live OUTSIDE
// the database and ideally on storage the web/DB layer cannot write.
// Strict mode also rejects keys that were never pinned.
// One pin file per database (pins are keyed by institution/key id, which
// are only unique within one database).
defined('KEY_PINS_FILE')       || define('KEY_PINS_FILE', getenv('CV_KEY_PINS_FILE')
    ?: __DIR__ . '/../../private_data/pins/' . preg_replace('/[^A-Za-z0-9_-]/', '_', DB_NAME) . '.json');
defined('KEY_PINNING_STRICT')  || define('KEY_PINNING_STRICT', (getenv('CV_KEY_PINNING_STRICT') ?: '0') === '1');
defined('CERTIFICATE_TRANSPARENCY_ENABLED') || define('CERTIFICATE_TRANSPARENCY_ENABLED', (getenv('CV_CERTIFICATE_TRANSPARENCY_ENABLED') ?: '0') === '1');

// ── Error Handling ──────────────────────────────────────────────────
// In production: display_errors = Off, log_errors = On
$is_production = (getenv('CV_ENV') === 'production');
defined('CV_DEBUG') || define('CV_DEBUG', false);
$debug = CV_DEBUG === true;
ini_set('display_errors', $debug ? '1' : '0');
ini_set('display_startup_errors', $debug ? '1' : '0');
ini_set('log_errors', '1');
// CV_ERROR_LOG=stderr sends errors to the SAPI's own log instead (Apache's
// error log = the container log in the Docker image; stderr for CLI) — for
// hosts whose dashboard shows that log but offers no shell (Render). Any
// other non-empty value is used as a file path.
$cv_error_log = getenv('CV_ERROR_LOG') ?: '';
ini_set('error_log', $cv_error_log === 'stderr' ? '' : ($cv_error_log !== '' ? $cv_error_log : __DIR__ . '/../../private_data/php_errors.log'));
unset($cv_error_log);
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
    // The file mail transport is a development aid; in production it would
    // silently stop OTP delivery. 'brevo' is a real transport, but only
    // with an API key (otherwise no code could ever be delivered).
    $mail_ok = MAIL_TRANSPORT === 'smtp'
        || (MAIL_TRANSPORT === 'brevo' && trim((string)BREVO_API_KEY) !== '');
    if (!$mail_ok) {
        error_log("[CertiVault] FATAL: CV_MAIL_TRANSPORT='" . MAIL_TRANSPORT . "' is not allowed while CV_ENV=production. Use 'smtp', or 'brevo' together with CV_BREVO_API_KEY.");
        http_response_code(500);
        die('<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Server Error</title></head><body><h1>500 — Internal Server Error</h1><p>The service is misconfigured. Please contact the site administrator.</p></body></html>');
    }
}
