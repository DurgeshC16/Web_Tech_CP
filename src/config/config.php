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
define('BASE_URL', getenv('CV_BASE_URL') ?: 'http://localhost/certivault/public');

// Server-side encryption key for RSA private keys at rest.
// IMPORTANT: In production, use a proper KMS or at minimum a strong
// random value stored outside the repo (e.g. in an env var).
define('APP_ENCRYPTION_KEY', getenv('CV_ENCRYPTION_KEY') ?: 'CHANGE-ME-local-dev-only-32chars!!');

// ── Error Handling ──────────────────────────────────────────────────
// In production: display_errors = Off, log_errors = On
$is_production = (getenv('CV_ENV') === 'production');
ini_set('display_errors', $is_production ? '0' : '1');
ini_set('display_startup_errors', $is_production ? '0' : '1');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/../../private_data/php_errors.log');
error_reporting(E_ALL);
