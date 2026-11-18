<?php
// scripts/set_super_admin.php
// ─────────────────────────────────────────────────────────────────────
// Set (or rotate) the super admin's email + password.
//
// Usage:  php scripts/set_super_admin.php
//
// Why this exists: the seeded superadmin@certivault.com row is not a
// real mailbox, so the OTP-based password-reset/activation flows can
// never deliver to it. This script sets credentials directly.
//
// NOTE: the seeded row in database/schema.sql is intentionally untouched.
// ─────────────────────────────────────────────────────────────────────

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die('This script must be run from the command line.');
}

require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/SuperAdminService.php';

fwrite(STDOUT, "Set super admin credentials\n");
fwrite(STDOUT, "---------------------------\n");

fwrite(STDOUT, "New email: ");
$email = trim((string)fgets(STDIN));
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fwrite(STDERR, "Error: not a valid email address.\n");
    exit(1);
}

fwrite(STDOUT, "New password: ");
$password = (string)fgets(STDIN);
$password = rtrim($password, "\r\n");
fwrite(STDOUT, "Confirm password: ");
$confirm = rtrim((string)fgets(STDIN), "\r\n");

if ($password !== $confirm) {
    fwrite(STDERR, "Error: passwords do not match.\n");
    exit(1);
}

// Validation (email, full password policy) + the UPDATE live in
// SuperAdminService, shared with the CV_SUPER_ADMIN_* bootstrap in
// scripts/render_boot.php.
try {
    SuperAdminService::setCredentials(Database::getInstance(), $email, $password);
} catch (InvalidArgumentException | RuntimeException $e) {
    fwrite(STDERR, 'Error: ' . $e->getMessage() . "\n");
    exit(1);
}

echo "Super admin credentials updated for $email\n";
exit(0);
