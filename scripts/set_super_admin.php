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
if (($e = validate_password_strength($password)) !== true) {
    fwrite(STDERR, "Error: $e\n");
    exit(1);
}

$db = Database::getInstance();
$hash = password_hash($password, PASSWORD_BCRYPT);
$stmt = $db->prepare('UPDATE users SET email = :email, password_hash = :hash, is_verified = 1, failed_login_attempts = 0, locked_until = NULL WHERE role = "super_admin"');
$stmt->execute(['email' => $email, 'hash' => $hash]);

if ($stmt->rowCount() === 0) {
    fwrite(STDERR, "Error: no super_admin row found to update.\n");
    exit(1);
}

echo "Super admin credentials updated for $email\n";
exit(0);
