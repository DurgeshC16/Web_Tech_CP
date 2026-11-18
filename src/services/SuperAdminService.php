<?php
// src/services/SuperAdminService.php
// ─────────────────────────────────────────────────────────────────────
// Set (or rotate) the super admin's email + password. Shared by
//   scripts/set_super_admin.php  (interactive CLI)
//   scripts/render_boot.php      (CV_SUPER_ADMIN_EMAIL / _PASSWORD at
//                                 container start; hosts without a shell)
// Same rules everywhere: valid email, the full password-strength policy,
// bcrypt hash, account verified and unlocked. Passwords are never logged.
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/../utils/validators.php';

class SuperAdminService
{
    /**
     * Apply credentials to the super_admin row.
     *
     * @param bool $createIfMissing  insert a super_admin row when none exists
     *                               (the CLI script keeps its old "no row"
     *                               error; the boot script creates one)
     * @return string 'updated' | 'unchanged' | 'created'
     * @throws InvalidArgumentException  invalid email / weak password /
     *                                   email used by another account
     * @throws RuntimeException          no super_admin row (and !$createIfMissing)
     */
    public static function setCredentials(PDO $db, string $email, string $password, bool $createIfMissing = false): string
    {
        $email = trim($email);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new InvalidArgumentException('not a valid email address.');
        }
        if (($e = v_password_strong($password)) !== true) {
            throw new InvalidArgumentException($e);
        }

        $stmt = $db->prepare('SELECT id, email, password_hash, is_verified, failed_login_attempts, locked_until FROM users WHERE role = :role ORDER BY id LIMIT 1');
        $stmt->execute(['role' => 'super_admin']);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        // The email must not belong to a different account (UNIQUE index).
        $other = $db->prepare('SELECT id FROM users WHERE email = :email AND role <> :role LIMIT 1');
        $other->execute(['email' => $email, 'role' => 'super_admin']);
        if ($other->fetchColumn() !== false) {
            throw new InvalidArgumentException('that email address already belongs to another (non super admin) account.');
        }

        if ($row) {
            // Idempotent on every boot: nothing to do when the same
            // credentials are already active (no needless re-hash).
            if (strcasecmp((string)$row['email'], $email) === 0
                && password_verify($password, (string)$row['password_hash'])
                && (int)$row['is_verified'] === 1
                && (int)$row['failed_login_attempts'] === 0
                && $row['locked_until'] === null) {
                return 'unchanged';
            }
            $hash = password_hash($password, PASSWORD_BCRYPT);
            $upd = $db->prepare('UPDATE users SET email = :email, password_hash = :hash, is_verified = 1, failed_login_attempts = 0, locked_until = NULL WHERE role = :role');
            $upd->execute(['email' => $email, 'hash' => $hash, 'role' => 'super_admin']);
            return 'updated';
        }

        if (!$createIfMissing) {
            throw new RuntimeException('no super_admin row found to update.');
        }
        $hash = password_hash($password, PASSWORD_BCRYPT);
        $ins = $db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:email, :hash, :role, 1)');
        $ins->execute(['email' => $email, 'hash' => $hash, 'role' => 'super_admin']);
        return 'created';
    }
}
