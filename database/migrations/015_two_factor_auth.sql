-- database/migrations/015_two_factor_auth.sql
-- Optional TOTP two-factor authentication (RFC 6238; authenticator apps).
--   users.totp_secret     base32 secret, encrypted at rest (CryptoService CFG1)
--   users.totp_enabled    1 once the user confirmed a code during setup
--   users.totp_last_step  last accepted 30-s time step (blocks code replay)
--   user_recovery_codes   10 single-use recovery codes per user, stored as
--                         HMAC-SHA-256 hashes only
-- Safe to re-run.

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'totp_secret');
SET @ddl := IF(@c = 0, 'ALTER TABLE users ADD COLUMN totp_secret TEXT NULL DEFAULT NULL', 'SELECT 1');
PREPARE s1 FROM @ddl; EXECUTE s1; DEALLOCATE PREPARE s1;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'totp_enabled');
SET @ddl := IF(@c = 0, 'ALTER TABLE users ADD COLUMN totp_enabled TINYINT(1) NOT NULL DEFAULT 0', 'SELECT 1');
PREPARE s2 FROM @ddl; EXECUTE s2; DEALLOCATE PREPARE s2;

SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME = 'totp_last_step');
SET @ddl := IF(@c = 0, 'ALTER TABLE users ADD COLUMN totp_last_step BIGINT NULL DEFAULT NULL', 'SELECT 1');
PREPARE s3 FROM @ddl; EXECUTE s3; DEALLOCATE PREPARE s3;

CREATE TABLE IF NOT EXISTS user_recovery_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    code_hash CHAR(64) NOT NULL,
    used_at DATETIME NULL DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_recovery_user (user_id),
    CONSTRAINT fk_recovery_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
