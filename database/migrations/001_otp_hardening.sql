-- database/migrations/001_otp_hardening.sql
-- Phase 2: OTP hardening
-- Safe to re-run: uses IF NOT EXISTS / idempotent ALTER patterns.
-- Run this in phpMyAdmin against the 'certivault' database.

USE certivault;

-- 1. Widen otp_code from VARCHAR(6) to VARCHAR(64) for HMAC-SHA256 storage.
--    ALTER COLUMN is idempotent if already VARCHAR(64).
ALTER TABLE otp_codes MODIFY COLUMN otp_code VARCHAR(64) NOT NULL;

-- 2. Update purpose ENUM: drop 'login_2fa', add 'password_reset' and 'password_change'.
ALTER TABLE otp_codes MODIFY COLUMN purpose ENUM('activation','password_reset','password_change') NOT NULL;

-- 3. Add attempts counter (tracks wrong verification attempts per code).
--    Safe to re-run: "ADD COLUMN IF NOT EXISTS" is not standard MySQL,
--    so we use a procedure guard.
SET @col_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'otp_codes' AND COLUMN_NAME = 'attempts');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE otp_codes ADD COLUMN attempts TINYINT NOT NULL DEFAULT 0',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 4. Invalidate ALL existing unused plaintext codes. After this migration,
--    only HMAC-hashed codes will be stored, so old plaintext rows must not
--    be verifiable.
UPDATE otp_codes SET used = 1 WHERE used = 0;
