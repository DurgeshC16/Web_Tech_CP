-- database/migrations/004_revocation_audit.sql
-- Phase 5: record WHEN and WHO revoked a certificate
-- Run this in phpMyAdmin against the 'certivault' database.

USE certivault;

SET @col_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'certificates' AND COLUMN_NAME = 'revoked_at');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE certificates ADD COLUMN revoked_at DATETIME NULL DEFAULT NULL',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

SET @col_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'certificates' AND COLUMN_NAME = 'revoked_by');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE certificates ADD COLUMN revoked_by INT NULL DEFAULT NULL',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
