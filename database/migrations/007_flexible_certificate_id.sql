-- database/migrations/007_flexible_certificate_id.sql
-- Custom certificate IDs at issuance: widen the columns and enforce
-- case-insensitive uniqueness via a lowercase generated column (works
-- regardless of the table collation).
-- Safe to re-run: MODIFY COLUMN is idempotent; the column/index use guards.
-- Run this in phpMyAdmin against the 'certivault' database.

USE certivault;

ALTER TABLE certificates MODIFY COLUMN certificate_id VARCHAR(64) NOT NULL;
ALTER TABLE verification_logs MODIFY COLUMN certificate_id_found VARCHAR(64) NULL;

-- certificates.certificate_id_norm (LOWER mirror for uniqueness)
SET @col_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'certificates' AND COLUMN_NAME = 'certificate_id_norm');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE certificates ADD COLUMN certificate_id_norm VARCHAR(64) GENERATED ALWAYS AS (LOWER(certificate_id)) STORED',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- UNIQUE on certificates.certificate_id_norm
SET @idx_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'certificates' AND INDEX_NAME = 'uniq_certificates_cid_norm');
SET @sql = IF(@idx_exists = 0,
    'ALTER TABLE certificates ADD UNIQUE INDEX uniq_certificates_cid_norm (certificate_id_norm)',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
