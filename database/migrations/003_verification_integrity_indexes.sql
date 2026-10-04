-- database/migrations/003_verification_integrity_indexes.sql
-- Phase 5: hardening indexes + unique qr_token
-- Run this in phpMyAdmin against the 'certivault' database.

USE certivault;

-- UNIQUE on certificates.qr_token (guard: skip if the index exists)
SET @idx_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'certificates' AND INDEX_NAME = 'uniq_certificates_qr_token');
SET @sql = IF(@idx_exists = 0,
    'ALTER TABLE certificates ADD UNIQUE INDEX uniq_certificates_qr_token (qr_token)',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- certificates(student_id)
SET @idx_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'certificates' AND INDEX_NAME = 'idx_certificates_student_id');
SET @sql = IF(@idx_exists = 0,
    'ALTER TABLE certificates ADD INDEX idx_certificates_student_id (student_id)',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- certificates(institution_id)
SET @idx_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'certificates' AND INDEX_NAME = 'idx_certificates_institution_id');
SET @sql = IF(@idx_exists = 0,
    'ALTER TABLE certificates ADD INDEX idx_certificates_institution_id (institution_id)',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- verification_logs(verifier_ip, verified_at)
SET @idx_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'verification_logs' AND INDEX_NAME = 'idx_vlogs_ip_time');
SET @sql = IF(@idx_exists = 0,
    'ALTER TABLE verification_logs ADD INDEX idx_vlogs_ip_time (verifier_ip, verified_at)',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- verification_logs(certificate_id_found)
SET @idx_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'verification_logs' AND INDEX_NAME = 'idx_vlogs_cert_found');
SET @sql = IF(@idx_exists = 0,
    'ALTER TABLE verification_logs ADD INDEX idx_vlogs_cert_found (certificate_id_found)',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
