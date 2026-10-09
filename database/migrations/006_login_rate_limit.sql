-- database/migrations/006_login_rate_limit.sql
-- Login rate limiting per email + IP: 5 failed attempts within 15 minutes
-- lock that email+IP pair for the remainder of the window. This complements
-- (not replaces) the per-account users.failed_login_attempts backstop.
-- Safe to re-run: uses CREATE TABLE IF NOT EXISTS + index guard.
-- Run this in phpMyAdmin against the 'certivault' database.

USE certivault;

CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- login_attempts(email, ip, attempted_at)
SET @idx_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'login_attempts' AND INDEX_NAME = 'idx_login_attempts_email_ip_time');
SET @sql = IF(@idx_exists = 0,
    'ALTER TABLE login_attempts ADD INDEX idx_login_attempts_email_ip_time (email, ip, attempted_at)',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
