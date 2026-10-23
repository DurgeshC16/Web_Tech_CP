-- database/migrations/005_remember_me_tokens.sql
-- Persistent "Remember me" logins: selector + SHA-256(hashed validator).
-- The cookie holds "selector:validator"; only the hash is stored, so the
-- DB alone can never mint a cookie. No user id or password ever touches
-- a cookie.
-- Safe to re-run: uses CREATE TABLE IF NOT EXISTS + index guards.
-- Run this in phpMyAdmin against the 'certivault' database.

USE certivault;

CREATE TABLE IF NOT EXISTS remember_tokens (
    selector VARCHAR(24) NOT NULL PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL,
    user_id INT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- remember_tokens(user_id)
SET @idx_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'remember_tokens' AND INDEX_NAME = 'idx_remember_tokens_user_id');
SET @sql = IF(@idx_exists = 0,
    'ALTER TABLE remember_tokens ADD INDEX idx_remember_tokens_user_id (user_id)',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- remember_tokens(expires_at)
SET @idx_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'remember_tokens' AND INDEX_NAME = 'idx_remember_tokens_expires_at');
SET @sql = IF(@idx_exists = 0,
    'ALTER TABLE remember_tokens ADD INDEX idx_remember_tokens_expires_at (expires_at)',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
