-- database/migrations/002_institution_rejection.sql
-- Phase 4: institution rejection support
-- Run this in phpMyAdmin against the 'certivault' database.

USE certivault;

-- Add rejection_reason so the super admin can record WHY an institution
-- was rejected. Safe to re-run via the procedure guard below.
SET @col_exists = (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA = 'certivault' AND TABLE_NAME = 'institutions' AND COLUMN_NAME = 'rejection_reason');
SET @sql = IF(@col_exists = 0,
    'ALTER TABLE institutions ADD COLUMN rejection_reason VARCHAR(500) NULL DEFAULT NULL',
    'SELECT 1');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
