-- database/migrations/008_external_verification_source.sql
-- ─────────────────────────────────────────────────────────────────────
-- Widen the verification_logs.result ENUM with the EXTERNAL_* markers
-- used when the optional external verification sources (v. 1.1 feature)
-- are enabled (they are OFF by default; see README).
-- Safe to re-run: the ALTER only fires when the values are absent.
-- ─────────────────────────────────────────────────────────────────────

SET @coltype := (
    SELECT COLUMN_TYPE FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'verification_logs'
      AND COLUMN_NAME  = 'result'
);
SET @desired := CONCAT(
    "enum('VALID','TAMPERED','EXPIRED','REVOKED','INVALID','SUPERSEDED',",
         "'EXTERNAL_FOUND','EXTERNAL_NOT_FOUND','EXTERNAL_ERROR')"
);
SET @ddl := IF(@coltype IS NOT NULL AND @coltype <> @desired,
    'ALTER TABLE verification_logs MODIFY COLUMN result ',
    'SELECT 1 AS nothing_to_do');
SET @ddl := IF(@coltype IS NOT NULL AND @coltype <> @desired,
    CONCAT(@ddl, @desired, ' NOT NULL'),
    @ddl);
PREPARE ext_stmt FROM @ddl;
EXECUTE ext_stmt;
DEALLOCATE PREPARE ext_stmt;
