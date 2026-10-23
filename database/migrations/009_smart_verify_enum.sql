-- database/migrations/009_smart_verify.sql
-- ─────────────────────────────────────────────────────────────────────
-- Smart Verify (Phase 1):
--   1. verification_logs.query_type gains the smart-verify pipeline
--      sources: 'file', 'qr_image', 'text', 'external_ref'.
--   2. certificates gains stamped_sha256 (hash of the QR-stamped copy;
--      the ORIGINAL sha256_hash remains the source of truth). Both are
--      accepted when a verifier uploads a file to verify.php.
-- Safe to re-run: guarded by INFORMATION_SCHEMA checks.
-- ─────────────────────────────────────────────────────────────────────

SET @qt := (
    SELECT COLUMN_TYPE FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'verification_logs'
      AND COLUMN_NAME  = 'query_type'
);
SET @want_qt := "enum('token','certificate_id','file','qr_image','text','external_ref')";
SET @ddl := IF(@qt IS NOT NULL AND @qt <> @want_qt,
    'ALTER TABLE verification_logs MODIFY COLUMN query_type ',
    'SELECT 1 AS nothing_to_do');
SET @ddl := IF(@qt IS NOT NULL AND @qt <> @want_qt,
    CONCAT(@ddl, @want_qt, ' NOT NULL'),
    @ddl);
PREPARE sv_qt_stmt FROM @ddl;
EXECUTE sv_qt_stmt;
DEALLOCATE PREPARE sv_qt_stmt;

SET @has_stamped := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'certificates'
      AND COLUMN_NAME  = 'stamped_sha256'
);
SET @ddl := IF(@has_stamped = 0,
    'ALTER TABLE certificates ADD COLUMN stamped_sha256 CHAR(64) NULL DEFAULT NULL AFTER sha256_hash',
    'SELECT 1 AS nothing_to_do');
PREPARE sv_hash_stmt FROM @ddl;
EXECUTE sv_hash_stmt;
DEALLOCATE PREPARE sv_hash_stmt;

SET @has_idx := (
    SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'certificates'
      AND INDEX_NAME   = 'idx_cert_stamped_hash'
);
SET @ddl := IF(@has_idx = 0,
    'ALTER TABLE certificates ADD INDEX idx_cert_stamped_hash (stamped_sha256)',
    'SELECT 1 AS nothing_to_do');
PREPARE sv_idx_stmt FROM @ddl;
EXECUTE sv_idx_stmt;
DEALLOCATE PREPARE sv_idx_stmt;
