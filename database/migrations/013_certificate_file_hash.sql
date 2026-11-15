-- database/migrations/013_certificate_file_hash.sql
-- Raw SHA-256 of the stored certificate file, so Smart Verify can match an
-- uploaded copy of the ORIGINAL file (and the browser privacy-mode hash).
--
-- Why: certificates.sha256_hash is the CANONICAL digest
--   SHA-256(id|institution|student|title|issued|expires|SHA-256(file))
-- and can never equal the hash of the file alone, so the old byte-hash
-- lookup never matched a really issued certificate.
--
-- After applying, back-fill existing rows once:
--   php scripts/backfill_file_hashes.php
--
-- Safe to re-run: every ALTER is guarded.

SET @has_col := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'certificates'
      AND COLUMN_NAME  = 'file_sha256'
);
SET @ddl := IF(@has_col = 0,
    'ALTER TABLE certificates ADD COLUMN file_sha256 CHAR(64) NULL DEFAULT NULL AFTER sha256_hash',
    'SELECT 1 AS nothing_to_do');
PREPARE fh_col_stmt FROM @ddl;
EXECUTE fh_col_stmt;
DEALLOCATE PREPARE fh_col_stmt;

SET @has_idx := (
    SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME   = 'certificates'
      AND INDEX_NAME   = 'idx_cert_file_sha256'
);
SET @ddl := IF(@has_idx = 0,
    'ALTER TABLE certificates ADD INDEX idx_cert_file_sha256 (file_sha256)',
    'SELECT 1 AS nothing_to_do');
PREPARE fh_idx_stmt FROM @ddl;
EXECUTE fh_idx_stmt;
DEALLOCATE PREPARE fh_idx_stmt;
