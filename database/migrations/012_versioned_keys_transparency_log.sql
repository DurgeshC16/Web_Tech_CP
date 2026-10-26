-- Institution signing-key history and append-only certificate transparency log.
-- Existing certificates are assigned to each institution's v1 key, unchanged.

CREATE TABLE IF NOT EXISTS institution_keys (
    institution_id INT NOT NULL,
    key_id INT NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    status ENUM('active','retired') NOT NULL DEFAULT 'active',
    valid_from DATETIME NOT NULL,
    valid_to DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (institution_id, key_id),
    INDEX idx_institution_keys_status (institution_id, status),
    CONSTRAINT fk_institution_keys_institution FOREIGN KEY (institution_id) REFERENCES institutions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @has_legacy_key_cols := (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='institutions'
      AND COLUMN_NAME IN ('public_key','encrypted_private_key')
);
SET @backfill_keys_sql := IF(@has_legacy_key_cols=2,
    'INSERT IGNORE INTO institution_keys (institution_id,key_id,public_key,encrypted_private_key,status,valid_from,valid_to) SELECT i.id,1,i.public_key,i.encrypted_private_key,IF(i.status="approved","active","retired"),COALESCE(u.created_at,NOW()),IF(i.status="approved",NULL,COALESCE(u.created_at,NOW())) FROM institutions i JOIN users u ON u.id=i.user_id WHERE i.public_key IS NOT NULL AND i.encrypted_private_key IS NOT NULL AND (i.status="approved" OR EXISTS (SELECT 1 FROM certificates c WHERE c.institution_id=i.id))',
    'SELECT 1'
);
PREPARE inst_key_backfill_stmt FROM @backfill_keys_sql; EXECUTE inst_key_backfill_stmt; DEALLOCATE PREPARE inst_key_backfill_stmt;
-- If an old certificate somehow lacks key material, preserve its FK target as
-- an empty v1 marker; verification will fail closed as TAMPERED.
INSERT IGNORE INTO institution_keys (institution_id,key_id,public_key,encrypted_private_key,status,valid_from,valid_to)
SELECT i.id,1,'','',IF(i.status='approved','active','retired'),NOW(),IF(i.status='approved',NULL,NOW())
FROM institutions i JOIN certificates c ON c.institution_id=i.id
LEFT JOIN institution_keys k ON k.institution_id=i.id AND k.key_id=1
WHERE k.institution_id IS NULL;

-- Signing material has been moved into the versioned key history.
SET @has_old_pub := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='institutions' AND COLUMN_NAME='public_key');
SET @ddl := IF(@has_old_pub=1,'ALTER TABLE institutions DROP COLUMN public_key','SELECT 1');
PREPARE inst_pub_drop_stmt FROM @ddl; EXECUTE inst_pub_drop_stmt; DEALLOCATE PREPARE inst_pub_drop_stmt;
SET @has_old_priv := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='institutions' AND COLUMN_NAME='encrypted_private_key');
SET @ddl := IF(@has_old_priv=1,'ALTER TABLE institutions DROP COLUMN encrypted_private_key','SELECT 1');
PREPARE inst_priv_drop_stmt FROM @ddl; EXECUTE inst_priv_drop_stmt; DEALLOCATE PREPARE inst_priv_drop_stmt;

SET @has_key_id := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='certificates' AND COLUMN_NAME='key_id');
SET @ddl := IF(@has_key_id=0,'ALTER TABLE certificates ADD COLUMN key_id INT NOT NULL DEFAULT 1 AFTER institution_id','SELECT 1');
PREPARE cert_key_col_stmt FROM @ddl; EXECUTE cert_key_col_stmt; DEALLOCATE PREPARE cert_key_col_stmt;
UPDATE certificates SET key_id=1 WHERE key_id IS NULL OR key_id=0;

SET @has_cert_key_fk := (SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND CONSTRAINT_NAME='fk_certificates_institution_key');
SET @ddl := IF(@has_cert_key_fk=0,'ALTER TABLE certificates ADD CONSTRAINT fk_certificates_institution_key FOREIGN KEY (institution_id,key_id) REFERENCES institution_keys(institution_id,key_id)','SELECT 1');
PREPARE cert_key_fk_stmt FROM @ddl; EXECUTE cert_key_fk_stmt; DEALLOCATE PREPARE cert_key_fk_stmt;

SET @has_attesting_key := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='external_credentials' AND COLUMN_NAME='attesting_key_id');
SET @ddl := IF(@has_attesting_key=0,'ALTER TABLE external_credentials ADD COLUMN attesting_key_id INT NULL AFTER attesting_institution_id','SELECT 1');
PREPARE extcred_key_col_stmt FROM @ddl; EXECUTE extcred_key_col_stmt; DEALLOCATE PREPARE extcred_key_col_stmt;
UPDATE external_credentials SET attesting_key_id=1 WHERE status='ATTESTED' AND attesting_key_id IS NULL;
SET @has_extcred_key_fk := (SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND CONSTRAINT_NAME='fk_external_credentials_key');
SET @ddl := IF(@has_extcred_key_fk=0,'ALTER TABLE external_credentials ADD CONSTRAINT fk_external_credentials_key FOREIGN KEY (attesting_institution_id,attesting_key_id) REFERENCES institution_keys(institution_id,key_id) ON DELETE SET NULL','SELECT 1');
PREPARE extcred_key_fk_stmt FROM @ddl; EXECUTE extcred_key_fk_stmt; DEALLOCATE PREPARE extcred_key_fk_stmt;

CREATE TABLE IF NOT EXISTS tlog_entries (
    seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    certificate_id VARCHAR(64) NOT NULL,
    event_type ENUM('ISSUE','REVOKE','SUPERSEDE') NOT NULL,
    leaf_hash CHAR(64) NOT NULL,
    prev_root CHAR(64) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_tlog_certificate (certificate_id,seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tlog_checkpoints (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    tree_size BIGINT UNSIGNED NOT NULL UNIQUE,
    last_seq BIGINT UNSIGNED NOT NULL,
    root_hash CHAR(64) NOT NULL,
    signature TEXT NOT NULL,
    public_key_fingerprint CHAR(95) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @has_last_seq := (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tlog_checkpoints' AND COLUMN_NAME='last_seq');
SET @ddl := IF(@has_last_seq=0,'ALTER TABLE tlog_checkpoints ADD COLUMN last_seq BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER tree_size','SELECT 1');
PREPARE tlog_last_seq_stmt FROM @ddl; EXECUTE tlog_last_seq_stmt; DEALLOCATE PREPARE tlog_last_seq_stmt;
