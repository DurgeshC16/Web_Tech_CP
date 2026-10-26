-- Attested third-party credentials. Re-runnable on existing installations.
CREATE TABLE IF NOT EXISTS external_credentials (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    public_token CHAR(43) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
    student_id INT NOT NULL,
    student_name VARCHAR(255) NOT NULL,
    issuer_slug VARCHAR(300) NOT NULL,
    issuer_label VARCHAR(120) NOT NULL,
    verification_url VARCHAR(2048) NOT NULL,
    issuer_code VARCHAR(255) NULL,
    title VARCHAR(200) NOT NULL,
    issue_date DATE NOT NULL,
    file_path VARCHAR(255) NULL,
    file_sha256 CHAR(64) NULL,
    status ENUM('SELF_DECLARED','ATTESTED','WITHDRAWN') NOT NULL DEFAULT 'SELF_DECLARED',
    attesting_institution_id INT NULL,
    attesting_institution_name VARCHAR(255) NULL,
    attested_at DATETIME NULL,
    attestation_hash CHAR(64) NULL,
    signature TEXT NULL,
    withdrawn_at DATETIME NULL,
    withdrawn_by INT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_external_credentials_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
    CONSTRAINT fk_external_credentials_institution FOREIGN KEY (attesting_institution_id) REFERENCES institutions(id) ON DELETE SET NULL,
    CONSTRAINT fk_external_credentials_withdrawer FOREIGN KEY (withdrawn_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_external_credentials_queue (status, created_at),
    INDEX idx_external_credentials_student (student_id, created_at),
    INDEX idx_external_credentials_institution (attesting_institution_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @qt := (SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='verification_logs' AND COLUMN_NAME='query_type');
SET @want_qt := "enum('token','certificate_id','file','qr_image','text','external_ref','external_credential')";
SET @ddl := IF(@qt IS NOT NULL AND @qt <> @want_qt, CONCAT('ALTER TABLE verification_logs MODIFY COLUMN query_type ', @want_qt, ' NOT NULL'), 'SELECT 1');
PREPARE extcred_qt_stmt FROM @ddl; EXECUTE extcred_qt_stmt; DEALLOCATE PREPARE extcred_qt_stmt;

SET @result_type := (SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='verification_logs' AND COLUMN_NAME='result');
SET @want_result := "enum('VALID','TAMPERED','EXPIRED','REVOKED','INVALID','SUPERSEDED','EXTERNAL_FOUND','EXTERNAL_NOT_FOUND','EXTERNAL_ERROR','ATTESTED','SELF_DECLARED','WITHDRAWN')";
SET @ddl := IF(@result_type IS NOT NULL AND @result_type <> @want_result, CONCAT('ALTER TABLE verification_logs MODIFY COLUMN result ', @want_result, ' NOT NULL'), 'SELECT 1');
PREPARE extcred_result_stmt FROM @ddl; EXECUTE extcred_result_stmt; DEALLOCATE PREPARE extcred_result_stmt;
