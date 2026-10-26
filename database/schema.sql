CREATE DATABASE IF NOT EXISTS certivault;
USE certivault;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('super_admin', 'admin', 'student') NOT NULL,
    is_verified TINYINT(1) NOT NULL DEFAULT 0,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE otp_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    otp_code VARCHAR(64) NOT NULL,
    purpose ENUM('activation','password_reset','password_change') NOT NULL,
    expires_at DATETIME NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0,
    attempts TINYINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE institutions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    rejection_reason VARCHAR(500) DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE students (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    enrollment_number VARCHAR(100),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Versioned institution signing keys. Fingerprints are also published through
-- institutions.php and /.well-known/certivault-keys.json for external pinning.
CREATE TABLE institution_keys (
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
    FOREIGN KEY (institution_id) REFERENCES institutions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert a default super_admin for demo purposes
INSERT INTO users (email, password_hash, role, is_verified) VALUES 
('superadmin@certivault.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'super_admin', 1); 
-- password is 'password'

CREATE TABLE certificates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    certificate_id VARCHAR(64) NOT NULL UNIQUE,
    certificate_id_norm VARCHAR(64) GENERATED ALWAYS AS (LOWER(certificate_id)) STORED,
    institution_id INT NOT NULL,
    key_id INT NOT NULL DEFAULT 1,
    student_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    issue_date DATE NOT NULL,
    expiry_date DATE,
    file_path VARCHAR(255) NOT NULL,
    status ENUM('active', 'revoked', 'expired', 'superseded') DEFAULT 'active',
    version INT DEFAULT 1,
    previous_version_id INT NULL,
    superseded_by_id INT NULL,
    revocation_reason TEXT NULL,
    revoked_at DATETIME NULL DEFAULT NULL,
    revoked_by INT NULL DEFAULT NULL,
    sha256_hash VARCHAR(64) NULL,
    -- Hash of the QR-stamped copy (Smart Verify, migration 009); the
    -- ORIGINAL sha256_hash above remains the source of truth.
    stamped_sha256 CHAR(64) NULL DEFAULT NULL,
    digital_signature TEXT NULL,
    qr_token VARCHAR(255) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (institution_id) REFERENCES institutions(id),
    CONSTRAINT fk_certificates_institution_key FOREIGN KEY (institution_id, key_id) REFERENCES institution_keys(institution_id, key_id),
    FOREIGN KEY (student_id) REFERENCES students(id),
    FOREIGN KEY (previous_version_id) REFERENCES certificates(id),
    FOREIGN KEY (superseded_by_id) REFERENCES certificates(id)
);

-- Indexes (kept in sync with database/migrations/003_verification_integrity_indexes.sql)
CREATE INDEX idx_certificates_student_id ON certificates(student_id);
CREATE INDEX idx_certificates_institution_id ON certificates(institution_id);
CREATE UNIQUE INDEX uniq_certificates_qr_token ON certificates(qr_token);
CREATE UNIQUE INDEX uniq_certificates_cid_norm ON certificates(certificate_id_norm);
-- Smart Verify file-upload lookups (migration 009)
CREATE INDEX idx_cert_stamped_hash ON certificates(stamped_sha256);

CREATE TABLE verification_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    -- 'file'|'qr_image'|'text'|'external_ref' added in migration 009
    -- (Smart Verify pipeline stages).
    query_type ENUM('token', 'certificate_id', 'file', 'qr_image', 'text', 'external_ref', 'external_credential') NOT NULL,
    query_value VARCHAR(255) NOT NULL,
    certificate_id_found VARCHAR(64) NULL,
    -- EXTERNAL_* markers exist for the optional external verification
    -- sources (migration 008; feature off by default — see README).
    result ENUM('VALID', 'TAMPERED', 'EXPIRED', 'REVOKED', 'INVALID', 'SUPERSEDED',
                 'EXTERNAL_FOUND', 'EXTERNAL_NOT_FOUND', 'EXTERNAL_ERROR',
                  'ATTESTED', 'SELF_DECLARED', 'WITHDRAWN') NOT NULL,
    detail VARCHAR(255) NULL,
    verifier_ip VARCHAR(45) NOT NULL,
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_vlogs_ip_time ON verification_logs(verifier_ip, verified_at);
CREATE INDEX idx_vlogs_cert_found ON verification_logs(certificate_id_found);

-- Persistent "Remember me" logins (see database/migrations/005_remember_me_tokens.sql).
-- Cookie holds "selector:validator"; only SHA-256(validator) is stored.
CREATE TABLE remember_tokens (
    selector VARCHAR(24) NOT NULL PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL,
    user_id INT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_remember_tokens_user_id ON remember_tokens(user_id);
CREATE INDEX idx_remember_tokens_expires_at ON remember_tokens(expires_at);

-- Login rate limiting per email + IP (see database/migrations/006_login_rate_limit.sql).
CREATE TABLE login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    ip VARCHAR(45) NOT NULL,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_login_attempts_email_ip_time ON login_attempts(email, ip, attempted_at);

-- Managed external registry (migration 010); rows are disabled by default.
CREATE TABLE IF NOT EXISTS external_sources (
    id INT AUTO_INCREMENT PRIMARY KEY,
    slug VARCHAR(64) NOT NULL UNIQUE,
    label VARCHAR(120) NOT NULL,
    type ENUM('open_badges','remote_db') NOT NULL,
    config_json LONGTEXT NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    allowed_host VARCHAR(255) NOT NULL,
    rate_limit SMALLINT UNSIGNED NOT NULL DEFAULT 15,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_external_sources_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Student-declared third-party credentials and institutional attestations (migration 011).
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
    attesting_key_id INT NULL,
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
    CONSTRAINT fk_external_credentials_key FOREIGN KEY (attesting_institution_id,attesting_key_id) REFERENCES institution_keys(institution_id,key_id) ON DELETE SET NULL,
    CONSTRAINT fk_external_credentials_withdrawer FOREIGN KEY (withdrawn_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_external_credentials_queue (status, created_at),
    INDEX idx_external_credentials_student (student_id, created_at),
    INDEX idx_external_credentials_institution (attesting_institution_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Append-only transparency event log. issued_at is certificates.created_at.
CREATE TABLE tlog_entries (
    seq BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    certificate_id VARCHAR(64) NOT NULL,
    event_type ENUM('ISSUE','REVOKE','SUPERSEDE') NOT NULL,
    leaf_hash CHAR(64) NOT NULL,
    prev_root CHAR(64) NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_tlog_certificate (certificate_id, seq)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tlog_checkpoints (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    tree_size BIGINT UNSIGNED NOT NULL UNIQUE,
    last_seq BIGINT UNSIGNED NOT NULL,
    root_hash CHAR(64) NOT NULL,
    signature TEXT NOT NULL,
    public_key_fingerprint CHAR(95) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
