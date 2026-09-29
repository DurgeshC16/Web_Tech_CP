CREATE DATABASE IF NOT EXISTS certivault;
USE certivault;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('super_admin', 'admin', 'student') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE institutions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    public_key TEXT,
    encrypted_private_key TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE students (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    enrollment_number VARCHAR(100),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Insert a default super_admin for demo purposes
INSERT INTO users (email, password_hash, role) VALUES 
('superadmin@certivault.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'super_admin'); 
-- password is 'password'

CREATE TABLE certificates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    certificate_id VARCHAR(20) NOT NULL UNIQUE,
    institution_id INT NOT NULL,
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
    sha256_hash VARCHAR(64) NULL,
    digital_signature TEXT NULL,
    qr_token VARCHAR(255) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (institution_id) REFERENCES institutions(id),
    FOREIGN KEY (student_id) REFERENCES students(id),
    FOREIGN KEY (previous_version_id) REFERENCES certificates(id),
    FOREIGN KEY (superseded_by_id) REFERENCES certificates(id)
);

CREATE TABLE verification_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    query_type ENUM('token', 'certificate_id') NOT NULL,
    query_value VARCHAR(255) NOT NULL,
    certificate_id_found VARCHAR(20) NULL,
    result ENUM('VALID', 'TAMPERED', 'EXPIRED', 'REVOKED', 'INVALID', 'SUPERSEDED') NOT NULL,
    detail VARCHAR(255) NULL,
    verifier_ip VARCHAR(45) NOT NULL,
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
