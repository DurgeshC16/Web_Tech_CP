-- Managed external-source registry. Re-runnable on fresh and existing installs.
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
