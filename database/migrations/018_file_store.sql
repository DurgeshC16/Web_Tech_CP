-- database/migrations/018_file_store.sql
-- Durable copies of runtime files (src/services/FileStore.php), used ONLY
-- when CV_FILE_STORE=db — hosts with an ephemeral filesystem such as the
-- Render free plan (docs/13_DEPLOY_RENDER.md). With the default setting the
-- table simply stays empty.
--
--   path       file path relative to the repository root, e.g.
--              private_data/uploads/CV-2026-000001_<hex>.pdf,
--              public/qrcodes/<token>.png, private_data/pins/<db>.json
--   content    the exact bytes of the file
--   sha256     SHA-256 of content (restore skips files that already match)
--   size       length of content in bytes
--
-- scripts/render_boot.php writes every row back to disk at container start.
-- Large uploads need max_allowed_packet >= the biggest file (8 MB uploads;
-- MySQL 8 defaults to 64 MB).
-- Safe to re-run.

CREATE TABLE IF NOT EXISTS stored_files (
    path VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    content LONGBLOB NOT NULL,
    sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    size BIGINT UNSIGNED NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (path)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
