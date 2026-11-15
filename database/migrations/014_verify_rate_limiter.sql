-- database/migrations/014_verify_rate_limiter.sql
-- Bounded state for the public verification rate limiter.
--
-- Why: the limiter used to run COUNT(DISTINCT query_value) over the whole
-- verification_logs history of an IP. Its cost grows with request history
-- (measured 3.8 ms -> 54.7 ms at 30 000 logged rows), so one client could
-- slow every check down. This table holds at most VERIFY_RATE_MAX (30)
-- live rows per IP; verification_logs stays the full audit trail.
--
-- value_hash = SHA-256 of the lookup key (never the raw input).
-- Safe to re-run.

CREATE TABLE IF NOT EXISTS verify_rate (
    ip VARCHAR(45) NOT NULL,
    value_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ip, value_hash),
    INDEX idx_verify_rate_seen (seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
