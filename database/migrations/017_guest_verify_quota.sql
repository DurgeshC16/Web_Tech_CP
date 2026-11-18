-- database/migrations/017_guest_verify_quota.sql
-- Free-verification quota for visitors who are not logged in
-- (GuestQuotaService, GUEST_VERIFY_LIMIT / GUEST_VERIFY_WINDOW).
--
-- One row per (client, lookup key) seen in the rolling window:
--   subject_hash = HMAC-SHA256 of the client IP under a server-side derived
--                  key (the raw IP is never stored here)
--   key_hash     = SHA-256 of the lookup key (token, typed ID, file hash,
--                  or a "cert:<id>" alias) — never the raw input
--   is_credit    = 1 for the row that consumed a free verification,
--                  0 for free alias rows (same certificate, PDF report …)
-- Bounded like verify_rate (migration 014): stale rows are pruned on every
-- check, and at most limit + 50 live rows are kept per client.
-- Without this table the IP counter fails open (the per-session counter
-- still applies), so applying it late never breaks verification.
-- Safe to re-run.

CREATE TABLE IF NOT EXISTS guest_verify_quota (
    subject_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    key_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    is_credit TINYINT(1) NOT NULL DEFAULT 1,
    seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (subject_hash, key_hash),
    INDEX idx_guest_verify_quota_seen (seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
