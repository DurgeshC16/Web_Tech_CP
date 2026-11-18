# 03 — Database

Database name: **`certivault`** (15 tables; MySQL 8 / MariaDB 10.4+, InnoDB; every table `utf8mb4` / `utf8mb4_unicode_ci`).
`database/schema.sql` always contains the **full current schema**; the files
in `database/migrations/` upgrade an older existing database step by step.

## 1. Entity overview

```
users ──1:1── institutions ──1:N── institution_keys (versioned RSA keys)
  │                │
  │                └──1:N── certificates ──N:1── students ──1:1── users
  │                             │  ▲ previous_version_id / superseded_by_id (self)
  ├──1:N── otp_codes            │
  ├──1:N── remember_tokens      └── (by certificate_id) verification_logs, tlog_entries
  └── login_attempts (by email+ip)

students ──1:N── external_credentials ──N:1── institutions (attesting)
external_sources (managed registry) · tlog_checkpoints (signed Merkle roots) · verify_rate (rate limiter)
```

## 2. Tables

### Accounts & authentication

| Table | Purpose | Key columns |
|-------|---------|-------------|
| `users` | Every account | `email` (unique), `password_hash` (bcrypt), `role` ∈ {super_admin, admin, student}, `is_verified`, `failed_login_attempts`, `locked_until`, `totp_secret` (AES-GCM encrypted), `totp_enabled`, `totp_last_step` (2FA replay guard) |
| `students` | Student profile | `user_id` → users, `full_name`, `enrollment_number` |
| `institutions` | Institution profile | `user_id` → users, `name`, `status` ∈ {pending, approved, rejected}, `rejection_reason` |
| `otp_codes` | Email one-time codes | `otp_code` (HMAC-SHA-256 hash, never plaintext), `purpose` ∈ {activation, password_reset, password_change}, `expires_at`, `used`, `attempts` |
| `remember_tokens` | "Remember me" logins | `selector` (PK), `token_hash` = SHA-256(validator), `expires_at` |
| `login_attempts` | Failed-login rate limiting | `email`, `ip`, `attempted_at` |
| `user_recovery_codes` | 2FA recovery codes (migration 015) | `user_id`, `code_hash` (HMAC-SHA-256 only), `used_at` (single use) |

### Certificates & keys

| Table | Purpose | Key columns |
|-------|---------|-------------|
| `institution_keys` | Versioned RSA key pairs | PK (`institution_id`, `key_id`), `public_key` (PEM), `encrypted_private_key` (`GCM1.` blob), `status` ∈ {active, retired}, `valid_from`, `valid_to` |
| `certificates` | Issued certificates | `certificate_id` (unique; `certificate_id_norm` generated lower-case unique), `institution_id`, `key_id`, `student_id`, `title`, `issue_date`, `expiry_date`, `file_path`, `status` ∈ {active, revoked, expired, superseded}, `version`, `previous_version_id`, `superseded_by_id`, `revocation_reason`, `revoked_at`, `revoked_by`, `sha256_hash` (canonical digest), `file_sha256` (raw file hash, for file-upload matching), `stamped_sha256`, `digital_signature` (base64), `qr_token` (unique) |
| `guest_verify_quota` | Guest verification quota (migration 017); raw IPs are never stored | PK (`subject_hash`, `key_hash`), `is_credit`, `seen_at`; pruned after the window |
| `stored_files` | Durable copies of runtime files (migration 018), used only with `CV_FILE_STORE=db` (e.g. Render free plan) | PK `path` (relative to the repo root), `content` (LONGBLOB), `sha256`, `size`, `updated_at`; empty in the default mode |
| `verify_rate` | Rate-limiter state (migration 014) | PK (`ip`, `value_hash` = SHA-256 of the lookup key), `seen_at`; at most 30 live rows per IP |
| `verification_logs` | Audit trail of every lookup | `query_type` ∈ {token, certificate_id, file, qr_image, text, external_ref, external_credential}, `query_value`, `certificate_id_found`, `result` (VALID … WITHDRAWN), `detail`, `verifier_ip`, `verified_at` |

### Optional features

| Table | Feature | Notes |
|-------|---------|-------|
| `external_sources` | Managed external registry (migration 010) | `type` ∈ {open_badges, remote_db}; `config_json` stored AES-256-GCM-encrypted (`CFG1.`); disabled by default |
| `external_credentials` | Attested third-party credentials (migration 011) | `public_token`, issuer + URL + code, optional file + SHA-256, `status` ∈ {SELF_DECLARED, ATTESTED, WITHDRAWN}, attesting institution/key, `attestation_hash`, `signature` |
| `tlog_entries` | Append-only transparency log (migration 012) | `seq`, `certificate_id`, `event_type` ∈ {ISSUE, REVOKE, SUPERSEDE}, `leaf_hash`, `prev_root` |
| `tlog_checkpoints` | Signed Merkle checkpoints (migration 012) | `tree_size`, `last_seq`, `root_hash`, `signature`, `public_key_fingerprint` |

### Indexes worth knowing

* `uniq_certificates_qr_token`, `uniq_certificates_cid_norm` — O(1) lookup by
  token / case-insensitive ID (measured flat latency up to 100 000 rows).
* `idx_vlogs_ip_time (verifier_ip, verified_at)` — rate-limit window query.
* `idx_login_attempts_email_ip_time` — login lockout window.
* `idx_cert_file_sha256`, `idx_cert_stamped_hash` — Smart Verify file-upload lookups.
* `verify_rate` PK (`ip`, `value_hash`) — constant-cost rate-limit check.

## 3. Seed data

`schema.sql` seeds one super admin, `superadmin@certivault.com`, with an
**unusable password hash** — nobody can log in as super admin until you run
`php scripts/set_super_admin.php`, which sets a real email (OTP flows need a
real mailbox) and password. `php scripts/seed_demo.php` adds a demo institution,
student and certificates (see doc 06).

## 4. Migrations

Use `schema.sql` for a **fresh** install — it already includes everything
below. For an **existing** database, apply the migrations you are missing,
in order. They are written to be idempotent (guarded `ALTER`s /
`IF NOT EXISTS`) and safe to re-run.

| # | File | Adds |
|---|------|------|
| 001 | `001_otp_hardening.sql` | OTP attempts counter, hashed code width, purpose enum |
| 002 | `002_institution_rejection.sql` | `institutions.rejection_reason`, `rejected` status |
| 003 | `003_verification_integrity_indexes.sql` | Hardening indexes, unique `qr_token` |
| 004 | `004_revocation_audit.sql` | `revoked_at`, `revoked_by` |
| 005 | `005_remember_me_tokens.sql` | `remember_tokens` table |
| 006 | `006_login_rate_limit.sql` | `login_attempts` table |
| 007 | `007_flexible_certificate_id.sql` | Wider IDs, generated `certificate_id_norm` + unique index (custom IDs) |
| 008 | `008_external_verification_source.sql` | `EXTERNAL_*` verdicts in `verification_logs` |
| 009 | `009_smart_verify_enum.sql` | `file`/`qr_image`/`text`/`external_ref` query types, `stamped_sha256` |
| 010 | `010_external_sources_registry.sql` | `external_sources` table |
| 011 | `011_attested_external_credentials.sql` | `external_credentials` table + verdicts |
| 012 | `012_versioned_keys_transparency_log.sql` | `institution_keys` — moves `public_key` / `encrypted_private_key` out of `institutions` (existing keys become v1, certificates are **not** re-signed), `certificates.key_id`, `tlog_entries`, `tlog_checkpoints` |
| 013 | `013_certificate_file_hash.sql` | `certificates.file_sha256` + index. Afterwards run `php scripts/backfill_file_hashes.php` once |
| 014 | `014_verify_rate_limiter.sql` | `verify_rate` table (bounded rate-limiter state) |
| 015 | `015_two_factor_auth.sql` | `users.totp_*` columns + `user_recovery_codes` (2FA) |
| 017 | `017_guest_verify_quota.sql` | `guest_verify_quota` table: PK (`subject_hash` = keyed hash of the IP or session, `key_hash` = SHA-256 of the lookup), `is_credit`, `seen_at` — guest verification quota (5 / 24 h) |
| 016 | `016_unify_collation.sql` | Converts the original tables to `utf8mb4_unicode_ci` (mixed collations broke cross-table comparisons on MariaDB 10.11). Rebuilds tables — run in a quiet moment |
| 018 | `018_file_store.sql` | `stored_files` table for `CV_FILE_STORE=db` ([13 Deploy on Render](13_DEPLOY_RENDER.md)). In the Docker image, `scripts/render_boot.php` applies 017 + 018 automatically at start-up (both are `CREATE TABLE IF NOT EXISTS`) |

Run them in phpMyAdmin (Import tab, select the `certivault` database) or:

```sh
# apply every migration in order (all are re-runnable)
for f in database/migrations/*.sql; do mysql -u root certivault < "$f"; done
```
