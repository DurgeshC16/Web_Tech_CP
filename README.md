# Web Technology Course Project

A web technology course project developed as part of the Web Technology curriculum.  
The project demonstrates the use of front-end development, back-end/database integration, and web application concepts.

## Project Overview

This project is developed using modern web development technologies and is organized into separate sections for the application source code, public assets, and database-related files.

The main objective of the project is to apply concepts learned in Web Technology, including:

- Web page design and structure
- Styling and responsive layouts
- Client-side scripting
- Server-side development
- Database integration
- CRUD operations
- Form handling and validation
- Dynamic web application development

## Technologies Used

- HTML5
- CSS3
- JavaScript
- PHP
- MySQL
- XAMPP
- Git & GitHub

## Project Structure

```text
Web_Tech_CP/
├── database/
│   └── Database-related files
├── public/
│   └── Publicly accessible files and assets
├── src/
│   └── Main source code of the application
└── README.md
```

# Email setup

OTP codes are delivered by email via SMTP using PHPMailer (vendored at
`src/utils/PHPMailer/`, mirroring the `src/utils/phpqrcode/` pattern — no
Composer required). Configure it with environment variables:

- `SMTP_HOST`, `SMTP_PORT` (default `587`), `SMTP_USERNAME`, `SMTP_PASSWORD`
- `SMTP_ENCRYPTION` (default `tls`; use `ssl` with port `465`)
- `SMTP_FROM_EMAIL`, `SMTP_FROM_NAME` (default `CertiVault`)

For local development, do **not** rely on OS environment variables — XAMPP/Apache on Windows doesn't reliably pass them to PHP. Instead:

1. Copy the example override file:
   ```
   copy src\config\config.local.php.example src\config\config.local.php
   ```
2. Fill in the real values in `src/config/config.local.php` (it's gitignored, so credentials never get committed). `config.php` loads it automatically when present, and its values win over the env-var fallbacks.
3. Restart Apache so the new settings are picked up.

**Gmail:** set `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_ENCRYPTION=tls`.
`SMTP_PASSWORD` must be a **16-character Google App Password**, not your normal
Gmail password — generate one at <https://myaccount.google.com/apppasswords>
after enabling 2-Step Verification. A regular Gmail password will be rejected
by Google's SMTP servers.

If you'd rather use real environment variables (e.g. on Linux/hosted servers), set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_ENCRYPTION` (default `tls`; use `ssl` with port `465`), `SMTP_FROM_EMAIL`, and `SMTP_FROM_NAME` (default `CertiVault`) — they're picked up as fallbacks when no `config.local.php` exists.

**Working SMTP credentials are required.** OTP codes are delivered exclusively
by email — they are never displayed on screen. Without valid SMTP configuration,
users will not be able to receive verification codes and complete account
activation. Use `php scripts/smtp_diagnostic.php someone@example.com` to verify
your SMTP setup before running the application.

## Email setup (Gmail App Password)

1. Copy the local override file (it is gitignored — credentials never get
   committed):
   ```
   copy src\config\config.local.php.example src\config\config.local.php
   ```
2. Fill in these values in `src/config/config.local.php`:
   - `SMTP_USERNAME` — your full Gmail address, e.g. `you@gmail.com`
   - `SMTP_PASSWORD` — a **16-character App Password** (NOT your Gmail
     login password; generate one at <https://myaccount.google.com/apppasswords>
     after enabling 2-Step Verification)
   - `SMTP_FROM_EMAIL` — the same Gmail address
   (`SMTP_HOST`/`SMTP_PORT`/`SMTP_ENCRYPTION` ship as
   `smtp.gmail.com`/`587`/`tls` and need no change.)
3. Verify: `php scripts/smtp_diagnostic.php you@gmail.com` — it also prints
   which source every SMTP value came from (local file, env var or default);
   the password is never shown.
4. Restart Apache if it was already running.

Without credentials the app shows "Email delivery is not set up on this
server. Contact the administrator." (when `CV_DEBUG=true` on a dev server,
the message instead points at `config.local.php` and the offline
`private_data/dev_mail.log` fallback). `config.local.php` values win over
env vars, which win over the `config.php` defaults. In production set real
env vars instead.

## Email troubleshooting — OTP / activation emails don't arrive

The SMTP diagnostic prints PASS/FAIL for every stage of the email path
(config, OpenSSL, connection, TLS + authentication, test send):

```
php scripts/smtp_diagnostic.php someone@example.com
```

Common causes, matched to the stage that fails:

- **Stage 1 FAIL** — `SMTP_USERNAME`/`SMTP_PASSWORD` are empty. The app then
  shows "Email delivery is not set up on this server. Contact the
  administrator." instead of pretending a code was sent.
- **Stage 3 FAIL** — wrong host/port, firewall block, or Gmail unreachable.
  Use `smtp.gmail.com:587` with `SMTP_ENCRYPTION=tls`.

### Gmail App Password setup (stage 4 "authentication failed" fixes)

Google rejects regular Gmail passwords on SMTP. You must use an **App Password**
(16 characters) — and that requires 2-Step Verification:

1. Visit <https://myaccount.google.com/security> and turn on
   **2-Step Verification** (this is mandatory; App Passwords are not
   offered without it).
2. Go to <https://myaccount.google.com/apppasswords>.
3. Give the key a name (e.g. "CertiVault dev") and click **Create**.
4. Google shows a **16-character password** (like `abcd efgh ijkl mnop` —
   spaces are just display grouping). Copy it.
5. Put it in `src/config/config.local.php` as `SMTP_PASSWORD` **without
   spaces**:
   ```php
   define('SMTP_USERNAME', 'yourname@gmail.com');
   define('SMTP_PASSWORD', 'abcdefghijklmnop');
   define('SMTP_HOST', 'smtp.gmail.com');
   define('SMTP_PORT', 587);
   define('SMTP_ENCRYPTION', 'tls');
   define('SMTP_FROM_EMAIL', 'yourname@gmail.com');
   ```
6. Restart Apache (or your PHP built-in server) and re-run
   `php scripts/smtp_diagnostic.php <your-email>` — stage 4 must now PASS.

Other Gmail gotchas:

- **"Password command failed 534-5.7.9 / 535-5.7.8"** in the logs = wrong
  password: you used the account password, or an App Password with the
  spaces left in, or 2-Step Verification is off.
- New App Passwords can take a minute to become active; retry if stage 4
  still fails immediately after creating one.
- The app **logs the specific SMTP cause** (authentication failed,
  connection refused, TLS error) using PHPMailer's `ErrorInfo` — check
  `private_data/php_errors.log`.

### Testing the flow without a mail server (development only)

With `define('CV_DEBUG', true);` or `define('CV_DEV_SHOW_OTP', true);` in
`config.local.php` (never with `CV_ENV=production`), every OTP delivery is
also appended to `private_data/dev_mail.log` (outside the web root) with
the recipient and plaintext code, so registration → activation → password
reset can be tested locally with no SMTP configured at all. Failed sends
never start the 60-second resend cooldown or consume the 5-per-hour quota —
only successful attempts count.

# Setup

1. **Clone** the repository into your XAMPP `htdocs` folder.
2. **Folders** — `public/qrcodes/`, `private_data/`, and `private_data/uploads/` are committed as empty directories (via committed `.gitkeep` placeholder files), so a fresh clone works out of the box. If they are missing for any reason, create them manually:
   ```
   mkdir public/qrcodes private_data private_data/uploads
   ```
3. **Database** — import `database/schema.sql` into MySQL (e.g. via phpMyAdmin or `mysql -u root < database/schema.sql`). It creates the `certivault` database, all tables, and a seeded super admin.
4. **Configuration** — all settings are read from environment variables (see `src/config/config.php`):
   - `CV_DB_HOST`, `CV_DB_USER`, `CV_DB_PASS`, `CV_DB_NAME`
   - `CV_BASE_URL`
   - `CV_ENCRYPTION_KEY`
   - `CV_ENV` (set to `production` in production; anything else is treated as local dev)

    The committed defaults (localhost, root, empty password, `certivault`) work for a standard local XAMPP setup, so env vars are optional locally.
5. **Document root** — point Apache/XAMPP at the `/public` directory (e.g. `http://localhost/<repo>/public`), not the repo root.

### Base URL (QR codes, share links, activation emails)

`BASE_URL` is derived automatically per request (scheme + host + port + path
up to `/public`), so in most layouts there is **nothing to configure**:

- **XAMPP on port 80**, app at `http://localhost/certivault/public` → derived as-is. No setting needed.
- **PHP built-in server with docroot `public`** (`php -S localhost:8081 -t public`), app at `http://localhost:8081/verify.php` → derived as `http://localhost:8081`. No setting needed.
- **Built-in server with docroot at the repo root**, app at `http://localhost:8081/certivault/public` → derived as-is.

Set it explicitly only to *force* a value (reverse proxy, public hostname
differs from the request host): via the `CV_BASE_URL` environment variable,
or in `src/config/config.local.php` with `define('CV_BASE_URL',
'http://localhost/certivault/public');` (no trailing slash). CLI scripts
(`seed_demo.php`, etc.) have no request to derive from and fall back to
`http://localhost:8081/certivault/public` unless `CV_BASE_URL` is set.

After that, register an institution, have the super admin approve it, and you can issue certificates.

## Troubleshooting uploads

Certificate uploads (Issue / Supersede) accept PDF, PNG, JPG up to **5 MB**.
If uploads fail, run the environment audit first — CLI, or in the browser
as an admin (anonymous visitors are redirected to login):

```
php scripts/check_environment.php
http://localhost/<repo>/scripts/check_environment.php
```

It prints PASS/FAIL for every dependency with the exact fix. The usual
cause is PHP's own limits in `C:\xampp\php\php.ini`:

```ini
file_uploads = On
upload_max_filesize = 8M
post_max_size = 10M
extension=fileinfo
extension=gd
```

`post_max_size` must be larger than `upload_max_filesize` (it covers the
file plus all form fields). **Restart Apache after every php.ini change**,
otherwise the old values stay in effect. Other checklist items:

- `private_data/uploads/`, `public/qrcodes/`, and
  `src/utils/phpqrcode/cache/` must exist and be writable by the Apache/PHP
  user (the app self-creates the first two with `mkdir(..., 0755, true)` and
  reports a clear error when a directory is missing or read-only).
- Files over 5 MB are rejected by design: the form sends
  `MAX_FILE_SIZE=5242880`, `validation.js` blocks them client-side, and
  `v_upload()` enforces the cap server-side (the server is authoritative).
- If the whole POST body exceeds `post_max_size`, PHP empties
  `$_POST`/`$_FILES`; the app detects this before CSRF validation and shows
  an explanatory message instead of a 403.


## Phase 4 Notes

### Setting the super admin credentials
The seeded superadmin@certivault.com row is not a real mailbox, so OTP-based flows can never reach it. Use the CLI script to set the real email + password (password is read from the terminal prompt and stored with password_hash()):

`ash
php scripts/set_super_admin.php
`

### Database migrations
Run each new file in phpMyAdmin against the certivault database:
- database/migrations/001_otp_hardening.sql (Phase 2)
- database/migrations/002_institution_rejection.sql (Phase 4 � adds institutions.rejection_reason)

### Cookies set by the app
- PHPSESSID � login session (HttpOnly, SameSite=Strict, Secure on HTTPS)
- cv_email � remembered login email, 30 days (HttpOnly, SameSite=Strict, Secure on HTTPS). Email only, never a token.
- cv_theme � theme preference light/dark, 1 year (SameSite=Strict, Secure on HTTPS)


### Phase 5 notes
- APP_ENCRYPTION_KEY must be set to a strong value via CV_ENCRYPTION_KEY BEFORE the first institution is approved � it encrypts institution RSA private keys at rest, and rotating it later would break signing. In production (CV_ENV=production) the app refuses to boot with the committed defaults for APP_ENCRYPTION_KEY, SHARE_LINK_SECRET (CV_SHARE_SECRET), or OTP_PEPPER (CV_OTP_PEPPER). Do NOT re-encrypt existing data.
- Migrations to run in phpMyAdmin:  03_verification_integrity_indexes.sql,  04_revocation_audit.sql.

## External verification sources (optional, OFF by default)
verify.php falls back to configured *external* sources when an ID is not
found in CertiVault. A hit is shown in a clearly separate card:

> **Found in external source: \<name\>** — *CertiVault has not verified this
> record's signature. Treat it as unverified information from the source
> named above.*

An external record is **never** marked VALID by CertiVault's pipeline; the
local verdict stays `INVALID` and the external content is advisory only.

**Two adapters** (`src/services/ExternalSourceService.php`):

1. `OpenBadgesAdapter` — fetches an Open Badges 2.0 assertion JSON from a
   `https://…/{id}.json` URL template and validates it: `type: Assertion`,
   valid `issuedOn`, a `recipient` with a (typically `hashed`) identity,
   and the boolean `revoked` flag. `EXT_OB_SOURCE_NAME` overrides the
   displayed source name.
2. `RemoteDbAdapter` — a second PDO connection (`EXT_DB_DSN`, user must be
   READ-ONLY) against a configurable table/view (`EXT_DB_TABLE` and the
   `EXT_DB_*_COLUMN` names). Column/table names are interpolated into SQL
   because identifiers cannot be bound — they are strictly validated
   (`[A-Za-z_][A-Za-z0-9_]*`), and IDs are always bound as prepared-statement
   parameters.

**Security controls:** HTTPS-only (including redirect hops), host
allow-list (`EXT_ALLOWED_HOSTS`), SSRF guard (all A/AAAA records of the
host must be public — private/loopback/link-local/CGNAT ranges are
blocked, redirects are re-validated on every hop), 5-second timeout,
1 MB response cap, JSON schema validation, 10-minute cache
(`private_data/cache/external/`), per-IP external-lookup rate limit
(`EXT_RATE_LIMIT`, default 15 / 10 min), all output escaped, and every
external attempt logged to `verification_logs` as `EXTERNAL_FOUND` /
`EXTERNAL_NOT_FOUND` / `EXTERNAL_ERROR` (run migration 008 first;
without it the row falls back to an `INVALID` + `[external] …` detail).

**Enable the offline MySQL demo:** first apply migration 010, then run
`php scripts/seed_external_source.php` and set `EXT_REGISTRY_ENABLED` to true
in local configuration. It creates the `DEMO MOOC registry` managed source
and ten fictional records (`DEMO-MOOC-001` through `DEMO-MOOC-010`).

**Limitation:** CertiVault cannot cryptographically verify records it does
not hold — hashes, signatures and files only exist for locally issued
certificates. The external card is explicitly labelled *unverified by
CertiVault*; verifiers who need certainty must use local verification or
contact the named source. For hosted Open Badges sources, `EXT_ALLOWED_HOSTS`
must list exactly the CDN host(s) you trust. To enable a real hosted
source, set `EXT_OB_URL_TEMPLATE` and keep `EXT_SOURCE_ENABLED` true.

## Smart Verify, trust score, report & status API (Phases 1–3)
- **Smart Verify** (`verify.php`, ON by default, `CV_SMART_VERIFY=0` to
  disable): one panel accepts ANY of — certificate ID in any format, QR
  token, full self-verification URL, QR-image upload, or the certificate
  FILE itself (PDF/PNG/JPG ≤5 MB) — plus a privacy toggle that hashes the
  file in the browser (`crypto.subtle`) so bytes never leave the device.
  **Either/or inputs:** at least ONE of the ID box / file field must be
  provided — submitting with neither shows the shared message "Enter a
  certificate ID or upload a certificate file." (no per-field errors);
  when BOTH are provided the file/hash pipeline resolves first and the
  ID becomes the fallback ("Both provided: checking the file first, then
  the ID."). File matching falls back to the QR-stamped copy's hash and
  to QR/text decoding; temp files are deleted in `finally` and never
  stored.
- **Trust score** (`TrustScoreService`): a 0–100 rule-based score derived
  from the EXISTING checks only (exists 20 / hash 30 / signature 30 /
  not-expired 10 / not-revoked 10). A failed critical check (hash /
  signature / exists) caps the score at 40; the score can never contradict
  the verdict. Served beside the seal with a gauge, per-check checklist
  and the disclaimer: "CertiVault confirms the record passes technical
  checks; it does not verify the real-world achievement."
- **Verification report** (`report.php`, dompdf via Composer `vendor/`):
  one PDF per verification - verdict, trust score + checks, certificate
  fields, SHA-256, and a QR back to the live verify page. Contains ONLY
  public verify-page facts (no tokens, keys, internal paths). Rate
  limited to 5 downloads / 10 min / IP and audit-logged.
- **Status API** (`api_status.php?certificate_id=…` or `?id=…`): public
  read-only JSON (verdict, detail, public cert fields, trust score).
  Rate limited, audit-logged, off-switch `CV_API_ENABLED=0`. Response
  never includes tokens, keys, signatures or file paths.

## Demo credentials
After running `php scripts/seed_demo.php` you can log in with:

- Institution (`admin`): `demo.institution@certivault.test` / `DemoInst@2026`
- Student: `demo.student@certivault.test` / `DemoStudent@2026`
- Super admin: seeded row `superadmin@certivault.com` � set a working email/password with `php scripts/set_super_admin.php`

## Migrations (run in this order, in phpMyAdmin)
1. `database/migrations/001_otp_hardening.sql`
2. `database/migrations/002_institution_rejection.sql`
3. `database/migrations/003_verification_integrity_indexes.sql`
4. `database/migrations/004_revocation_audit.sql`
5. `database/migrations/005_remember_me_tokens.sql` (Phase 5)
6. `database/migrations/006_login_rate_limit.sql` (Phase 5)
7. `database/migrations/007_flexible_certificate_id.sql`
8. `database/migrations/008_external_verification_source.sql` (only needed for external sources; the local pipeline works without it)
9. `database/migrations/009_smart_verify_enum.sql` (extends the `verification_logs.query_type` ENUM for Smart Verify; needed by Phase 1 – 3 features)

Each file is idempotent where possible (guarded ALTERs / IF NOT EXISTS) and safe to re-run.

## Security features
- bcrypt password hashing; OTP codes HMAC-SHA256 hashed at rest, 10-min expiry, 5-attempt lockout, resend cooldown
- Login lockout after 5 failed attempts (15 min), sessions regenerated on login/password change
- Idle timeout 30 min / absolute timeout 8 h, no-store cache headers on authenticated pages
- Role-based access (`super_admin`, `admin`, `student`) + `require_approved_institution()` for admin pages
- CSRF token on every POST; prepared statements throughout; output escaped with `htmlspecialchars()`
- CAPTCHA on public forms; rate limiting on verify.php (30 distinct lookups / 10 min / IP ? 429)
- RSA-signed certificates, SHA-256 file integrity, QR-token verification, share-link HMACs with a dedicated secret
- Cookie flags: PHPSESSID and cv_email are HttpOnly; cv_theme is readable by JS (it is the theme feature); all three are SameSite=Strict, Secure on HTTPS

## Hardening (`php.ini`)

Every page sends `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: strict-origin-when-cross-origin`, a least-privilege
`Content-Security-Policy`, a tight `Permissions-Policy`, and
`Strict-Transport-Security` on HTTPS (see `send_security_headers()` in
`src/utils/helpers.php`, called from `src/partials/head.php`). Two settings
cannot be sent reliably at runtime, so set them in `C:\xampp\php\php.ini`
and restart Apache:

```ini
expose_php = Off
display_errors = Off
```

`expose_php = Off` removes the `X-Powered-By: PHP/x.y.z` response header so
the exact PHP version is not advertised to scanners (verify with
`curl -I http://localhost/<repo>/public/` — the header must be gone).
`display_errors = Off` (with `log_errors = On`, already configured in
`src/config/config.php`) keeps stack traces out of responses; errors go to
`private_data/php_errors.log` instead.

## Managed external-source registry (migration 010)

The super-admin dashboard has an **External sources** tab for adding,
editing, testing and disabling sources. Apply `database/migrations/010_external_sources_registry.sql`
first. Registry configuration (including passwords and tokens) is stored as
authenticated AES-256-GCM ciphertext using `CryptoService`; the UI never
re-displays secret values. Set `EXT_REGISTRY_ENABLED=true` in local config to
turn on registry lookups; this is OFF by default. Existing `EXT_*` settings
remain the fallback when no enabled managed source is available.

For Credly add an `open_badges` source with `{"provider":"credly"}` and
allowed hosts `api.credly.com,www.credly.com`. Credly assertions, badge-class
documents and issuer documents are fetched only through the HTTPS SSRF-guarded
HTTP client. Enter either the badge UUID or its `https://www.credly.com/badges/<uuid>`
URL. External results always remain in the separate **Not verified by
CertiVault** card.
Public Credly badge URL to smoke-test: `https://www.credly.com/badges/2ce07a8a-ba1c-450f-98d6-bad4deffe5f5` (the public “Sample Badge” record).

For an offline example run `php scripts/seed_external_source.php`, then enable
`EXT_REGISTRY_ENABLED`; look up `DEMO-MOOC-001` through `DEMO-MOOC-010`. These
10 invented Coursera-style records are held in the local MySQL database. They
are not real Coursera certificates and are never CertiVault-verified.

Pasted URLs are matched against exact official issuer hosts. Likely typosquats,
IDN/punycode and nested lookalikes are shown as warnings and never emitted as
clickable links. Use a real public Credly badge URL for an online smoke test;
the demo registry provides deterministic offline coverage.

## Attested external credentials

Apply `database/migrations/011_attested_external_credentials.sql` and opt in
by setting `ATTESTED_EXTERNAL_CREDENTIALS_ENABLED=true` in local config (it is
OFF by default). Students
can add Coursera, Credly, NPTEL, or a custom issuer host from the enabled
managed-source allow-list, enter an official verification URL or code, and
optionally attach a PDF. The record begins as `SELF_DECLARED`. An approved
institution administrator must open the exact-host-validated issuer link,
compare the evidence, and explicitly attest it. Its signature covers the
student identity, issuer, code, URL, title, issue date, optional PDF SHA-256,
attesting institution, and attestation timestamp. The institution may later
withdraw its attestation. QR and public share links resolve to
`public/external_credential.php`; the page never calls the issuer and never
returns `VALID`. A trust-score variant is capped at 70 and means only that an
institution signed its own claim.

### Why we don't scrape Coursera

CertiVault does not scrape Coursera, Credly, NPTEL, or other issuer sites and
does not make server-side requests to them. Scraping is brittle, can violate
issuer terms, may expose student identifiers, and would falsely suggest that
CertiVault independently validated a credential. Instead, the student shares
the official link and an approved institution representative checks it in
their browser. The institution's signed attestation is attributed to that
institution; it is not an issuer signature or a CertiVault verification.

## Institution key history and transparency log

Apply `database/migrations/012_versioned_keys_transparency_log.sql`, then opt
in by setting `CERTIFICATE_TRANSPARENCY_ENABLED=true` in local config (OFF by
default). Existing
certificates receive `key_id=1` and are not re-signed. New certificates use
the institution's active key version; retired public keys remain available to
verify historical signatures. Institution dashboards, `institutions.php`,
the verify page and `/.well-known/certivault-keys.json` show key versions and
SHA-256 fingerprints. Compare fingerprints through a channel independent of
CertiVault before trusting a key.

Certificate issuance, revocation and supersession append leaves to
`tlog_entries`. A leaf is SHA-256 of
`certificate_id|sha256_hash|signature|certificates.created_at` (`created_at`
is the immutable issuance timestamp). Publish signed checkpoints periodically:

```sh
php scripts/publish_checkpoint.php
```

The first run creates a dedicated platform RSA key pair under
`private_data/tlog/`; back up and protect the private key, and pin the public
key fingerprint independently. The command writes `public/checkpoints/latest.json`.
Schedule it with cron/Task Scheduler after migration 012. The verify page and
status API include inclusion proofs and flag a database/log mismatch.

### Anchor checkpoints outside CertiVault

Publish each `latest.json` to a **separate, public GitHub repository** whose
credentials CertiVault does not possess (prefer a protected branch and signed
commits). For example, a separate operator can periodically download
`https://your-certivault-host/checkpoints/latest.json` and commit it to that
repository. Compare the downloaded copy to the local published checkpoint:

```sh
php scripts/compare_checkpoint.php path/to/out-of-band/latest.json
```

The comparison checks tree size, Merkle root, and the checkpoint signature
against the locally pinned platform public key. A mismatch is evidence that
the local database/checkpoint changed or the published anchor is stale.

For paper measurements run:

```sh
php tests/benchmark_transparency_log.php
```

It prints CSV timings for leaf append/hash, proof generation and verification
at 1k, 10k and 100k entries; these in-memory primitive timings exclude SQL and
network I/O.
