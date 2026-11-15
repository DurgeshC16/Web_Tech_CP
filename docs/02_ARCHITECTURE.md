# 02 — Architecture

## 1. High-level design

CertiVault is a classic server-rendered PHP application with no framework.
Only `public/` is meant to be reachable over HTTP; business logic, uploaded
files and secrets live outside the web root.

```
 Browser (HTML/CSS/JS, html5-qrcode, pdf.js)
        │  HTTPS
        ▼
 ┌──────────────────────────── public/  (web root) ────────────────────────────┐
 │ Page controllers: login, dashboards, issue/revoke/supersede, verify, share,  │
 │ report (PDF), api_status (JSON), well-known-keys …                           │
 └───────────────┬──────────────────────────────────────────────────────────────┘
                 │ require_once
 ┌───────────────▼────────────── src/  (NOT web-reachable) ─────────────────────┐
 │ config/   config.php (constants, secrets guard) · Database.php (PDO singleton)│
 │ utils/    helpers.php (sessions, auth, CSRF, CAPTCHA, OTP, mail, headers)     │
 │           validators.php (server-side validators)                             │
 │ services/ Crypto · Verification · SmartVerify · FileVerify · TrustScore ·     │
 │           Report · StatusApi · StudentStats · ExternalSource ·                │
 │           AttestedCredential · TransparencyLog · QR                           │
 │ partials/ head / header / footer templates                                    │
 └───────┬───────────────────────────────┬──────────────────────────────────────┘
         ▼                               ▼
   MySQL / MariaDB                 private_data/ (uploads, logs, mail spool,
   (13 tables)                     transparency-log key, caches) — denied by .htaccess
```

**Patterns used**

* **Page controller** — each `public/*.php` file handles its own GET/POST,
  calls services, then renders HTML with shared partials.
* **Service layer** — stateless static classes in `src/services/`; the same
  `VerificationService::verify()` is used by `verify.php`, `share.php`,
  `report.php`, `api_status.php` and the trust score, so every surface gives
  the same verdict.
* **PDO singleton** — `Database::getInstance()`; prepared statements with
  emulation **off**; the MySQL session time zone is aligned with PHP's.
* **Progressive enhancement** — every form works without JavaScript; JS adds
  client-side validation, QR scanning and browser-side hashing.
* **Feature flags** — optional features (external sources, attested
  credentials, transparency log, status API, Smart Verify) are switched by
  constants in `config.php` / `config.local.php`.

## 2. Directory layout

```
Web_Tech_CP/
├── public/                     # Web root — the ONLY directory Apache should serve
│   ├── .htaccess               # rewrite for /.well-known/certivault-keys.json
│   ├── index.php               # Landing page + quick verify
│   ├── *.php                   # Page controllers (see §3)
│   ├── assets/css/style.css    # Design system (responsive, light/dark)
│   ├── assets/js/              # validation.js, theme.js, verify-scan.js,
│   │                           # html5-qrcode.min.js, vendor/pdf.js
│   ├── qrcodes/                # Generated QR PNGs (runtime, git-ignored)
│   └── checkpoints/            # Published transparency checkpoint (runtime)
├── src/                        # Application code (outside web root)
│   ├── config/                 # config.php, Database.php, config.local.php.example
│   ├── services/               # Business logic (12 services)
│   ├── utils/                  # helpers.php, validators.php, composer_autoload.php
│   │   ├── PHPMailer/          # vendored — SMTP email
│   │   ├── phpqrcode/          # vendored — QR generation (+ precomputed cache)
│   │   └── qrdecoder/          # vendored — ZXing port, server-side QR decoding
│   └── partials/               # head.php, header.php, footer.php, head_fonts.php
├── database/
│   ├── schema.sql              # Full current schema (fresh installs)
│   └── migrations/             # 001…012 incremental upgrades (existing installs)
├── scripts/                    # CLI maintenance tools (see doc 06)
├── tests/                      # Plain-PHP CLI test suites + Node browser tests
├── private_data/               # Runtime data, denied over HTTP (git-ignored content)
│   ├── uploads/                # Issued certificate files
│   ├── mail/                   # Dev mail spool
│   └── php_errors.log          # Application error log
├── docs/                       # This documentation
├── composer.json / .lock       # dompdf + smalot/pdfparser (run `composer install`)
└── vendor/                     # Composer output (git-ignored)
```

## 3. Page map (`public/`)

### Public (no login)

| Page | Purpose |
|------|---------|
| `index.php` | Landing page with Smart Verify quick-verify panel |
| `verify.php` | **Verification engine UI** — `?token=` (QR), or POST ID / URL / file / browser-computed hash; shows verdict seal, certificate card, trust-score gauge, key fingerprint, external-source cards |
| `share.php` | Opens a student's HMAC-signed, 24-hour share link and shows the verified certificate |
| `report.php` | Streams the PDF verification report (`?cert=` / `?certificate_id=`), 5 per 10 min per IP |
| `api_status.php` | Read-only JSON status API (`?certificate_id=` or `?id=`) |
| `institutions.php` | Public directory of institutions and their signing-key fingerprints |
| `well-known-keys.php` | Key directory as JSON, served at `/.well-known/certivault-keys.json` |
| `external_credential.php` | Public page for a student's attested external credential (`?token=`) |
| `login.php` / `logout.php` | Login (CAPTCHA, lockout, remember-me) / POST-only logout |
| `register_student.php` / `register_institution.php` | Self-registration (institutions then await approval) |
| `activate_account.php` | Email-OTP account activation + password set |
| `forgot_password.php` / `reset_password.php` | OTP-based password reset |

### Student

| Page | Purpose |
|------|---------|
| `student_dashboard.php` | Own certificates, per-certificate verification counts, activity strip |
| `view_certificate_student.php` | Certificate detail, trust-score card, share-link generation, PDF report |
| `download.php` | Ownership-checked file download (`nosniff`, sanitised filename) |
| `external_credentials.php` | Declare third-party credentials for institutional attestation |

### Institution admin (must be approved)

| Page | Purpose |
|------|---------|
| `admin_dashboard.php` | Issued certificates, stats |
| `issue_certificate.php` | Issuance pipeline (doc 01 §3) |
| `view_certificate_admin.php` | Certificate detail + actions |
| `revoke_certificate.php` | Revoke with a reason |
| `supersede_certificate.php` | Issue a corrected version |
| `audit_logs.php` | Verification logs for the institution's certificates + transparency summary |
| `attest_external_credentials.php` / `external_credential_file.php` | Review queue for student-declared credentials; sign or withdraw attestations |
| `rotate_key.php` | Rotate the institution signing key (transparency feature) |

### Super admin

| Page | Purpose |
|------|---------|
| `super_admin.php` | Tabs: **Institutions** (approve → generates RSA key pair; reject with reason) and **External sources** (add/edit/test/disable managed registry entries) |

### Any logged-in role

| Page | Purpose |
|------|---------|
| `change_password.php` | Password change confirmed by email OTP |

## 4. Services (`src/services/`)

| Service | Responsibility |
|---------|----------------|
| `CryptoService` | RSA key generation, AES-256-GCM key wrapping (legacy CBC read support), canonical hash, sign/verify, key fingerprints, encrypted config blobs |
| `VerificationService` | Certificate lookup (token, exact ID, normalised ID, compact ID), the verdict cascade, per-IP rate limiting |
| `SmartVerifyService` | Classifies free text (self-verify URL, token, CV-ID, issuer links), allow-listed external issuer links, look-alike/typosquat detection |
| `FileVerifyService` | Uploaded-file pipeline: byte-hash match → QR decode → text extraction → regex scan; temp files always deleted |
| `TrustScoreService` | 0–100 score replaying the cascade's checks (exists 20 / hash 30 / signature 30 / not expired 10 / not revoked 10; critical failure caps at 40; external credentials capped at 70) |
| `ReportService` | dompdf PDF verification report with QR back to the live verify page |
| `StatusApiService` | JSON status API resolution + audit logging |
| `StudentStatsService` | Read-only verification counts for students |
| `ExternalSourceService` | Optional external lookups (Open Badges / Credly over HTTPS, remote read-only DB) with SSRF guard, allow-list, caching and rate limit |
| `AttestedCredentialService` | Student-declared credentials, exact-host URL validation, institution RSA attestation/withdrawal |
| `TransparencyLogService` | Append-only Merkle log of ISSUE/REVOKE/SUPERSEDE events, inclusion proofs, signed checkpoints |
| `QRService` | QR PNG generation (phpqrcode) |

## 5. Request lifecycle (example: `verify.php?token=…`)

1. `config.php` loads `config.local.php` (if present), then defines constants
   and enforces the production-secret guard.
2. `helpers.php` starts a hardened session and sends security headers.
3. Token format is validated (no DB hit for malformed input).
4. Rate limit: distinct lookups by this IP in the last 10 min ≥ 30 → HTTP 429.
5. `VerificationService::findByToken()` → `verify()` cascade.
6. `TrustScoreService::compute()`; transparency inclusion proof if enabled.
7. Result logged to `verification_logs`; HTML rendered with escaped output.

## 6. Third-party code

| Library | Location | Licence | Used for |
|---------|----------|---------|----------|
| PHPMailer | `src/utils/PHPMailer/` | LGPL-2.1 | SMTP delivery of OTP / notification emails |
| phpqrcode | `src/utils/phpqrcode/` | LGPL-3 | QR PNG generation |
| ZXing PHP port | `src/utils/qrdecoder/` | MIT (see `LICENSE-ORIGINAL-MIT`) | Server-side QR decoding of uploaded images |
| html5-qrcode | `public/assets/js/html5-qrcode.min.js` | Apache-2.0 | Camera scanning and image QR decoding in the browser |
| pdf.js 3.11.174 | `public/assets/js/vendor/` | Apache-2.0 | Rendering uploaded PDFs in the browser to find QR codes |
| dompdf | Composer (`vendor/`) | LGPL-2.1 | PDF verification report |
| smalot/pdfparser | Composer (`vendor/`) | LGPL-3 | Extracting text from uploaded PDFs |

Composer packages are **optional**. They are loaded through
`src/utils/composer_autoload.php`, which checks the install is complete
first. Without them, `report.php` serves an HTML fallback and Smart Verify
skips PDF text extraction.
