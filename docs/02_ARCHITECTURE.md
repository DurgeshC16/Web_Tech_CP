# 02 — Architecture

## 1. High-level design

CertiVault is a server-rendered PHP application with no framework. Only
`public/` is meant to be reachable over HTTP; business logic, uploaded files,
key pins and secrets live outside the web root.

```
 Browser (HTML/CSS, external JS only: ui.js, smart-verify.js,
          credential-verify.js, analytics.js, html5-qrcode, pdf.js)
        │  HTTPS
        ▼
 ┌──────────────────────────── public/  (web root) ─────────────────────────────┐
 │ Page controllers: login (+2FA), dashboards, issue / bulk issue / revoke /     │
 │ supersede, verify, share, report (PDF), credential (JSON), offline_verify,    │
 │ analytics, api_status (JSON), well-known-keys …                               │
 └───────────────┬───────────────────────────────────────────────────────────────┘
                 │ require_once
 ┌───────────────▼────────────── src/  (NOT web-reachable) ──────────────────────┐
 │ config/   config.php (constants, production guard) · Database.php (PDO,      │
 │           strict SQL mode, time-zone alignment)                               │
 │ utils/    helpers.php (sessions, auth, CSRF, CAPTCHA, OTP, mail, headers)     │
 │           validators.php · composer_autoload.php (safe optional loader)       │
 │ services/ 19 services — issuance, verification, crypto, pinning, credentials, │
 │           2FA, analytics, transparency log … (§4)                             │
 │ partials/ head / header / footer templates                                    │
 └───────┬───────────────────────────────┬────────────────────────────────────────┘
         ▼                               ▼
   MySQL / MariaDB                 private_data/ (uploads, mail spool, key pins,
   (15 tables, utf8mb4_unicode_ci)  transparency key, logs, backups) — denied over HTTP
```

**Patterns used**

* **Page controller** — each `public/*.php` handles its own GET/POST, calls
  services, then renders HTML with shared partials.
* **Service layer** — static classes in `src/services/`. One verification
  engine (`VerificationService::verify()`) serves verify, share, report, the
  status API, credentials and the trust score; one issuance pipeline
  (`IssuanceService`) serves single and bulk issuance.
* **PDO singleton** — `Database::getInstance()`; prepared statements with
  emulation off; session `sql_mode` strict (same behaviour as production
  MySQL/MariaDB) and time zone aligned with PHP.
* **Progressive enhancement** — every form works without JavaScript; JS adds
  client-side validation, QR/PDF decoding, browser hashing, Web Crypto
  verification and chart tooltips.
* **No inline JavaScript** — behaviour is attached from external files via
  data attributes, so the CSP forbids inline scripts (doc 04).
* **Feature flags** — optional features are switched by constants in
  `config.php` / `config.local.php` (doc 06).

## 2. Directory layout

```
Web_Tech_CP/
├── .github/workflows/ci.yml    # CI: lint + PHP suite + headless-Chrome suites
├── .htaccess                   # defence in depth for "repo inside htdocs"
├── public/                     # Web root — the ONLY directory to serve
│   ├── *.php                   # Page controllers (see §3)
│   ├── assets/css/style.css    # Design system (responsive, light/dark, charts)
│   ├── assets/js/              # ui.js, smart-verify.js, credential-verify.js,
│   │                           # analytics.js, validation.js, theme.js,
│   │                           # html5-qrcode.min.js, vendor/pdf.js
│   ├── qrcodes/                # Generated QR PNGs (runtime, git-ignored)
│   └── checkpoints/            # Published transparency checkpoint (runtime)
├── src/                        # Application code (denied over HTTP)
│   ├── config/                 # config.php, Database.php, config.local.php.example
│   ├── services/               # Business logic (19 services)
│   ├── utils/                  # helpers.php, validators.php, composer_autoload.php
│   │   ├── PHPMailer/          # vendored — SMTP email
│   │   ├── phpqrcode/          # vendored — QR generation (PHP 8.2-patched)
│   │   └── qrdecoder/          # vendored — ZXing port, server-side QR decoding
│   └── partials/               # head.php, header.php, footer.php
├── database/
│   ├── schema.sql              # Full current schema (fresh installs)
│   └── migrations/             # 001…016 incremental upgrades
├── scripts/                    # CLI tools (doc 06 §6)
├── tests/                      # 16 PHP suites, 2 browser suites, fixtures, helpers
├── private_data/               # Runtime data (contents git-ignored)
│   ├── uploads/  mail/  pins/  tlog/  backups/
│   └── php_errors.log
├── docs/                       # This documentation (+ git-ignored docs/private/)
├── composer.json / .lock       # dompdf + smalot/pdfparser
└── vendor/                     # Composer output (git-ignored)
```

## 3. Page map (`public/`)

### Public (no login)

| Page | Purpose |
|------|---------|
| `index.php` | Landing page with the Smart Verify panel |
| `verify.php` | **Verification UI** — `?token=` (QR), `?certificate_id=` / `?id=` (shareable links), or POST ID / URL / file / browser hash + browser-decoded QR text; verdict, trust score, key fingerprint, report + credential downloads |
| `share.php` | Student's HMAC-signed 24-hour share link |
| `report.php` | PDF verification report (`?cert=`), 5 per 10 min per IP |
| `credential.php` | Signed, self-verifying JSON credential (`?token=` / `?certificate_id=`) |
| `offline_verify.php` | Zero-trust verifier: checks a credential file **in the browser** with Web Crypto |
| `api_status.php` | Read-only JSON status API (`?certificate_id=` / `?id=`) |
| `institutions.php`, `well-known-keys.php` | Public key directory (HTML / JSON at `/.well-known/certivault-keys.json`) |
| `external_credential.php` | Public page of an attested external credential |
| `login.php` → `login_2fa.php` | Password (CAPTCHA, lockout, remember-me), then the TOTP step when 2FA is on |
| `logout.php`, `register_*.php`, `activate_account.php`, `forgot_password.php`, `reset_password.php` | Account lifecycle |

### Student

| Page | Purpose |
|------|---------|
| `student_dashboard.php` | Own certificates, verification counts, activity strip |
| `view_certificate_student.php` | Detail, trust score, share link, PDF report, signed credential |
| `download.php` | Ownership-checked download |
| `external_credentials.php` | Declare external credentials (opt-in feature) |

### Institution admin (approved)

| Page | Purpose |
|------|---------|
| `admin_dashboard.php` | Issued certificates |
| `issue_certificate.php` | Single issuance (uploaded file) |
| `bulk_issue.php` | **CSV bulk issuance** with generated certificate PDFs |
| `analytics.php` | **Verification analytics** (KPIs, daily chart, verdict mix, top certificates) |
| `view_certificate_admin.php`, `revoke_certificate.php`, `supersede_certificate.php` | Certificate lifecycle |
| `audit_logs.php` | Verification log + transparency summary |
| `attest_external_credentials.php`, `external_credential_file.php` | Attestation queue (opt-in) |
| `rotate_key.php` | Rotate the signing key (transparency feature) |

### Super admin

| Page | Purpose |
|------|---------|
| `super_admin.php` | Approve (generates + pins the RSA key) / reject institutions; manage external sources |

### Any logged-in role

| Page | Purpose |
|------|---------|
| `change_password.php` | Password change confirmed by email OTP |
| `two_factor.php`, `two_factor_qr.php` | Set up / manage TOTP two-factor authentication |

## 4. Services (`src/services/`)

| Service | Responsibility |
|---------|----------------|
| `CryptoService` | RSA keys, AES-256-GCM key wrapping, canonical hash, sign/verify, fingerprints, encrypted config blobs |
| `VerificationService` | Lookups (token, exact / normalised / compact ID), the verdict cascade incl. key-pin check, bounded pre-lookup rate limiter |
| `KeyPinService` | Append-only key-fingerprint pins outside the database; `match` / `mismatch` / `unpinned`, strict mode |
| `IssuanceService` | Shared issuance pipeline (student gate → ID → QR → file → hash → signature → insert → log) + issuance email |
| `CertificatePdfService` | Renders certificate PDFs (dompdf) with the QR embedded |
| `BulkIssueService` | CSV parsing/validation, CSV export (formula-injection safe) |
| `CredentialService` | Builds and independently verifies portable signed credentials |
| `SmartVerifyService` | Classifies free text / URLs / issuer links, look-alike detection |
| `FileVerifyService` | Upload pipeline: raw file hash (`file_sha256`) → QR decode → text extraction |
| `TrustScoreService` | 0–100 score mirroring the cascade (critical failure caps at 40) |
| `ReportService` | PDF verification report |
| `StatusApiService` | JSON status API + its own request-scoped rate limit |
| `StudentStatsService` | Read-only verification counts for students |
| `AnalyticsService` | Read-only institution analytics (DST-safe day series) |
| `TotpService` | RFC 6238 TOTP, replay protection, encrypted secrets, recovery codes |
| `ExternalSourceService` | Optional external lookups with SSRF guard |
| `AttestedCredentialService` | Student-declared credentials + institution attestations |
| `TransparencyLogService` | Merkle log, inclusion proofs, signed checkpoints |
| `QRService` | QR PNG generation |

## 5. Request lifecycle (example: `verify.php?certificate_id=…`)

1. `config.php` loads `config.local.php`, defines constants, runs the
   production guard; `Database.php` opens a strict-mode PDO session.
2. **Rate gate** — `checkAndRecordLookup()` on a key derived from the raw
   inputs; the 31st distinct lookup per IP per 10 min gets HTTP 429 before any
   certificate query.
3. Format pre-check (malformed input → INVALID without a DB lookup).
4. Layered lookup → `VerificationService::verify()`: status → integrity →
   **key pin** → RSA signature → expiry.
5. Trust score, optional transparency proof, audit log row
   (`verification_logs`), HTML with escaped output.

## 6. Third-party code

| Library | Location | Licence | Used for |
|---------|----------|---------|----------|
| PHPMailer | `src/utils/PHPMailer/` | LGPL-2.1 | SMTP delivery |
| phpqrcode | `src/utils/phpqrcode/` | LGPL-3 | QR PNG generation (two PHP 8.2 fixes, output byte-identical) |
| ZXing PHP port | `src/utils/qrdecoder/` | MIT | Server-side QR decoding |
| html5-qrcode | `public/assets/js/html5-qrcode.min.js` | Apache-2.0 | Camera scanning, image QR decoding |
| pdf.js 3.11.174 | `public/assets/js/vendor/` | Apache-2.0 | Rendering PDFs in the browser to find QR codes |
| dompdf | Composer | LGPL-2.1 | Verification report + generated certificates |
| smalot/pdfparser | Composer | LGPL-3 | PDF text extraction |

Composer packages load through `src/utils/composer_autoload.php`, which checks
the install is complete; without them the report shows a fallback page,
Smart Verify skips text extraction and bulk issuance is disabled.
