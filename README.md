# CertiVault — Digital Certificate Issuance & Verification

> Issue tamper-evident digital certificates and let anyone verify them in
> seconds — by QR code, certificate ID, the file itself, or a signed
> credential checked in their own browser.

CertiVault is a PHP + MySQL web platform built as a **Web Technology course
project**. Institutions issue certificates that are bound to their identity
with a **SHA-256 canonical fingerprint** and an **RSA-2048 digital
signature**, whose key is **pinned outside the database**, and carry a **QR
code**. Employers and other verifiers check a certificate **without an
account** and get one clear, audited verdict: **VALID, TAMPERED, EXPIRED,
REVOKED, SUPERSEDED or INVALID**.

[![CI](https://github.com/DurgeshC16/Web_Tech_CP/actions/workflows/ci.yml/badge.svg)](https://github.com/DurgeshC16/Web_Tech_CP/actions/workflows/ci.yml)
![PHP](https://img.shields.io/badge/PHP-8.2-777BB4?logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL%20%2F%20MariaDB-10.4%2B-4479A1?logo=mysql&logoColor=white)
![Tests](https://img.shields.io/badge/tests-590%20checks-brightgreen)
![No framework](https://img.shields.io/badge/framework-none-lightgrey)

---

## Contents

1. [Why CertiVault](#why-certivault)
2. [Features](#features)
3. [How it works](#how-it-works)
4. [Tech stack](#tech-stack)
5. [Project structure](#project-structure)
6. [Quick start](#quick-start)
7. [Configuration](#configuration)
8. [Demo accounts](#demo-accounts)
9. [Testing & CI](#testing--ci)
10. [Security](#security)
11. [Documentation](#documentation)
12. [Project status & roadmap](#project-status--roadmap)
13. [Limitations](#limitations)

---

## Why CertiVault

Certificates are shared as PDFs and images, which anyone can edit, and the
person receiving one rarely has a quick way to check it. Blockchain
solutions remove the central registry but add fees and latency, and still
can't prove that a ledger identity belongs to a real institution.

CertiVault uses plain, well-understood cryptography instead:

| Mechanism | What it guarantees |
|-----------|--------------------|
| Unique certificate ID | Fast lookup (`CV-2026-000123` or a custom ID) |
| SHA-256 canonical fingerprint of all fields **and** the file | Any change is detected (**integrity**) |
| RSA-2048 signature by the approved institution | Proves who issued it (**authenticity**) |
| Key fingerprint pinned outside the database | A swapped institution key is detected |
| QR code with a 256-bit random token | One-scan verification, no personal data inside |
| Status lifecycle: active / expired / revoked / superseded | Corrections without deleting history |

## Features

**Issue**
- **Single issuance** with an uploaded certificate file.
- **Bulk issuance from CSV** — preview and validation first, then one signed
  **generated certificate PDF** (QR embedded) per row, results CSV.
- Students are **emailed** their verify link; new students get an activation email first.
- Revocation with reason; **supersession** that keeps the version chain.

**Verify** (no account needed for the first 5 checks)
- **Smart Verify** — ID in any format, QR token, link, QR image or the
  certificate file. Exact originals match by fingerprint; other copies resolve
  through the **QR read inside the PDF, in the browser** (pdf.js). Privacy
  mode sends only a hash. Camera scanning. Shareable links
  (`verify.php?certificate_id=…`).
- **Six-verdict cascade** with fixed precedence, audit log and a **trust score**.
- **Guest quota** — visitors get **5 free verifications per 24 h** (per hashed IP
  and per session; repeats are free), then a "free limit reached — log in or
  register" page. Logged-in users are unlimited (`CV_GUEST_VERIFY_LIMIT`).
- **PDF verification report** and a **public JSON status API**.
- **Signed credential (JSON)** + **zero-trust verifier**: anyone can re-check a
  certificate **in their own browser** with Web Crypto (or with OpenSSL)
  without trusting the server's verdict.

**Accounts & security**
- Email-OTP activation, CAPTCHA, login lockout, remember-me, session timeouts.
- **Resumable sign-up** — registering again with an unverified email resumes the
  pending account (fresh code) instead of "already registered"; login asks
  unverified accounts to verify their email before checking institution approval.
- One password field with a **show/hide toggle** and live strength checklist.
- **Forgot password** is a 2-step flow (email → code + new password) with
  "Already have a code?" and "Resend code"; identical wording whether or not
  the account exists.
- **Two-factor authentication (TOTP)** with recovery codes, for every role.
- **Key pinning**, AES-256-GCM key storage, **CSP with no inline scripts**,
  pre-lookup rate limiting, strict SQL mode.

**Insight**
- **Institution analytics** — KPIs, verifications per day, verdict mix,
  most-checked certificates (accessible SVG charts with table views).

**Optional (off by default)** — Merkle **transparency log** with signed
checkpoints and key rotation; **external sources** (Open Badges / Credly);
**attested external credentials** (Coursera / Credly / NPTEL claims).

Responsive UI (360 → 1280 px) with a light/dark theme.

## How it works

```
ISSUE (institution)                              VERIFY (anyone, no login)
───────────────────                              ─────────────────────────
validate input + file (or CSV row → PDF)         QR / ID / link / file / credential
   │                                                │  format check + rate gate
store file outside the web root                     ▼
   │                                             exists? ─────────────── no → INVALID
h = SHA-256(id|inst|student|title|                revoked? ────────────── yes → REVOKED
            issued|expires|SHA-256(file))         superseded? ─────────── yes → SUPERSEDED
   │                                             recompute h == stored? ─ no → TAMPERED
σ = RSA-Sign(institution key, h)                  key matches its pin? ─── no → TAMPERED
   │  (key pinned outside the DB at approval)     RSA-Verify(h, σ)? ────── no → TAMPERED
QR → verify.php?token=<256-bit random>            expired? ────────────── yes → EXPIRED
   │                                                                            VALID
one DB transaction (rollback deletes file + QR)     │
email the student                                log, trust score, PDF report,
                                                 signed credential (JSON)
```

Full walkthrough: [docs/01_PROJECT_OVERVIEW.md](docs/01_PROJECT_OVERVIEW.md).

## Tech stack

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3 (custom responsive design system), vanilla JavaScript (external files only), Web Crypto, html5-qrcode, pdf.js |
| Backend | PHP 8.2 (no framework): sessions, cookies, PDO, OpenSSL |
| Database | MySQL / MariaDB (utf8mb4_unicode_ci, strict SQL mode) |
| Cryptography | SHA-256, RSA-2048, AES-256-GCM, HMAC-SHA-256, TOTP (RFC 6238), bcrypt |
| Libraries | PHPMailer, phpqrcode, ZXing PHP port (vendored); dompdf, smalot/pdfparser (Composer) |
| Tooling | GitHub Actions CI, headless Chrome tests (no npm dependencies) |
| Environment | XAMPP (Apache + MariaDB + PHP) or `php -S` |

## Project structure

```
Web_Tech_CP/
├── .github/workflows/ CI: lint, PHP suites (MariaDB 10.11), headless-Chrome suites
├── public/            Web root: page controllers, assets (CSS/JS), generated QR codes
├── src/
│   ├── config/        config.php, Database.php, config.local.php.example
│   ├── services/      19 services: Issuance, Verification, Crypto, KeyPin, Credential,
│   │                  Totp, Analytics, BulkIssue, CertificatePdf, SmartVerify, …
│   ├── utils/         helpers.php, validators.php + vendored PHPMailer / phpqrcode / qrdecoder
│   └── partials/      Shared head / header / footer templates
├── database/          schema.sql (fresh install) + migrations/001–016 (upgrades)
├── scripts/           CLI tools: setup, seeding, key pins, backfill, diagnostics, checkpoints
├── tests/             16 PHP suites + 2 browser suites + fixtures
├── private_data/      Uploads, mail spool, key pins, logs (not web-accessible; git-ignored)
├── docs/              Full documentation
└── composer.json      PHP dependencies (vendor/ is git-ignored)
```

Details: [docs/02_ARCHITECTURE.md](docs/02_ARCHITECTURE.md).

## Quick start

**Requirements:** PHP 8.2+ (`pdo_mysql`, `openssl`, `fileinfo`, `gd`,
`mbstring`, `curl`), MySQL/MariaDB, Composer. XAMPP provides PHP and MariaDB.

```sh
# 1. Get the code
git clone https://github.com/DurgeshC16/Web_Tech_CP.git
cd Web_Tech_CP

# 2. PHP dependencies (PDF report, generated certificates, PDF text extraction)
composer install

# 3. Create the database (creates `certivault`, all tables, a locked super admin)
mysql -u root < database/schema.sql            # or phpMyAdmin → Import

# 4. Local config (git-ignored): SMTP credentials + secrets
copy src\config\config.local.php.example src\config\config.local.php

# 5. Set the super-admin login
php scripts/set_super_admin.php

# 6. Optional demo data
php scripts/seed_demo.php
php scripts/generate_dataset.php   # 100 people, 5 institutions, ~190 signed certificates

# 7. Run — serve ONLY the public/ folder
php -S localhost:8081 -t public
```

Open <http://localhost:8081>. With Apache, point the virtual host's
`DocumentRoot` at `public/`. **Next:** follow the guided tour in
[docs/10_RUNNING_AND_DEMO_GUIDE.md](docs/10_RUNNING_AND_DEMO_GUIDE.md).

**Prefer Docker?** `docker compose up -d --build`, then
`docker compose exec -u www-data app php scripts/seed_demo.php` and open
<http://localhost:8080> (details in the [running guide](docs/10_RUNNING_AND_DEMO_GUIDE.md)).

**Free hosting?** Deploy on Render's free plan with an external MySQL and
Brevo for email — step by step in
[docs/13_DEPLOY_RENDER.md](docs/13_DEPLOY_RENDER.md) (`render.yaml` blueprint included).

**Upgrading an existing database:** apply the missing files in
`database/migrations/` in order (001 → 016), then run once
`php scripts/backfill_file_hashes.php` and `php scripts/pin_institution_keys.php`
([docs/03_DATABASE.md](docs/03_DATABASE.md)).

**No SMTP account?** Set `define('MAIL_TRANSPORT', 'file');` in
`config.local.php` and read every email (including codes) in
`private_data/mail/`.

## Configuration

Settings come from `src/config/config.local.php`, then environment variables,
then the defaults in `src/config/config.php`. Exception: an explicitly set
`CV_DB_NAME` or `CV_MAIL_TRANSPORT` environment variable overrides
`config.local.php` (so test servers really use `certivault_test`).

| Setting | Purpose |
|---------|---------|
| `CV_DB_HOST` / `CV_DB_USER` / `CV_DB_PASS` / `CV_DB_NAME` | Database connection (defaults: `localhost` / `root` / empty / `certivault`) |
| `CV_ENCRYPTION_KEY` | Encrypts institution private keys and 2FA secrets. **Set it before approving the first institution.** |
| `CV_OTP_PEPPER`, `CV_SHARE_SECRET` | HMAC secrets for codes and share links |
| `SMTP_*`, `CV_MAIL_TRANSPORT` | Email delivery (Gmail needs an App Password); `file` = local dev spool |
| `CV_KEY_PINS_FILE`, `CV_KEY_PINNING_STRICT` | Key-pin file location (keep it out of reach of the web/DB user); strict mode |
| `CV_RECAPTCHA_SITE_KEY` / `_SECRET_KEY` | Google reCAPTCHA; otherwise an offline arithmetic CAPTCHA |
| `CV_BASE_URL` | Only behind a proxy; otherwise derived per request |
| `CV_GUEST_VERIFY_LIMIT` / `CV_GUEST_VERIFY_WINDOW_SECONDS` | Free verifications for visitors who are not logged in (default 5 per 86400 s; `0` = off). `api_status.php` keeps its own limiter |
| `CV_ENV=production` | Refuses to start with development secrets or the file mail transport |
| Hosting (all off by default) | `CV_DB_PORT`, `CV_DB_SSL_CA` / `CV_DB_SSL_CA_PEM` (TLS to the DB), `CV_MAIL_TRANSPORT=brevo` + `CV_BREVO_API_KEY` + `CV_MAIL_FROM_EMAIL`, `CV_TRUST_PROXY=1`, `CV_FILE_STORE=db`, `CV_SUPER_ADMIN_EMAIL` / `_PASSWORD`, `CV_ERROR_LOG=stderr` — see [docs/13_DEPLOY_RENDER.md](docs/13_DEPLOY_RENDER.md) |
| Feature flags | `CV_SMART_VERIFY`, `CV_API_ENABLED` (on); `CV_EXT_REGISTRY_ENABLED`, `CV_ATTESTED_CREDENTIALS_ENABLED`, `CV_CERTIFICATE_TRANSPARENCY_ENABLED` (off) |

Full reference, Gmail setup and the production checklist:
[docs/06_SETUP_AND_CONFIGURATION.md](docs/06_SETUP_AND_CONFIGURATION.md).

## Demo accounts

After `php scripts/seed_demo.php`:

| Role | Email | Password |
|------|-------|----------|
| Institution admin | `demo.institution@certivault.test` | `DemoInst@2026` |
| Student | `demo.student@certivault.test` | `DemoStudent@2026` |
| Super admin | set by you | `php scripts/set_super_admin.php` (the seeded account is locked) |

Local demo credentials only — never reuse them on a server.

**Dummy dataset (100 people).** `php scripts/generate_dataset.php` creates 5 fictional
institutions, 100 students and ~190 certificates through the real issuance
pipeline (VALID / EXPIRED / REVOKED / SUPERSEDED mix). Every dataset account is on
`@dataset.example.com` with the password `Demo@12345` (e.g.
`registrar.northbridge@dataset.example.com`, `lea.moreau@dataset.example.com`).
`--reset` removes it again; it refuses to run with `CV_ENV=production`. CSVs and
column descriptions: [docs/samples/dataset/](docs/samples/dataset/README.md).

## Testing & CI

```sh
php tests/run_all.php              # 19 PHP suites (isolated certivault_test DB)
node tests/test_verify_ui.mjs      # Smart Verify in headless Chrome — 17 checks
node tests/test_pages_browser.mjs  # every page under the CSP, issuance, 2FA, analytics — 61 checks
```

The suites cover crypto, validators, uploads, the verification cascade, key
pinning (incl. the key-swap attack), signed credentials (incl. OpenSSL
interop), bulk issuance, two-factor login over HTTP, analytics, rate limits
and the full lifecycle. **GitHub Actions** runs everything on every push
(Linux, MariaDB 10.11 strict mode, Google Chrome). See
[docs/07_TESTING.md](docs/07_TESTING.md).

## Security

- bcrypt passwords; optional **TOTP 2FA** with recovery codes; HMAC-hashed email codes; lockout; CAPTCHA; hardened sessions
- RSA-signed certificates; AES-256-GCM key storage; **key fingerprints pinned outside the DB** (a swapped key → TAMPERED)
- Role-based + row-level authorization; CSRF tokens; prepared statements; strict SQL mode; escaped output
- **CSP without inline scripts** (`script-src 'self'`, `script-src-attr 'none'`) plus nosniff, frame, referrer, permissions headers and HSTS
- Rate limiting **before** any certificate lookup, with constant-cost state; every lookup logged
- Uploads checked by extension and real MIME type and stored outside the web root; only `public/` is web-reachable
- Production guard refuses development secrets; the seeded super admin is locked

Threat model and remaining gaps:
[docs/04_SECURITY_AND_CRYPTOGRAPHY.md](docs/04_SECURITY_AND_CRYPTOGRAPHY.md).

## Documentation

| Doc | Topic |
|-----|-------|
| [01 Project Overview](docs/01_PROJECT_OVERVIEW.md) | Problem, roles, end-to-end methodology, verdicts |
| [02 Architecture](docs/02_ARCHITECTURE.md) | Layers, page map, services, libraries |
| [03 Database](docs/03_DATABASE.md) | Tables, relationships, migrations |
| [04 Security & Cryptography](docs/04_SECURITY_AND_CRYPTOGRAPHY.md) | Hashing, signatures, pinning, 2FA, threat model |
| [05 Features & User Guide](docs/05_FEATURES_AND_USER_GUIDE.md) | Step-by-step per role, every feature |
| [06 Setup & Configuration](docs/06_SETUP_AND_CONFIGURATION.md) | Install, config reference, email, troubleshooting, production checklist |
| [07 Testing](docs/07_TESTING.md) | PHP + browser suites, CI |
| [08 Research Summary](docs/08_RESEARCH_SUMMARY.md) | Findings of the accompanying research paper |
| [09 Status & Roadmap](docs/09_STATUS_AND_ROADMAP.md) | Progress, change log, what is next |
| [10 Running & Demo Guide](docs/10_RUNNING_AND_DEMO_GUIDE.md) | **Step-by-step setup, guided tour of the website, 5-minute demo script** |
| [11 Novelties & Comparison](docs/11_NOVELTIES_AND_COMPARISON.md) | CertiVault vs Credly, Certifier, Accredible, Blockcerts, OB 3.0/W3C VC, DigiLocker/NAD + prioritised roadmap |
| [12 Design System](docs/12_DESIGN_SYSTEM.md) | UI tokens, components, motion rules of the redesigned frontend |
| [13 Deploy on Render (free)](docs/13_DEPLOY_RENDER.md) | **Beginner step-by-step:** external MySQL with TLS, Brevo email, Render Blueprint, UptimeRobot, limitations, troubleshooting |
| [Requirements Matrix](docs/REQUIREMENTS_MATRIX.md) | Course requirements → implementation |
| [Project Brief (PDF)](docs/reference/CertiVault_Project_Brief.pdf) | Original project brief |

## Project status & roadmap

All course requirements and core features are implemented and tested, the
issues from the 2026-11-15 review are fixed, and signed credentials, bulk
issuance, 2FA, analytics, key pinning and CI have been added. Next
([details](docs/09_STATUS_AND_ROADMAP.md)): move inline styles out of the
templates, optionally require 2FA for admins, a public HTTPS demo / container
image, W3C Verifiable Credentials export, and refreshed paper figures.

## Limitations

CertiVault is a single-operator, centralised system: if the server is down,
nothing can be verified online (signed credentials still verify offline).
Key pinning is trust-on-first-use and only as strong as the protection of the
pin file. A signature proves **who** issued a certificate, not that its
content is true.

---

*Web Technology course project — Department of Computer Engineering.*

## License

[MIT](LICENSE) for CertiVault's own code; bundled third-party components keep their own licences (listed in `LICENSE`).
