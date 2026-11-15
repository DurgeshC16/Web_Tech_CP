# CertiVault — Digital Certificate Issuance & Verification

> Issue tamper-evident digital certificates and let anyone verify them in
> seconds — by QR code, certificate ID, or the file itself.

CertiVault is a PHP + MySQL web platform built as a **Web Technology course
project**. Institutions issue certificates that are bound to their identity
with a **SHA-256 canonical fingerprint** and an **RSA-2048 digital
signature**, and carry a **QR code**. Employers and other verifiers check a
certificate **without creating an account**, and get one clear, audited
verdict: **VALID, TAMPERED, EXPIRED, REVOKED, SUPERSEDED or INVALID**.

![PHP](https://img.shields.io/badge/PHP-8.2-777BB4?logo=php&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL%20%2F%20MariaDB-10.4%2B-4479A1?logo=mysql&logoColor=white)
![Tests](https://img.shields.io/badge/tests-314%20checks%20passing-brightgreen)
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
9. [Testing](#testing)
10. [Security](#security)
11. [Documentation](#documentation)
12. [Project status & roadmap](#project-status--roadmap)
13. [Limitations](#limitations)

---

## Why CertiVault

Certificates are shared as PDFs and images, which anyone can edit. The
person receiving one usually has no quick way to check it. Blockchain
solutions remove the central registry but add fees and latency, and still
can't prove a ledger identity belongs to a real institution.

CertiVault uses plain, well-understood cryptography instead:

| Mechanism | What it guarantees |
|-----------|--------------------|
| Unique certificate ID | Fast lookup (`CV-2026-000123` or a custom ID) |
| SHA-256 canonical fingerprint of all fields **and** the file | Any change is detected (**integrity**) |
| RSA-2048 signature by the approved institution | Proves who issued it (**authenticity**) |
| QR code with a 256-bit random token | One-scan verification, no personal data inside |
| Status lifecycle: active / expired / revoked / superseded | Errors can be corrected without deleting history |

## Features

**Roles**
- **Super admin** — approves or rejects institutions (approval generates their RSA key pair) and manages external sources.
- **Institution admin** — issues, revokes and supersedes certificates, reads audit logs, attests students' external credentials, rotates keys.
- **Student** — views and downloads certificates, shares 24-hour signed links, sees how often each certificate was verified.
- **Verifier** — no account; scans the QR, types the ID, or uploads the file.

**Verification**
- **Smart Verify**: one box accepts an ID in any format, a QR token, a URL, a QR image or the certificate file (with an optional in-browser hashing privacy mode).
- **Six-verdict cascade** with a fixed precedence and a full audit log.
- **Trust score** (0–100) with a per-check checklist.
- **PDF verification report** with a QR back to the live result.
- **Public JSON status API** (`api_status.php`).

**Lifecycle & trust** (optional features are opt-in)
- Revocation with reason, and supersession that keeps the version chain.
- Versioned institution keys with public fingerprints (`/.well-known/certivault-keys.json`).
- Merkle-tree **transparency log** with signed checkpoints and inclusion proofs.
- **External sources** (Open Badges / Credly, read-only remote DB), always labelled *not verified by CertiVault*.
- **Attested external credentials** — institutions sign students' Coursera / Credly / NPTEL claims.

**Accounts & UX**
- Email-OTP activation and password reset, CAPTCHA, login lockout, remember-me, session timeouts.
- Responsive UI (360 → 1280 px), light/dark theme, validation on both client and server.

## How it works

```
ISSUE (institution)                              VERIFY (anyone, no login)
───────────────────                              ─────────────────────────
validate input + file                            QR token / ID / URL / file
   │                                                │  format check + rate limit
store file outside web root                         ▼
   │                                             exists? ─────────── no → INVALID
h = SHA-256(id|inst|student|title|                revoked? ────────── yes → REVOKED
            issued|expires|SHA-256(file))         superseded? ─────── yes → SUPERSEDED
   │                                             recompute h == stored? no → TAMPERED
σ = RSA-Sign(institution private key, h)          RSA-Verify(h, σ)? ── no → TAMPERED
   │                                             expired? ─────────── yes → EXPIRED
QR → verify.php?token=<256-bit random>                                     VALID
   │                                                │
commit in one DB transaction                     log to verification_logs,
(rollback deletes file + QR)                     trust score, PDF report
```

Full walkthrough: [docs/01_PROJECT_OVERVIEW.md](docs/01_PROJECT_OVERVIEW.md).

## Tech stack

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3 (custom responsive design system), vanilla JavaScript, html5-qrcode, pdf.js |
| Backend | PHP 8.2 (no framework): sessions, cookies, PDO, OpenSSL |
| Database | MySQL / MariaDB |
| Cryptography | SHA-256, RSA-2048, AES-256-GCM, HMAC-SHA-256, bcrypt |
| Libraries | PHPMailer, phpqrcode, ZXing PHP port (vendored); dompdf, smalot/pdfparser (Composer, optional) |
| Environment | XAMPP (Apache + MariaDB + PHP) or `php -S` |

## Project structure

```
Web_Tech_CP/
├── public/          Web root: page controllers, assets (CSS/JS), generated QR codes
├── src/
│   ├── config/      config.php, Database.php, config.local.php.example
│   ├── services/    Crypto, Verification, SmartVerify, FileVerify, TrustScore,
│   │                Report, StatusApi, ExternalSource, AttestedCredential,
│   │                TransparencyLog, StudentStats, QR
│   ├── utils/       helpers.php, validators.php + vendored PHPMailer / phpqrcode / qrdecoder
│   └── partials/    Shared head / header / footer templates
├── database/        schema.sql (fresh install) + migrations/001–012 (upgrades)
├── scripts/         CLI tools: seeding, super-admin setup, SMTP / environment / key checks, checkpoints
├── tests/           Plain-PHP CLI suites + Node browser tests
├── private_data/    Uploaded certificates, logs, mail spool (not web-accessible; contents git-ignored)
├── docs/            Full documentation
└── composer.json    Optional PHP dependencies (vendor/ is git-ignored)
```

Details: [docs/02_ARCHITECTURE.md](docs/02_ARCHITECTURE.md).

## Quick start

**Requirements:** PHP 8.2+ (`pdo_mysql`, `openssl`, `fileinfo`, `gd`,
`mbstring`), MySQL/MariaDB, optionally Composer. XAMPP provides all of these.

```sh
# 1. Get the code
git clone https://github.com/DurgeshC16/Web_Tech_CP.git
cd Web_Tech_CP

# 2. Optional: PDF report + PDF text extraction
composer install

# 3. Create the database (creates `certivault` + tables + super admin)
mysql -u root < database/schema.sql            # or phpMyAdmin → Import

# 4. Local config (git-ignored): SMTP credentials + secrets
copy src\config\config.local.php.example src\config\config.local.php

# 5. Set a real super-admin login (the seeded password is "password")
php scripts/set_super_admin.php

# 6. Optional demo data
php scripts/seed_demo.php

# 7. Run — serve ONLY the public/ folder
php -S localhost:8081 -t public
```

Open <http://localhost:8081>. With Apache, point the virtual host's
`DocumentRoot` at `public/`. Existing databases: apply the missing files in
`database/migrations/` in order ([docs/03_DATABASE.md](docs/03_DATABASE.md)).

## Configuration

Settings are read from `src/config/config.local.php`, then environment
variables, then the defaults in `src/config/config.php`.

| Setting | Purpose |
|---------|---------|
| `CV_DB_HOST` / `CV_DB_USER` / `CV_DB_PASS` / `CV_DB_NAME` | Database connection (defaults: `localhost` / `root` / empty / `certivault`) |
| `CV_ENCRYPTION_KEY` | Encrypts institution private keys. **Set it before approving the first institution.** |
| `CV_OTP_PEPPER`, `CV_SHARE_SECRET` | HMAC secrets for OTP codes and share links |
| `SMTP_*` | Email delivery for OTPs (Gmail needs an App Password) |
| `CV_RECAPTCHA_SITE_KEY` / `_SECRET_KEY` | Google reCAPTCHA; without them an offline arithmetic CAPTCHA is used |
| `CV_BASE_URL` | Only needed behind a proxy; otherwise derived per request |
| `CV_ENV=production` | Refuses to start while development secrets are still set |
| Feature flags | `CV_SMART_VERIFY`, `CV_API_ENABLED` (on by default); `CV_EXT_REGISTRY_ENABLED`, `CV_ATTESTED_CREDENTIALS_ENABLED`, `CV_CERTIFICATE_TRANSPARENCY_ENABLED` (off by default) |

Full reference, Gmail setup, no-SMTP development mode and troubleshooting:
[docs/06_SETUP_AND_CONFIGURATION.md](docs/06_SETUP_AND_CONFIGURATION.md).

## Demo accounts

After `php scripts/seed_demo.php`:

| Role | Email | Password |
|------|-------|----------|
| Institution admin | `demo.institution@certivault.test` | `DemoInst@2026` |
| Student | `demo.student@certivault.test` | `DemoStudent@2026` |
| Super admin | `superadmin@certivault.com` | `password` *(change with `set_super_admin.php`)* |

These are local demo credentials only. Never reuse them on a server.

## Testing

```sh
php tests/run_all.php     # uses an isolated `certivault_test` database
```

**314 checks across 8 suites pass** (crypto, validators, uploads, the
verification cascade, Smart Verify, trust score, status API, attested
credentials, transparency log, rate limits, full workflow, HTTP uploads).
Browser checks (`tests/*.mjs`) cover the verify UI and responsive layout.
See [docs/07_TESTING.md](docs/07_TESTING.md) and the manual
[test plan](docs/TEST_PLAN.md).

## Security

- bcrypt passwords; HMAC-hashed email OTPs (10-minute expiry, 5 attempts, resend cooldown, hourly cap)
- Login lockout (5 failures / 15 min), CAPTCHA, session regeneration, 30-minute idle and 8-hour absolute timeouts
- Role-based plus row-level authorization; CSRF tokens on every POST; prepared statements everywhere; escaped output
- Uploads checked by both extension and real MIME type (≤ 5 MB) and stored outside the web root
- Verification rate limit (30 distinct lookups / 10 min / IP → HTTP 429), and every lookup is logged
- Security headers (CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, HSTS)
- SSRF-guarded external lookups (HTTPS only, host allow-list, public IPs only)

Threat model and known gaps: [docs/04_SECURITY_AND_CRYPTOGRAPHY.md](docs/04_SECURITY_AND_CRYPTOGRAPHY.md).

## Documentation

| Doc | Topic |
|-----|-------|
| [01 Project Overview](docs/01_PROJECT_OVERVIEW.md) | Problem, roles, end-to-end methodology, verdicts |
| [02 Architecture](docs/02_ARCHITECTURE.md) | Layers, page map, services, libraries |
| [03 Database](docs/03_DATABASE.md) | Tables, relationships, migrations |
| [04 Security & Cryptography](docs/04_SECURITY_AND_CRYPTOGRAPHY.md) | Hashing, signatures, key storage, threat model |
| [05 Features & User Guide](docs/05_FEATURES_AND_USER_GUIDE.md) | Step-by-step per role, every feature |
| [06 Setup & Configuration](docs/06_SETUP_AND_CONFIGURATION.md) | Install, config reference, email, troubleshooting, production checklist |
| [07 Testing](docs/07_TESTING.md) | Automated and browser tests, results |
| [08 Research Summary](docs/08_RESEARCH_SUMMARY.md) | Findings of the accompanying research paper |
| [09 Status & Roadmap](docs/09_STATUS_AND_ROADMAP.md) | Progress, known bugs, next steps |
| [Requirements Matrix](docs/REQUIREMENTS_MATRIX.md) | Course requirements → implementation |
| [Project Brief (PDF)](docs/reference/CertiVault_Project_Brief.pdf) | Original project brief |

## Project status & roadmap

All core features and course requirements are implemented and tested. The
next steps, in priority order ([details](docs/09_STATUS_AND_ROADMAP.md)):

1. Fix Smart Verify's file-hash matching (store the raw file SHA-256 at issuance).
2. Recover the unfinished work parked in `git stash@{0}` (dev mail spool, tabbed scanner UI).
3. Run `composer install` locally so the PDF report and PDF text extraction work.
4. Port the paper's scalable rate limiter.
5. Add CI, remove `'unsafe-inline'` from the CSP, enforce key pinning.

## Limitations

CertiVault is a single-operator, centralised prototype. If the server is
down, nothing can be verified. An attacker with write access to the database
*including the key table* could swap an institution's key; published
fingerprints and the transparency log narrow that gap but do not close it
automatically. A signature proves **who** issued a certificate, not that its
content is true.

---

*Web Technology course project — Department of Computer Engineering.*
