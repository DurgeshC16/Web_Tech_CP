# 09 — Status & Roadmap

*Last reviewed: 2026-11-15.*

## 1. Current progress

### Done and working

| Area | Status |
|------|--------|
| Accounts: registration, email-OTP activation, login (CAPTCHA, lockout, remember-me), forgot/reset/change password | ✅ |
| Roles & authorization: super admin, approved institution admin, student, public verifier | ✅ |
| Institution approval → RSA key generation, AES-256-GCM key storage | ✅ |
| Issuance pipeline: validation, custom/auto IDs, canonical SHA-256, RSA signature, QR, single transaction with cleanup | ✅ |
| Verification cascade with six verdicts + audit logging | ✅ |
| Rate limiting before any lookup, constant-cost state (migration 014) | ✅ |
| Revocation and supersession (version chain) | ✅ |
| Student dashboard, downloads, 24-hour signed share links, verification counts | ✅ |
| Smart Verify (ID in any format, token, URL, QR image, file upload with raw-hash matching, browser hashing, camera scan) | ✅ |
| Trust score, PDF verification report (dompdf), public JSON status API | ✅ |
| Dev mail spool (`MAIL_TRANSPORT=file`) and dev OTP log | ✅ |
| External sources (Open Badges/Credly, remote DB, managed registry) — opt-in | ✅ |
| Attested external credentials — opt-in | ✅ |
| Versioned keys, published fingerprints, Merkle transparency log — opt-in | ✅ |
| Responsive UI (360–1280 px), light/dark theme | ✅ |
| All course requirements (see [REQUIREMENTS_MATRIX.md](REQUIREMENTS_MATRIX.md)) | ✅ |
| Automated tests | ✅ 347 checks, 10/10 suites green |

## 2. Change log of the 2026-11-15 clean-up

### Round 1 — repository and documentation

| Problem | Fix |
|---------|-----|
| `vendor/` committed as 7 **empty git sub-module links** plus generated autoload files; loading it **crashed** `report.php`, the PDF text pipeline and the test suite | `vendor/` git-ignored; `src/utils/composer_autoload.php` checks the install is complete first |
| `AttestedCredentialService::validateIssuerUrl()` regex never compiled, so URLs with spaces/tabs/backslashes were accepted | Fixed + regression checks |
| `config.php` redefined `APP_ENCRYPTION_KEY` / `DB_*` without guards | `defined()` guards |
| `seed_demo.php` reachable over HTTP | CLI-only |
| Messy README, no documentation set, stale test docs, draft paper in `docs/` | README rewritten, docs 01–09, paper moved to git-ignored `docs/private/` |

### Round 2 — bugs fixed

| # | Problem | Fix | Proof |
|---|---------|-----|-------|
| 1 | **Uploading an issued certificate file never matched**: raw file SHA-256 was compared with `sha256_hash`, which is the canonical digest; `stamped_sha256` was never written | Migration 013 adds `file_sha256`, stored at issue/supersede/seed; lookup uses it (then `stamped_sha256`); active + newest wins when files are shared; `scripts/backfill_file_hashes.php` for old rows (integrity-checked) | Unit checks + end-to-end: all 5 seeded certificates resolve from their real files with VALID / EXPIRED / REVOKED / SUPERSEDED / VALID |
| 1b | Every demo certificate used the same file bytes | Each demo file embeds its ID and title | same E2E run |
| 2 | **Unfinished work in `git stash@{0}`** — the documented `MAIL_TRANSPORT=file` option did nothing | Mail transport ported (`deliver_mail()`, `write_mail_to_file()`, production guard) | `test_otp` 3/17 → 17/17, `test_config_guard` 4/5 → 5/5 |
| 3 | Composer packages missing → PDF report and PDF text extraction disabled | `composer install` (lock file unchanged) | PDF report checks now execute and pass |
| 4 | **Rate limiter ran after the lookup** (the 429 came only after the DB query, hashing and RSA check), cost grew with log history, query ran twice per request, inconsistent `>`/`>=` | Gate moved before any lookup; bounded `verify_rate` table (migration 014); `Retry-After` header | 30 lookups → 200, 31st → 429 with **no** audit row written, repeat → 200 (Apache/`php -S`); 0.65 ms vs 22.8 ms at 30 000 logged rows |
| 5 | Local dev database was only at migration ~004 (no `login_attempts`, `remember_tokens`, key history…) — login/issuance would fail | Backed up to `private_data/backups/`, migrations 001–014 applied; schema verified identical to `schema.sql` (118 columns, 43 indexes before 014) | column/index diff |
| 6 | Approved institution #3 had no signing key (approved by an old build while key generation failed) | `repair_institution_keys.php 3` → key v1, decrypts and matches | `check_institution_keys.php` |
| 7 | Non-public folders (`src/`, `database/`, `docs/`, `.git/`…) were web-reachable when the repo root sits in `htdocs` | Deny `.htaccess` per folder + root rules for dotfiles and `.md/.sql/.log/.lock` | Real XAMPP Apache run: public pages, CSS and pdf.js → 200, `check_environment.php` → login redirect, `/.well-known/` rewrite still reached; 16 private paths (`src/`, `database/`, `docs/`, `tests/`, `vendor/`, `scripts/seed_demo.php`, `private_data/`, `.git/`, `.gitignore`, `.rnd`, `README.md`, `composer.*`, repo root) → 403/404 |
| 8 | Seeded super admin shipped with password `password` | Seeded with an unusable hash; `set_super_admin.php` required | `password_verify()` false for every input |
| 9 | phpqrcode flooded the error log under PHP 8.2 (447 deprecations per 8 QR codes) | Declared `$cmyk`, explicit int casts | 0 deprecations; QR images byte-identical to before |

## 3. Still open

### 🟠 Needs your decision

* **Tabbed scanner UI from `git stash@{0}`.** The stash also holds an
  alternative `verify.php` with camera / QR-image / PDF / ID tabs, browser
  PDF→QR decoding via pdf.js, `GET ?id=` lookups and decode limits. Current
  Smart Verify already covers ID, file, browser hashing and camera scanning;
  the genuine gap is decoding a QR from a PDF page *in the browser*.
  `public/assets/js/verify-scan.js` and `public/assets/js/vendor/pdf*.js`
  are committed but unused, and `test_verify_http.php` (7/21) tests that UI.
  Options: port the PDF-QR tab into Smart Verify, or drop the stash, delete
  the orphaned assets and rewrite `test_verify_http.php` for the current
  page. After that, `git stash drop`.

### 🟡 Security hardening (remaining work)

* **CSP allows `'unsafe-inline'`** — move inline `<script>` blocks / `on*=`
  handlers to `assets/js/`, replace `style=` attributes with classes, emit a
  per-request nonce.
* **Key pinning not enforced** — compare the signing key's fingerprint with
  a copy kept outside the database before RSA verification.

### 🟢 Project hygiene / completeness

* **CI** — GitHub Actions: `php -l` + `php tests/run_all.php` against a
  MariaDB service.
* **Local leftovers** — 145 `verifyui-*.pdf` browser-test fixtures in
  `private_data/uploads/` (git-ignored, unused by any database) can be
  deleted; `private_data/php_errors.log` can be truncated.
* **Your dev super admin** still has the old `password` hash (only fresh
  installs get the locked seed) — run `php scripts/set_super_admin.php`.
* **Paper refresh** — update numbers to match the repository (doc 08 §6) and
  fix the reference-list notes left in the draft.
* Real-device QR camera check; public HTTPS demo deployment; append-only
  revocation log and trusted timestamping; multi-core load test; employer
  usability study; align the brief's "Verifier login role" wording with the
  account-free verifier.
