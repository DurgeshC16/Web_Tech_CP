# 07 — Testing

CertiVault uses plain-PHP CLI test scripts (no framework) plus two Node.js
browser scripts. Manual end-to-end cases are in [TEST_PLAN.md](TEST_PLAN.md).

## 1. Running the automated suite

Prerequisites: MySQL/MariaDB running; `php` on PATH (XAMPP:
`C:\xampp\php\php.exe`).

```sh
php tests/run_all.php
```

* Uses an **isolated database `certivault_test`** (override with
  `CV_TEST_DB`); the dev database is never touched. It is created and
  loaded from `database/schema.sql` automatically.
* Connection via `CV_DB_HOST` / `CV_DB_USER` / `CV_DB_PASS` (default
  `localhost` / `root` / empty).
* On Windows the harness relaunches itself with `OPENSSL_CONF` set so RSA
  key generation works.
* Every test file can also be run on its own: `php tests/test_crypto.php`.

## 2. Suites in `run_all.php`

Results from the run on 2026-11-15 (XAMPP PHP 8.2.12, MariaDB 10.4.32, Composer packages installed):

| Suite | Checks | Covers |
|-------|-------:|--------|
| `test_upload_suite.php` | 212 | `v_upload()` matrix; all validators; flexible certificate-ID lookup; verification cascade; external-source adapters + SSRF guard; Smart Verify text/file pipelines; trust score; PDF report; status API; student stats; either/or input planning |
| `test_crypto.php` | 11 | RSA keygen, GCM wrap/unwrap, sign/verify, tamper and wrong-key failures |
| `test_attested_credentials.php` | 31 | Exact-host URL validation (incl. malformed-URL regression), canonical payload, attestation/withdrawal verdicts, trust-score cap |
| `test_transparency_log.php` | 17 | Merkle root, inclusion proofs, leaf hashing, checkpoint signing |
| `test_rate_limit.php` | 20 | Verify rate limiter: 30/31 boundary, free repeats, expiry/pruning, bounded state under a flood, legacy fallback, timing vs the old query |
| `test_timezone.php` | 2 | PHP ↔ MySQL session time-zone alignment |
| `test_workflow.php` | 25 | End-to-end register → approve → issue → verify → revoke/supersede |
| `test_upload_http.php` | 7 | Real multipart uploads through `php -S` |
| `test_otp.php` | 17 | OTP create/verify, hashing, cooldown, hourly cap, attempt lockout, single use — via the `MAIL_TRANSPORT=file` spool |
| `test_config_guard.php` | 5 | Production guard: default secrets and the file mail transport are refused |
| **Total** | **347** | **10/10 suites green** |

## 3. Tests not yet in `run_all.php`

| Test | Status | Why |
|------|--------|-----|
| `test_verify_http.php` | 7 pass / 14 fail | Expects the tabbed scanner UI and `GET ?id=` lookups from the same stash |
| `test_smtp_live.php` | not run | Needs real SMTP credentials (`tests/support/smtp_capture_server.py` provides a local capture server) |

## 4. Browser tests (Node.js)

| Script | Purpose |
|--------|---------|
| `tests/test_verify_ui.mjs` | Drives `verify.php` in headless Chromium (QR image, PDF, ID flows). Seed fixtures first with `php tests/seed_browser_fixtures.php` |
| `tests/support/responsive_check.mjs` | 19 pages × 4 widths (360/768/1024/1280): no overflow, ≥ 44 px touch targets, table wrapping |

These write fixture PDFs named `verifyui-*.pdf` into `private_data/uploads/`
(git-ignored). Delete them after a run if you don't need them.

## 5. Static checks

```sh
# Lint every first-party PHP file
git ls-files '*.php' | grep -v -e phpqrcode -e PHPMailer -e qrdecoder | xargs -n1 php -l
```

All first-party files lint clean.

## 6. Known test-coverage gaps

* No automated test for the CSP or the security headers.
* No CI — tests run only on a developer machine.
