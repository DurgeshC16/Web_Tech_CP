# 07 — Testing

CertiVault has three layers of automated tests plus a manual plan
([TEST_PLAN.md](TEST_PLAN.md)):

| Layer | Command | Size |
|-------|---------|------|
| PHP CLI suites (unit + HTTP via `php -S`) | `php tests/run_all.php` | 19 suites, 690 checks |
| Browser — Smart Verify | `node tests/test_verify_ui.mjs` | 17 checks |
| Browser — whole app under CSP | `node tests/test_pages_browser.mjs` | 61 checks |
| CI (GitHub Actions) | every push / PR to `main` | all of the above on Linux |

## 1. Running locally

Prerequisites: MySQL/MariaDB running, PHP 8.2 with `pdo_mysql`, `openssl`,
`gd`, `fileinfo`, `mbstring`, `curl`; `composer install`; Node 21+ and
Chrome/Edge for the browser suites.

```sh
php tests/run_all.php            # PHP suites (exit 1 on any failure)
node tests/test_verify_ui.mjs    # Smart Verify in headless Chrome
node tests/test_pages_browser.mjs
```

* Tests use the isolated **`certivault_test`** database (override
  `CV_TEST_DB`), created from `schema.sql` on first use — drop it to start
  fresh. The dev database is never touched.
* Tests use their **own key-pin file** (`CV_KEY_PINS_FILE` is pointed at a
  temp file), never the dev pins.
* The harness and the app both use **strict SQL mode**, so invalid data fails
  locally exactly as it would in production.
* Connection: `CV_DB_HOST` / `CV_DB_USER` / `CV_DB_PASS` (default localhost /
  root / empty). On Windows the harness sets `OPENSSL_CONF` itself.
* `CV_SCREENSHOT_DIR=… node tests/test_pages_browser.mjs` also saves the
  analytics page in light, dark and mobile.

## 2. PHP suites (`run_all.php`)

Run on a fresh test database, 2026-11-15 (XAMPP PHP 8.2.12, MariaDB 10.4.32):

| Suite | Checks | Covers |
|-------|-------:|--------|
| `test_upload_suite.php` | 213 | upload validation; validators; flexible IDs; verification cascade; external sources + SSRF guard; Smart Verify text/file pipelines; trust score; PDF report; status API (incl. its own request budget); student stats |
| `test_crypto.php` | 11 | RSA, AES-GCM, sign/verify |
| `test_attested_credentials.php` | 31 | external-credential attestation |
| `test_transparency_log.php` | 17 | Merkle log + checkpoints |
| `test_rate_limit.php` | 20 | pre-lookup limiter: 30/31 boundary, free repeats, pruning, bounded state, legacy fallback, timing |
| `test_timezone.php` | 2 | PHP ↔ MySQL time zone |
| `test_workflow.php` | 25 | end-to-end lifecycle |
| `test_upload_http.php` | 7 | multipart uploads over HTTP |
| `test_otp.php` | 19 | OTP lifecycle via the dev mail spool |
| `test_config_guard.php` | 5 | production guard |
| `test_verify_http.php` | 32 | every verdict via token + GET ID, CSRF, browser-QR fallback, no inline scripts |
| `test_key_pinning.php` | 20 | the S6 key-swap attack (TAMPERED with pins, VALID without), append-only, fail-closed, strict mode, operator script |
| `test_credentials.php` | 28 | credential export, tampering, attacker key, no secrets, **OpenSSL CLI "Verified OK"**, HTTP endpoint |
| `test_bulk_issuance.php` | 33 | shared issuance pipeline, generated PDFs (hash / text / credential), rollback leaves nothing behind, issuance email, CSV parsing edge cases, formula injection |
| `test_two_factor.php` | 36 | RFC 6238 test vectors, window, replay, encrypted secret, recovery codes, real two-step login over HTTP |
| `test_analytics.php` | 15 | DST-safe day series, scoping, counts, scales |
| `test_auth_flows.php` | 65 | registration resume (student/institution, role switch, verified duplicate), activation-takeover guard, login message order (verify email → awaiting approval → rejected with reason), email normalisation + `v_email` rules, forgot→reset always reachable (unknown email, cooldown, no session), registration without `confirm_password` |
| `test_guest_quota.php` | 66 | GuestQuotaService (5/6 boundary, free repeats, rolling window, session vs IP, login exemption, limit 0, pruning, missing table fails open) + HTTP with the quota on (countdown, limit page without verdict, cleared cookies stay blocked, logged-in unlimited, long padded Smart Verify text can't alias another lookup) |
| `test_dataset.php` | 47 | dataset generator: dry-run, production refusal, counts, key pinning, every certificate's verdict, CSV formats (bulk CSV parsed by `BulkIssueService`), determinism, refusal on re-run, reset removes only dataset rows |
| **Total** | **690** | **19/19** |

`test_smtp_live.php` needs real SMTP credentials and is run by hand.

## 3. Browser suites

**`test_verify_ui.mjs` (17)** — real headless Chrome against `php -S`:
QR decoding of PDFs (page 1 and page 3), a bulk-generated certificate PDF, a
PNG; PDF without QR / corrupt PDF; upload and privacy flows resolved by the
browser-decoded QR; GET links; camera start/stop (fake stream); zero CSP
violations or exceptions.

**`test_pages_browser.mjs` (61)** — logs in through the real form (CAPTCHA
solved) as admin and student in isolated contexts and loads ~25 pages,
failing on any CSP violation, exception or unexpected redirect. Also: an
injected inline script must be blocked; `ui.js` behaviours; single issuance
through the form; bulk preview → confirm → results; Web Crypto credential
verification (genuine / tampered / attacker key); 2FA setup with a
browser-computed TOTP code and turning it off with a recovery code;
analytics (KPI = table sum, 30 focusable days, tooltip on focus, filters).

## 4. Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

1. **PHP job** — PHP 8.2 + MariaDB 10.11 (strict mode) service, `composer
   install`, `php -l` on every first-party file, `php tests/run_all.php`.
2. **Browser job** — Node 22 + Google Chrome, both browser suites.

Failures are summarised as a job annotation (visible without logging in).
CI has already caught real issues invisible on XAMPP: invalid ENUM values
silently stored in non-strict mode, an undefined variable on a result view,
mixed table collations, and flaky single-attempt QR decoding.

## 5. Coverage notes

* The manual plan still covers real SMTP delivery, real-device camera
  scanning, and visual feel.
* Static analysis beyond `php -l` is not yet in CI.
