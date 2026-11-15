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
| Verification cascade with six verdicts + audit logging + rate limiting | ✅ |
| Revocation and supersession (version chain) | ✅ |
| Student dashboard, downloads, 24-hour signed share links, verification counts | ✅ |
| Smart Verify (ID in any format, token, URL, QR image, file, browser hashing) | ✅ — except byte-hash matching (bug 1) |
| Trust score, PDF verification report, public JSON status API | ✅ (report needs `composer install`) |
| External sources (Open Badges/Credly, remote DB, managed registry) — opt-in | ✅ |
| Attested external credentials — opt-in | ✅ |
| Versioned keys, published fingerprints, Merkle transparency log — opt-in | ✅ |
| Responsive UI (360–1280 px), light/dark theme | ✅ |
| All course requirements (see [REQUIREMENTS_MATRIX.md](REQUIREMENTS_MATRIX.md)) | ✅ |
| Automated tests | ✅ 314 checks, 8/8 suites green |

### Fixed during the 2026-11-15 clean-up

| Problem | Fix |
|---------|-----|
| `vendor/` was committed as 7 **empty git sub-module links** plus generated autoload files — every clone (and this machine) had a broken Composer install, and loading it **crashed** `report.php`, the PDF text pipeline and the test suite with a fatal error | `vendor/` untracked and git-ignored; new `src/utils/composer_autoload.php` checks the install is complete before loading it, so the features degrade gracefully |
| `AttestedCredentialService::validateIssuerUrl()` used a regex that **failed to compile** (`[\x00-\x20\]`), so URLs containing spaces, tabs or backslashes were never rejected | Regex fixed; 3 regression checks added |
| `config.php` redefined `APP_ENCRYPTION_KEY` and `DB_*` without `defined()` guards — setting them in `config.local.php` (as the example suggests) produced "already defined" warnings | Guards added; local overrides now work for DB settings too |
| `scripts/seed_demo.php` had no CLI guard and was reachable over HTTP in an htdocs layout | Refuses non-CLI requests |
| `run_all.php` ran only 4 of the 8 passing suites | Now runs all 8 |
| README was a pile of phase notes with broken characters | Rewritten; full documentation set in `docs/` |
| `.gitignore` gaps (vendor, private docs, editor files) | Reorganised and extended |
| Draft research paper (with author emails) in `docs/` | Moved to git-ignored `docs/private/` |

## 2. Known bugs and gaps

### 🔴 P0 — fix next

1. **Smart Verify cannot match an uploaded original file by hash.**
   `FileVerifyService::findLocalByContentHash()` compares the uploaded
   file's raw SHA-256 with `certificates.sha256_hash`, but that column holds
   the *canonical digest* `SHA-256(id|…|SHA-256(file))`, so it never
   matches a really issued certificate. `stamped_sha256` is never written by
   any code path. Browser "privacy mode" hashing relies on the same lookup.
   The unit test hides this because its fixture stores the raw file hash.
   **Plan:** migration `013` adding `certificates.file_sha256 CHAR(64)` +
   index; populate it in `issue_certificate.php`, `supersede_certificate.php`
   and `seed_demo.php`; a one-off backfill script hashing existing files;
   match on `file_sha256` (then `stamped_sha256`); fix the test fixture to use
   the real issuance pipeline.

2. **Unfinished work parked in `git stash@{0}` ("before-pull-2026-10-26").**
   It was stashed before a pull and never re-applied. Its *tests* were later
   committed (that is why `test_otp`, `test_config_guard` and
   `test_verify_http` fail) but its *source changes* were not:
   * `MAIL_TRANSPORT=file` dev mail spool (`deliver_mail()` /
     `write_mail_to_file()` in `helpers.php`, constants + production guard in
     `config.php`) — referenced by `config.local.php.example`, so the
     documented option currently does nothing;
   * a tabbed scanner UI for `verify.php` (camera / image / PDF / ID tabs,
     `GET ?id=`, browser decode limits `VERIFY_PDF_MAX_*`) with CSS;
   * README / TEST_PLAN / matrix edits.
   **Plan:** inspect with `git stash show -p stash@{0}`, port the mail
   transport (low conflict), decide whether the tabbed scanner should be
   merged into the current Smart Verify panel (high conflict in
   `verify.php`), enable the three tests, then `git stash drop`.
   *Do not run `git stash pop` blindly — `verify.php` has diverged.*

3. **Composer packages not installed on the dev machine** — the PDF report
   and PDF text extraction are disabled until `composer install` is run.

4. **Rate-limiter scalability patch from the paper is missing.**
   `VerificationService::recentLookupCount()` still runs
   `COUNT(DISTINCT query_value)` over `verification_logs`, which the paper
   measured degrading from 3.8 ms to 54.7 ms at 30 000 rows. **Plan:** a
   small `verify_rate (ip, value_hash, seen_at)` table capped at 31 rows per
   IP, keep `verification_logs` as the audit trail, extend
   `test_rate_limit.php`.

### 🟠 P1 — security hardening

5. **CSP allows `'unsafe-inline'`** — move inline `<script>` blocks and
   `on*=` handlers into `assets/js/`, replace `style=` attributes with
   classes, then emit a per-request nonce.
6. **Key pinning not enforced** — compare the signing key's fingerprint
   with a copy stored outside the database (file or published list) before
   RSA verification; show a mismatch as TAMPERED.
7. **Non-public directories are web-reachable when the repo root is
   served** (htdocs clone, `php -S` without `-t public`). Add
   `Require all denied` `.htaccess` files to `src/`, `database/`, `tests/`,
   `docs/` and `scripts/` (whitelisting `check_environment.php`), or make the
   `public/` vhost mandatory.
8. **Seeded super admin uses `password`** — force a password change on first
   login, or generate a random one at install time.

### 🟡 P2 — project hygiene

9. **CI** — GitHub Actions workflow: `php -l` on all files +
   `php tests/run_all.php` against a MariaDB service container.
10. **phpqrcode PHP 8 deprecations** (optional parameters before required
    ones in `qrimage.php`) fill the error log — patch the signature or move
    to a maintained Composer QR library.
11. **Local leftovers** — 145 `verifyui-*.pdf` browser-test fixtures sit in
    `private_data/uploads/` (git-ignored, unreferenced by the dev database);
    safe to delete. `private_data/php_errors.log` can be truncated.
12. **phpqrcode `cache/mask_*` files** (320) are runtime-generated but
    tracked; they could be ignored.
13. **Refresh the research paper's numbers** to match the repository (doc 08
    §6), and fix the reference-list notes left in the draft.

### 🟢 P3 — product completeness

14. Real-device check of camera QR scanning and mobile feel.
15. Deploy a public HTTPS demo (needed for the paper's URL claims and for
    employers to try it).
16. Append-only revocation log and trusted timestamping (paper future work).
17. Multi-core load test and a small usability study with employers.
18. Align wording between the brief and the app: the brief lists
    "Verifier" as a login role, but verification needs no account.

## 3. Suggested order of work

1. Bug 1 (file-hash matching) — user-visible, small, well-scoped.
2. Bug 2 (stash) — recover the mail transport; decide on the scanner UI.
3. `composer install` and re-run tests (report PDF checks start executing).
4. Bug 4 (rate limiter) — makes the repo match the paper.
5. CI (item 9) so every later change is checked automatically.
6. Security items 5–8.
7. Paper refresh and public demo deployment.
