# CertiVault — Manual Test Plan

Each case lists steps + expected result, and whether it has been verified by code reading or is "manual" (needs a human in the browser).

## Authentication & registration
1. **Registration with email OTP** — register a student → mail sent → enter code + set password on activate_account.php → account activated → can log in. *(verified by code reading; manual run recommended with a real SMTP account)*
2. **Resend cooldown** — request resend within 60s → cooldown message; no new code issued. *manual*
3. **Wrong-OTP lockout** — enter 5 wrong codes → code invalidated; must request a new one. *verified by code reading / manual*
4. **Forgot/reset password** — request reset, open code, set new password matching `v_password_strong`, login with new password. *manual*
5. **Change password** — log in, submit current + new + OTP → password updates, notification email, old password fails, new works. *manual*
6. **Login lockout** — 5 failed attempts → 15-minute lock banner; further login blocked until unlock. *verified by code reading / manual*
7. **CAPTCHA failure** — submit a login with a wrong CAPTCHA → per-field error on captcha, login blocked. *verified by code reading / manual*

## Session & cookies
8. **Session timeout** — log in, wait 30+ min (or lower the constant for testing) → next page load redirects to `login.php?expired=1`. *verified by code reading; manual quick check by temporarily setting `SESSION_IDLE_TIMEOUT = 5`*
9. **Logout** — POST logout → session destroyed, cookie expired, `login.php` reached; subsequent authenticated GET redirects to login. *verified by code reading / manual*
10. **Remember-email** — login with checkbox ticked → `cv_email` cookie set, next visit email pre-filled + box checked; untick → cookie deleted. *manual*
11. **Theme cookie** — toggle Dark → `cv_theme=dark`; reload → `<html data-theme="dark">` persists; invalid value falls back to light. *manual*

## Institution admin
12. **Approve** — super admin approves a pending institution → RSA keys generated, admin can issue certs. *manual*
13. **Reject** — reject with a reason → status `rejected`, reason visible in Rejected tab; that institution's session/page access is denied (require_approved_institution). *verified by code reading / manual*
14. **Issue** — issue a certificate → success seal card + QR, file/QR cleaned up on failure. *manual*
15. **Revoke** — revoke with reason → status/verification verdict becomes REVOKED, revoked_at + revoked_by shown. *verified by code reading / manual*
16. **Supersede** — issue corrected version → old shows superseded, new active, QR works for new one. *manual*

## Verification (verify.php / share.php)
17. **VALID** — correct certificate ID → green seal, details diploma card. *verified*
18. **TAMPERED** — alter an uploaded file → TAMPERED verdict on both pages. *verified*
19. **EXPIRED** — expiry in the past → EXPIRED. *verified*
20. **REVOKED** — revoked cert → REVOKED (wins over expired *and* over tampered: status is server-authoritative). *verified e2e* evidenced by `verification_logs` rows VALID → TAMPERED → REVOKED for one QR token.
21. **SUPERSEDED** — superseded cert → SUPERSEDED + link to current. *manual*
22. **INVALID** — unknown ID, or malformed ID/token → INVALID, no DB hit for malformed. *verified*
23. **Share-link expiry** — use an old share token → "This share link has expired." *manual*

## Responsive check (four widths, touch emulation)
24. **360 / 768 / 1024 / 1280** on index, login, verify, register_student, register_institution, forgot_password, share, student_dashboard, admin_dashboard, view_certificate_admin, view_certificate_student, audit_logs, super_admin, change_password, issue_certificate, revoke_certificate, supersede_certificate — headless Chromium with touch on, asserting per page-width: no document scroll past the viewport, no element clipped outside it, every button-like control ≥44px tall, every table inside `.table-wrap` (scrolls internally or stacked with `data-labels` ≤639px), `.form-row` single-column <768px. *verified 76/76 (plus a client-side `range` validator fix this run exposed: `(v + 0)` concatenated strings so every CAPTCHA failed — now `Number(v)`).* Text links inside sentences keep inline sizing (WCAG inline exception).

Legend: *verified* = reproduced against the running app during development; *verified by code reading* = traced in source; *manual* = execute in browser.

## Automated CLI tests (`tests/`, no framework)
Prerequisites: MariaDB/MySQL running (`CV_DB_HOST`/`CV_DB_USER`/`CV_DB_PASS`
env or the localhost/root defaults). On Windows XAMPP the suite relaunches
itself with `OPENSSL_CONF` set so RSA key generation works.

```
php tests/run_all.php            # all four suites + summary (exit 1 on failure)
php tests/test_validators.php    # single suite (each file runs standalone)
```

- `test_validators.php` (34): `v_required`, `v_range`, `v_compare`,
  `v_email`, `v_number`, `v_certificate_id`, `v_person_name`,
  `v_password_strong`, `v_date_range` — accept + reject cases each.
- `test_crypto.php` (8): RSA keygen, GCM encrypt/decrypt round trip,
  sign + verify, verify failure after a 1-byte hash change and with a
  wrong public key.
- `test_upload_validation.php` (12): `v_upload()` against mocked
  `$_FILES` for every error code. `is_uploaded_file()` is false under
  CLI by design, so the `UPLOAD_ERR_OK` happy path is asserted at its
  guard message here and covered live by the multipart matrix below.
- `test_certflow.php` (7): issues a certificate in an isolated
  `certivault_test` database (auto-created, schema imported; override
  with `CV_TEST_DB`) and asserts VALID → TAMPERED → REVOKED
  (incl. revoked-wins-over-tampered) → EXPIRED → INVALID, then
  removes its fixtures. The dev database is never touched.

## Live upload matrix (multipart, admin session)
- [ ] Small PDF (~300 B, `application/pdf`) → issued. *verified e2e*
- [ ] 4 MB PNG (`image/png`) → issued. *verified e2e*
- [ ] 6 MB PDF → "form size limit (MAX_FILE_SIZE)… max 5 MB". *verified e2e*
- [ ] EXE bytes named `.pdf` → "content does not match". *verified e2e*
- [ ] Empty file → rejected. *verified e2e*
- [ ] Download serves `CV-YYYY-NNNNNN.<ext>` with `nosniff`. *verified e2e*

## Validator checklist (server is source of truth, client is UX only)
Server: `src/utils/validators.php`. Client: `public/assets/js/validation.js` via `data-validate`. For each row, run once with JS on (expect inline error, no submit) and once with JS disabled (expect the same server-side field error after submit — proving the server never trusts the client).

- [ ] **Required** — submit any form empty (login, register, issue): client `required` blocks; server `v_required()` returns per-field errors. *manual*
- [ ] **Range** — CAPTCHA `0`, `1`, `19`, `abc` on login: client `number|range:2,18` blocks; server `v_range($captcha, 2, 18)` rejects. (Certificate validity windows use the date-range pair `v_date_range` / `daterange`+`after` on issue/supersede.) *verified by code reading / manual*
- [ ] **Compare** — mismatched password/confirm on register_student, register_institution, activate_account, reset_password, change_password: client `match:#…` blocks; server `v_compare()` rejects. *manual*
- [ ] **Email** — `not-an-email` and a 255-char address on login/register/forgot/issue: client `email` blocks; server `v_email()` (filter_var + 254 cap) rejects. *manual*
- [ ] **Number** — CAPTCHA `5.5`/`abc`: client `number` blocks; enrollment `12AB` on register_student: client `enrollment` (`^\d{5,20}$`) blocks, server `v_number(…, 0)` + `ctype_digit` rejects. *verified by code reading / manual*
- [ ] **Custom certid** — `XX-123` on index/verify quick-verify: client `certid` blocks; server `v_certificate_id()` returns INVALID without a DB hit. *manual*
- [ ] **Custom personname** — `John123` on register_student / issue: client `personname` blocks; server `v_person_name()` rejects. *manual*
- [ ] **Custom strong** — `password1` (no upper/special) on any password set: client `strong` + meter blocks; server `v_password_strong()` (8–72, upper/lower/digit/special) rejects. *manual*
