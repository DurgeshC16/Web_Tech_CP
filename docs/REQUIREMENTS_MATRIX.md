# CertiVault — Requirements Matrix

| Requirement | Where implemented | Fully implemented? |
|---|---|---|
| Session | `src/utils/helpers.php` (session config, `check_session_expiry()`, `SESSION_IDLE_TIMEOUT`, `SESSION_ABSOLUTE_LIFETIME`), every page calls `require_role()` | Yes |
| Cookies | `helpers.php` (`current_theme()`, `cv_theme`), `public/login.php` (`cv_email`), `public/assets/js/theme.js` (writes `cv_theme`) | Yes |
| Data Encryption | `src/services/CryptoService.php` (`encryptPrivateKey`, `decryptPrivateKey`, RSA sign/verify, SHA-256 via `computeCertificateHash`), `APP_ENCRYPTION_KEY` | Yes |
| Authentication | `public/login.php`, `public/register_student.php`, `public/register_institution.php`, `public/activate_account.php`, `public/forgot_password.php`, `public/reset_password.php`, `public/change_password.php` | Yes |
| Authorization | `helpers.php` `require_role()`, `require_approved_institution()`, row-ownership in `public/view_certificate_admin.php`, `view_certificate_student.php`, `download.php` | Yes |
| Authentication & Authorization functions | `require_role`, `require_approved_institution`, `redirect_to_dashboard`, `validate_csrf_token`, `verify_otp`, `validate_password_strength` in `helpers.php` | Yes |
| CAPTCHA | reCAPTCHA v2 when keys set (`RECAPTCHA_*`, `verify_recaptcha()`), else offline arithmetic fallback (`generate_captcha()` / `verify_captcha()`); unified gate `validate_captcha()` + `captcha_field_html()` in `helpers.php`; used in `login.php`, `register_student.php`, `register_institution.php`, `forgot_password.php` | Yes |
| OTP verification | `helpers.php` `create_otp()` / `verify_otp()` / `hash_otp()`; OTP flow in `activate_account.php`, `reset_password.php`, `change_password.php` | Yes |
| Email verification | OTP emailed via PHPMailer in `create_otp()`; `scripts/test_smtp.php` | Yes |
| Required validator | Server `v_required()` (`src/utils/validators.php:16`); client `required` (`public/assets/js/validation.js:22,114`); on every user-editable control in login, register ×2, activate, forgot, reset, change, issue, supersede, revoke, super_admin reject, verify/index quick-verify | Yes |
| Range validator | Server `v_range()` (`validators.php:26`); client `range:min,max` (`validation.js:138`); CAPTCHA 2–18 in 4 forms + optional Validity 1–50 (`issue_certificate.php` server ~:60, input ~:293) | Yes |
| Compare validator | Server `v_compare()` (`validators.php:51`) for password/confirm on all 5 password pages + `v_date_after()` (`validators.php:164`) for expiry-after-issue in issue/supersede; client `match:` (`validation.js:143`) + `after:` (`validation.js:148`, used on both expiry inputs) | Yes |
| Email validator | Server `v_email()` (`validators.php:61`, filter_var + 254); client `email` (`validation.js:25,115`); every email field (login, register ×2, forgot, issue `student_email`) carries `required\|email` on both sides | Yes |
| Custom validators | `v_password_strong` (`:100`), `v_certificate_id` (`:127`, `verify.php:39`, pre-DB), `v_person_name` (`:137`), `v_otp` (`:152`), `v_date_range` (`:183`), `v_upload` (`:226`) — each mirrored client-side (`ruleStrong:32`, `ruleCertId:44`, `rulePersonName:47`, `ruleOtp:41`, `ruleDateRange:55`/`ruleAfter:69`, `ruleUpload:78`). No `v_institution_registration_no`: no such field exists (form has name/email/password only; no DB column) | Yes |
| Number validator | Server `v_number()` (`validators.php:75`); client `number` (`validation.js:29,116`); enrollment (`register_student.php:32`, digits-only) + Validity years (`issue_certificate.php`, integer 1–50) + CAPTCHA inputs client-side | Yes |
| Responsive application | `public/assets/css/style.css` (breakpoints 479 / 639 / 767 / 768 / 1280 + touch rules); 19 pages × 4 widths green in headless Chromium (TEST_PLAN #24) | Yes |
| Mobile | stacked `.split` panels, stacked tables with `data-labels`, 44px touch targets via `(pointer: coarse)`, hamburger nav <768px | Yes |
| Tablet | `≥768px` two-column form rows, 2-col grids | Yes |
| Laptop | `≥1024px` wider shells | Yes |
| Desktop | `≥1280px` 3-col feature grid, 1200px container | Yes |

Not fully implemented / noted:
- A real-device spot check (phone + desktop) is still worthwhile for feel
  issues automation cannot judge (QR camera scan, toast timing); layout
  itself is verified headlessly (see docs/TEST_PLAN.md #24).
