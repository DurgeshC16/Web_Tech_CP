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
| Required validator | `v_required()` in `src/utils/validators.php`; used on required fields in login, register, etc. | Yes |
| Range validator | `v_range()` in validators.php; applied to CAPTCHA answers (2–18) | Yes |
| Compare validator | `v_compare()`; used for password/confirm (and client `match:` rule) | Yes |
| Email validator | `v_email()` (filter_var + max 254); used in login, register, issue, forgot | Yes |
| Custom validators | `v_password_strong`, `v_certificate_id`, `v_person_name`, `v_otp`, `v_date_range`, `v_upload` — all used on forms (verify.php uses `v_certificate_id`; issue/supersede use `v_upload`/`v_date_range`; revoke uses `v_length`) | Yes |
| Number validator | `v_number()` in validators.php; used on enrollment number (`register_student.php`, digits-only via min-0 bound + `ctype_digit`, mirroring client `ruleEnrollment`) | Yes |
| Responsive application | `public/assets/css/style.css` (Phase 6 breakpoints <480 / ≥480 / ≥768 / ≥1024 / ≥1280) | Yes (by code review; interactive check outstanding) |
| Mobile | base styles + `<480px` block; stacked card layouts | Yes (code) / visual check outstanding |
| Tablet | `≥768px` two-column form rows, 2-col grids | Yes (code) |
| Laptop | `≥1024px` wider shells | Yes (code) |
| Desktop | `≥1280px` 3–4 column grids, 1200px container | Yes (code) |

Not fully implemented / noted:
- Visual/responsive testing for every page@viewport was not executed end-to-end (see docs/TEST_PLAN.md; all entries marked "manual" for the responsive matrix).
