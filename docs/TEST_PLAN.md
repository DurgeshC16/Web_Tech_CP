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
20. **REVOKED** — revoked cert → REVOKED (wins over expired). *verified*
21. **SUPERSEDED** — superseded cert → SUPERSEDED + link to current. *manual*
22. **INVALID** — unknown ID, or malformed ID/token → INVALID, no DB hit for malformed. *verified*
23. **Share-link expiry** — use an old share token → "This share link has expired." *manual*

## Responsive check (four widths, both themes)
24. **375 / 768 / 1366 / 1920** on index, login, verify, student_dashboard, admin_dashboard, view_certificate_admin, audit_logs: no horizontal scroll, header collapses to hamburger <768, tables stack with data-labels on phones, stat grid 2→4 cols, no clipped text, cards don't overlap, theme toggle readable. *manual (not executed headlessly)*

Legend: *verified* = reproduced against the running app during development; *verified by code reading* = traced in source; *manual* = execute in browser.
