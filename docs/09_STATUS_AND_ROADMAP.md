# 09 — Status & Roadmap

*Last reviewed: 2026-11-15.*

## 1. Current state

| Area | Status |
|------|--------|
| Accounts: registration, email-OTP activation, login (CAPTCHA, lockout, remember-me), password reset/change | ✅ |
| **Two-factor authentication (TOTP) + recovery codes** | ✅ new |
| Roles & authorization (super admin, approved institution, student, public verifier) | ✅ |
| Issuance — single (upload) and **bulk from CSV with generated certificate PDFs** | ✅ bulk new |
| Canonical SHA-256 + RSA signatures, AES-256-GCM key storage, **key pinning outside the DB** | ✅ pinning new |
| Six-verdict cascade, audit log, **pre-lookup rate limiter** | ✅ |
| Revocation / supersession; transparency log (opt-in) | ✅ |
| Smart Verify incl. **browser PDF→QR decoding**, exact-file matching, privacy mode, camera, **shareable GET links** | ✅ |
| Trust score, PDF report, status API | ✅ |
| **Portable signed credentials + zero-trust browser verifier** | ✅ new |
| **Institution analytics dashboard** | ✅ new |
| **Issuance emails** | ✅ new |
| **CSP without inline scripts** | ✅ |
| Responsive UI, light/dark theme | ✅ |
| Automated tests: 16 PHP suites (512 checks) + 2 browser suites (78 checks) | ✅ |
| **CI on GitHub Actions** (Linux, MariaDB 10.11 strict, headless Chrome) | ✅ new |
| All course requirements ([REQUIREMENTS_MATRIX.md](REQUIREMENTS_MATRIX.md)) | ✅ |

## 2. Change log of 2026-11-15

### Round 1 — repository & documentation
Untracked the broken `vendor/` gitlinks (they crashed the PDF features);
fixed an attested-credential URL regex that never compiled; config guards;
CLI-only seeder; rewrote the README; wrote docs 01–09; moved the draft paper
to git-ignored `docs/private/`.

### Round 2 — existing bugs fixed
| Problem | Fix |
|---------|-----|
| Uploading an issued certificate never matched (raw hash compared with the canonical digest) | `file_sha256` (migration 013) + backfill script |
| Documented dev mail transport missing (left in a git stash) | Restored; production guard |
| Composer packages not installed | `composer install` |
| Rate limiter ran **after** the lookup; cost grew with history | Pre-lookup gate, bounded `verify_rate` table (migration 014) |
| Dev database stuck at migration ~004; an approved institution without a key | Migrated (backed up first); key repaired |
| Non-public folders web-reachable | Deny `.htaccess` everywhere (tested on Apache) |
| Seeded super admin with password `password` | Locked seed |
| phpqrcode PHP 8.2 deprecations | Patched, output byte-identical |

### Round 3 — remaining work and new features
| Item | Result |
|------|--------|
| Option (a): browser PDF→QR in Smart Verify | Done; stash archived (`archive/stash-2026-10-26`, local) and dropped |
| CSP `'unsafe-inline'` for scripts | Removed — all JS external (`ui.js`), `script-src-attr 'none'` |
| Key pinning | `KeyPinService` + `pin_institution_keys.php`; closes the paper's attack S6 |
| CI | GitHub Actions, green |
| New features | Signed credentials + browser verifier, bulk issuance, 2FA, analytics, issuance emails |
| Bugs found on the way | Issuer refs from uploaded files dropped (`_candidates` typo); audit rows lost when detail > 255 chars; undefined `$trusted` on result views; status API counted website lookups against its limit; mixed table collations (migration 016); DST gap in day series; non-strict XAMPP SQL mode hiding errors (strict mode now set per session); tests reading dev key pins |

## 2b. Change log of 2026-11-18

| Item | Result |
|------|--------|
| Dummy certificate dataset | `scripts/generate_dataset.php` — 100 people, 5 institutions, 191 signed certificates (VALID/EXPIRED/REVOKED/SUPERSEDED); CSVs in `docs/samples/dataset/` |
| Novelties & comparison | [11_NOVELTIES_AND_COMPARISON.md](11_NOVELTIES_AND_COMPARISON.md) (Credly, Certifier, Accredible, Blockcerts, OB 3.0/VC, DigiLocker) |
| Incomplete-registration bug | Re-registering an unverified email resumes it; login checks email verification before institution approval (pending vs rejected) |
| Password entered twice | Registration has one password field + show/hide toggle + strength checklist |
| Forgot password had no code field | Code + new-password step always reachable ("Already have a code?", resend, no session needed) |
| Guest verification limit | 5 free verifications / 24 h for visitors, then "free limit reached — log in or register" (`GuestQuotaService`, migration 017) |
| Frontend redesign | Gradient + glass design system ([12_DESIGN_SYSTEM.md](12_DESIGN_SYSTEM.md)), new landing page, all pages restyled; zero `style=""` attributes left |
| Test-harness bug | `config.local.php` overrode `CV_DB_NAME`, so local HTTP suites hit the dev DB; env now wins |

## 3. Still open

### Security
* `style-src 'unsafe-inline'` — done: all `style=""` attributes moved into
  classes and the allowance removed (kept only when reCAPTCHA is enabled).
* Optionally **require** 2FA for admin roles (today it is opt-in).
* Pin file location: in production put `CV_KEY_PINS_FILE` on storage the
  web/DB user cannot write and publish `--export` out of band.

### Product
* Public HTTPS demo deployment (and a container image for one-command setup).
* Real-device camera check; usability test with employers.
* Append-only revocation log and trusted timestamping (paper future work).
* W3C Verifiable Credentials / Open Badges 3.0 export format next to the
  current JSON credential.

### Project hygiene
* Static analysis (PHPStan) in CI.
* Refresh the research paper's numbers (doc 08 §6) and its reference notes.
* Local leftovers: 145 old `verifyui-*.pdf` fixtures in
  `private_data/uploads/` can be deleted.
* Your dev super admin still has the old `password` hash — run
  `php scripts/set_super_admin.php`.
