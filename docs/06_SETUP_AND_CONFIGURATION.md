# 06 — Setup & Configuration

## 1. Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| PHP | 8.2+ | Extensions: `pdo_mysql`, `openssl`, `fileinfo`, `gd`, `mbstring` (optional: `imagick`) |
| MySQL / MariaDB | MySQL 8 / MariaDB 10.4+ | XAMPP's MariaDB works |
| Web server | Apache 2.4 (XAMPP) or PHP built-in server | Serve **`public/` only** |
| Composer | 2.x | Optional — PDF report (dompdf) and PDF text extraction |
| SMTP account | Any (Gmail App Password works) | Needed for OTP emails (a dev log fallback exists) |
| Node.js | 18+ | Only for the browser test scripts in `tests/` |

## 2. Installation

```sh
# 1. Clone
git clone https://github.com/DurgeshC16/Web_Tech_CP.git
cd Web_Tech_CP

# 2. (Optional) PHP dependencies for the PDF report / PDF text extraction
composer install

# 3. Database — creates the `certivault` DB, all tables, and the super admin
mysql -u root < database/schema.sql          # or phpMyAdmin → Import

# 4. Local configuration (git-ignored)
copy src\config\config.local.php.example src\config\config.local.php   # Windows
# cp src/config/config.local.php.example src/config/config.local.php   # Linux/macOS
#    → fill in SMTP credentials and the three secrets (see §3)

# 5. Set the super-admin email + password (the seeded account cannot log in until you do)
php scripts/set_super_admin.php

# 6. Run
php -S localhost:8081 -t public              # then open http://localhost:8081
```

### Option A — PHP built-in server (simplest)

`php -S localhost:8081 -t public`. The `-t public` is important: it makes
`public/` the document root, so `src/`, `private_data/` and `.git/` are not
reachable. `BASE_URL` is derived automatically (`http://localhost:8081`).

### Option B — XAMPP / Apache

Point a virtual host (or an `Alias`) at the repository's **`public/`**
directory, e.g. in `httpd-vhosts.conf`:

```apache
<VirtualHost *:80>
    ServerName certivault.local
    DocumentRoot "C:/path/to/Web_Tech_CP/public"
    <Directory "C:/path/to/Web_Tech_CP/public">
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

If you instead clone into `htdocs` and browse to
`http://localhost/Web_Tech_CP/public/`, the app works (`BASE_URL` is derived
up to `/public`), but the rest of the repository is web-reachable too — fine
for a quick local demo, never for a shared machine or server.

On Windows, CLI key generation may need `OPENSSL_CONF` pointing at
`C:\xampp\apache\conf\openssl.cnf` (the test suite and `seed_demo.php` set
it automatically).

## 3. Configuration reference

Values are resolved in this order: **`config.local.php` → environment
variable → default in `config.php`**. On XAMPP/Windows prefer
`config.local.php` (Apache does not reliably pass OS environment variables).
In production prefer real environment variables.

### Core

| Constant | Env var | Default | Notes |
|----------|---------|---------|-------|
| `DB_HOST` / `DB_USER` / `DB_PASS` / `DB_NAME` | `CV_DB_HOST` … `CV_DB_NAME` | `localhost` / `root` / *(empty)* / `certivault` | |
| `BASE_URL` | `CV_BASE_URL` (or `CV_BASE_URL` constant) | derived per request | Used in QR codes, share links and emails. Set only behind proxies. CLI fallback `http://localhost:8081/certivault/public` |
| `APP_ENCRYPTION_KEY` | `CV_ENCRYPTION_KEY` | dev default | **Set before approving the first institution**; wraps RSA private keys |
| `OTP_PEPPER` | `CV_OTP_PEPPER` | dev default | HMAC key for stored OTPs |
| `SHARE_LINK_SECRET` | `CV_SHARE_SECRET` | dev default | HMAC key for share links |
| — | `CV_ENV` | — | `production` enables the secret guard (refuses dev defaults) |
| `CV_DEBUG` | — | `false` | Shows errors on screen; dev only |

### Email

| Constant | Env var | Default |
|----------|---------|---------|
| `SMTP_HOST` | `SMTP_HOST` | `smtp.gmail.com` |
| `SMTP_PORT` | `SMTP_PORT` | `587` |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | same | *(empty)* |
| `SMTP_ENCRYPTION` | `SMTP_ENCRYPTION` | `tls` (`ssl` for port 465) |
| `SMTP_FROM_EMAIL` / `SMTP_FROM_NAME` | same | username / `CertiVault` |
| `MAIL_TRANSPORT` | `CV_MAIL_TRANSPORT` | `smtp` (`file` = dev spool in `private_data/mail/`, refused in production) |

### CAPTCHA

| Constant | Env var | Default |
|----------|---------|---------|
| `RECAPTCHA_SITE_KEY` / `RECAPTCHA_SECRET_KEY` | `CV_RECAPTCHA_SITE_KEY` / `CV_RECAPTCHA_SECRET_KEY` | empty → offline arithmetic CAPTCHA |

### Feature flags

| Constant | Env var | Default |
|----------|---------|---------|
| `SMART_VERIFY_ENABLED` | `CV_SMART_VERIFY` | ON (`0` disables) |
| `SMART_EXTERNAL_LINKS` | `CV_SMART_EXTERNAL_LINKS` | ON |
| `API_ENABLED` | `CV_API_ENABLED` | ON |
| `EXT_SOURCE_ENABLED` + `EXT_*` | `CV_EXT_*` | OFF — legacy external sources |
| `EXT_REGISTRY_ENABLED` | `CV_EXT_REGISTRY_ENABLED=1` | OFF — managed registry (migration 010) |
| `ATTESTED_EXTERNAL_CREDENTIALS_ENABLED` | `CV_ATTESTED_CREDENTIALS_ENABLED=1` | OFF (migration 011) |
| `CERTIFICATE_TRANSPARENCY_ENABLED` | `CV_CERTIFICATE_TRANSPARENCY_ENABLED=1` | OFF (migration 012) |
| `TLOG_PRIVATE_KEY_FILE` / `TLOG_PUBLIC_KEY_FILE` | `CV_TLOG_*_KEY_FILE` | `private_data/tlog/platform_*.pem` |

## 4. Email (OTP) setup with Gmail

1. Enable **2-Step Verification** on the Google account.
2. Create an **App Password** at <https://myaccount.google.com/apppasswords>
   (16 characters; remove the spaces).
3. In `src/config/config.local.php`:
   ```php
   define('SMTP_USERNAME', 'yourname@gmail.com');
   define('SMTP_PASSWORD', 'abcdefghijklmnop');   // the App Password
   define('SMTP_FROM_EMAIL', 'yourname@gmail.com');
   ```
4. Test: `php scripts/smtp_diagnostic.php you@example.com` — prints PASS/FAIL
   for config, OpenSSL, connection, TLS + auth and test send, and where each
   value came from (password never shown).

Errors `534-5.7.9` / `535-5.7.8` mean a normal password, spaces left in the
App Password, or 2-Step Verification is off.

**Without SMTP (development only)** — two options, both refused or inert
with `CV_ENV=production`:

* `define('MAIL_TRANSPORT', 'file');` (or `CV_MAIL_TRANSPORT=file`) — every
  email, including OTPs, is written as an `.eml` file to `private_data/mail/`
  instead of being sent. The production guard refuses to start with it.
* `define('CV_DEV_SHOW_OTP', true);` (or `CV_DEBUG`) — OTPs are also
  appended to `private_data/dev_mail.log`.

Failed sends do not consume the resend cooldown or the hourly quota.

## 5. Demo data

```sh
php scripts/seed_demo.php
```

| Account | Email | Password |
|---------|-------|----------|
| Institution admin | `demo.institution@certivault.test` | `DemoInst@2026` |
| Student | `demo.student@certivault.test` | `DemoStudent@2026` |
| Super admin | set by you | locked until `php scripts/set_super_admin.php` is run |

The seeder uses the real issuance pipeline, so demo certificates verify as
VALID. It is idempotent and refuses to run over HTTP.

## 6. CLI scripts (`scripts/`)

| Script | Purpose |
|--------|---------|
| `set_super_admin.php` | Set or rotate the super admin's email + password (prompted) |
| `seed_demo.php` | Seed demo institution, student and certificates |
| `seed_external_source.php` | Seed the offline `DEMO MOOC registry` external source |
| `smtp_diagnostic.php <email>` | Stage-by-stage SMTP check |
| `backfill_file_hashes.php [--dry-run]` | After migration 013: store the raw file hash for older certificates (skips files that fail the integrity check) |
| `check_environment.php` | Upload-environment audit (CLI, or in the browser as an admin) |
| `check_institution_keys.php` | Read-only audit of stored keys (prints lengths/booleans, never key material) |
| `repair_institution_keys.php <id>` | Recovery rotation of one institution's key |
| `publish_checkpoint.php` | Sign and publish the transparency-log checkpoint |
| `compare_checkpoint.php <file>` | Compare an out-of-band checkpoint with the local one |

## 7. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Uploads fail | Run `php scripts/check_environment.php`. In `php.ini`: `file_uploads=On`, `upload_max_filesize=8M`, `post_max_size=10M`, `extension=fileinfo`, `extension=gd`; restart Apache |
| "Email delivery is not set up on this server" | SMTP credentials missing — see §4 |
| RSA key generation fails on Windows CLI | Set `OPENSSL_CONF=C:\xampp\apache\conf\openssl.cnf` |
| "Download verification report" shows a fallback page | dompdf not installed — run `composer install` |
| Verification shows wrong host in QR codes | Set `CV_BASE_URL` |
| Times look shifted (OTP cooldown, lockout) | PHP and MySQL time zones differ; `Database.php` aligns the session zone — check `date.timezone` in `php.ini` |
| A test file disappears after running tests (Windows) | Antivirus quarantine — restore with `git checkout -- <file>` and add an AV exclusion for the repo folder |

## 8. Production checklist

- [ ] `CV_ENV=production`
- [ ] Strong random `CV_ENCRYPTION_KEY`, `CV_OTP_PEPPER`, `CV_SHARE_SECRET`
      (set **before** approving institutions; back them up)
- [ ] HTTPS everywhere (HSTS is sent automatically on HTTPS)
- [ ] Document root = `public/`
- [ ] `php.ini`: `expose_php=Off`, `display_errors=Off`, `log_errors=On`
- [ ] Real SMTP credentials; reCAPTCHA keys
- [ ] Super-admin credentials set with `set_super_admin.php`
- [ ] `MAIL_TRANSPORT` left at `smtp`
- [ ] `composer install --no-dev`
- [ ] `private_data/` writable by PHP, not by the web
- [ ] Schedule `publish_checkpoint.php` and back up `private_data/tlog/`
      (if transparency is enabled)
- [ ] Database backups and monitoring
