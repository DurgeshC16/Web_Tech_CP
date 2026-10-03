# Web Technology Course Project

A web technology course project developed as part of the Web Technology curriculum.  
The project demonstrates the use of front-end development, back-end/database integration, and web application concepts.

## Project Overview

This project is developed using modern web development technologies and is organized into separate sections for the application source code, public assets, and database-related files.

The main objective of the project is to apply concepts learned in Web Technology, including:

- Web page design and structure
- Styling and responsive layouts
- Client-side scripting
- Server-side development
- Database integration
- CRUD operations
- Form handling and validation
- Dynamic web application development

## Technologies Used

- HTML5
- CSS3
- JavaScript
- PHP
- MySQL
- XAMPP
- Git & GitHub

## Project Structure

```text
Web_Tech_CP/
├── database/
│   └── Database-related files
├── public/
│   └── Publicly accessible files and assets
├── src/
│   └── Main source code of the application
└── README.md
```

# Email setup

OTP codes are delivered by email via SMTP using PHPMailer (vendored at
`src/utils/PHPMailer/`, mirroring the `src/utils/phpqrcode/` pattern — no
Composer required). Configure it with environment variables:

- `SMTP_HOST`, `SMTP_PORT` (default `587`), `SMTP_USERNAME`, `SMTP_PASSWORD`
- `SMTP_ENCRYPTION` (default `tls`; use `ssl` with port `465`)
- `SMTP_FROM_EMAIL`, `SMTP_FROM_NAME` (default `CertiVault`)

For local development, do **not** rely on OS environment variables — XAMPP/Apache on Windows doesn't reliably pass them to PHP. Instead:

1. Copy the example override file:
   ```
   copy src\config\config.local.php.example src\config\config.local.php
   ```
2. Fill in the real values in `src/config/config.local.php` (it's gitignored, so credentials never get committed). `config.php` loads it automatically when present, and its values win over the env-var fallbacks.
3. Restart Apache so the new settings are picked up.

**Gmail:** set `SMTP_HOST=smtp.gmail.com`, `SMTP_PORT=587`, `SMTP_ENCRYPTION=tls`.
`SMTP_PASSWORD` must be a **16-character Google App Password**, not your normal
Gmail password — generate one at <https://myaccount.google.com/apppasswords>
after enabling 2-Step Verification. A regular Gmail password will be rejected
by Google's SMTP servers.

If you'd rather use real environment variables (e.g. on Linux/hosted servers), set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_ENCRYPTION` (default `tls`; use `ssl` with port `465`), `SMTP_FROM_EMAIL`, and `SMTP_FROM_NAME` (default `CertiVault`) — they're picked up as fallbacks when no `config.local.php` exists.

For local development without SMTP, leave the variables unset: OTP creation
still succeeds, the error is logged to `private_data/php_errors.log`, and the
code is shown on screen (non-production only).

# Setup

1. **Clone** the repository into your XAMPP `htdocs` folder.
2. **Folders** — `public/qrcodes/`, `private_data/`, and `private_data/uploads/` are committed as empty directories (via committed `.gitkeep` placeholder files), so a fresh clone works out of the box. If they are missing for any reason, create them manually:
   ```
   mkdir public/qrcodes private_data private_data/uploads
   ```
3. **Database** — import `database/schema.sql` into MySQL (e.g. via phpMyAdmin or `mysql -u root < database/schema.sql`). It creates the `certivault` database, all tables, and a seeded super admin.
4. **Configuration** — all settings are read from environment variables (see `src/config/config.php`):
   - `CV_DB_HOST`, `CV_DB_USER`, `CV_DB_PASS`, `CV_DB_NAME`
   - `CV_BASE_URL`
   - `CV_ENCRYPTION_KEY`
   - `CV_ENV` (set to `production` in production; anything else is treated as local dev)

   The committed defaults (localhost, root, empty password, `certivault`) work for a standard local XAMPP setup, so env vars are optional locally.
5. **Document root** — point Apache/XAMPP at the `/public` directory (e.g. `http://localhost/<repo>/public`), not the repo root.

After that, register an institution, have the super admin approve it, and you can issue certificates.
