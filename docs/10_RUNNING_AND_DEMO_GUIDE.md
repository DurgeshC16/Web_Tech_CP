# 10 — Running CertiVault & Demo Guide

Everything needed to get CertiVault running on your machine, plus a guided
tour of what to try once the website is open — and a short script for
presenting it.

* Part A — [Run it](#part-a--run-it) (Windows + XAMPP, Apache, Linux/macOS)
* Part B — [Check it works](#part-b--check-it-works)
* Part C — [Guided tour](#part-c--guided-tour-what-to-explore) (~30 minutes)
* Part D — [5-minute presentation script](#part-d--5-minute-presentation-script)
* Part E — [Reset, troubleshooting, cheat sheet](#part-e--reset-troubleshooting-cheat-sheet)

---

## Part A — Run it

### A.1 What you need

| Tool | Version | Why |
|------|---------|-----|
| XAMPP (or PHP + MySQL/MariaDB) | PHP 8.2+, MariaDB 10.4+ | Runs the app and the database |
| Composer | 2.x | PDF report, generated certificates, PDF text reading |
| A modern browser | Chrome / Edge / Firefox | The website (camera scanning needs a webcam) |
| An authenticator app (optional) | Google/Microsoft Authenticator, Aegis… | To try two-factor login |
| Node.js 21+ (optional) | — | Only for the browser test suites |

### A.0 Fastest: Docker (no XAMPP needed)

With [Docker Desktop](https://www.docker.com/products/docker-desktop/) running:

```sh
docker compose up -d --build                                       # app + MariaDB, schema loaded automatically
docker compose exec -u www-data app php scripts/seed_demo.php      # demo data
docker compose exec -it -u www-data app php scripts/set_super_admin.php
```

Open **<http://localhost:8080>** and continue with Part C (use port 8080 in
the URLs). Emails are saved inside the container:
`docker compose exec app ls private_data/mail`. Stop with
`docker compose down` (add `-v` to delete the data). The secrets in
`docker-compose.yml` are demo values — local use only.

### A.2 Windows + XAMPP

Open **Git Bash** or **PowerShell** in the project folder.

**1 — Start the database.** Open the *XAMPP Control Panel* and click
**Start** next to **MySQL** (Apache is not needed for this setup).

**2 — Install the PHP libraries.**

```powershell
composer install
```

No Composer? Download the installer from <https://getcomposer.org>, or run
it with XAMPP's PHP: `C:\xampp\php\php.exe composer.phar install`.

**3 — Create the database** (fresh install). In *phpMyAdmin*
(<http://localhost/phpmyadmin>) → **Import** → choose
`database/schema.sql` → **Go**. Or from the command line:

```powershell
C:\xampp\mysql\bin\mysql.exe -u root < database\schema.sql
```

> Already have a `certivault` database from an older version? Do **not**
> import `schema.sql` over it — apply the missing files in
> `database/migrations/` in order (001 → 016), then run once:
> `php scripts\backfill_file_hashes.php` and `php scripts\pin_institution_keys.php`.

**4 — Create your local settings file** (never committed to Git):

```powershell
copy src\config\config.local.php.example src\config\config.local.php
```

For a local demo, open `src/config/config.local.php` and add:

```php
define('MAIL_TRANSPORT', 'file');      // every email (codes, notices) is saved to private_data/mail/
define('APP_ENCRYPTION_KEY', 'change-me-to-a-long-random-string-1');
define('OTP_PEPPER',         'change-me-to-a-long-random-string-2');
define('SHARE_LINK_SECRET',  'change-me-to-a-long-random-string-3');
```

* With `MAIL_TRANSPORT = 'file'` you need **no email account**: open the
  newest `.eml` file in `private_data/mail/` with Notepad to read an
  activation code.
* For real emails instead, fill in the `SMTP_*` lines (Gmail needs an *App
  Password*) — see [doc 06 §4](06_SETUP_AND_CONFIGURATION.md).
* Set the three secrets **before** approving any institution and keep them —
  changing `APP_ENCRYPTION_KEY` later makes existing keys unreadable.
  **Existing database with approved institutions?** Either keep the key it
  was created with (leave the line out to keep the default), or give each
  institution a new key afterwards with
  `php scripts\repair_institution_keys.php <institution_id>` (its old
  certificates stop verifying until reissued).

**5 — Create the super-admin login** (the seeded account is locked):

```powershell
php scripts\set_super_admin.php
```

It asks for an email and a strong password (8+ characters with upper,
lower, digit and symbol). If `php` is not on your PATH use
`C:\xampp\php\php.exe` instead of `php` in every command.

**6 — Load the demo data** (optional, recommended for the tour):

```powershell
php scripts\seed_demo.php
```

It prints five certificates with the verdict each one should show — keep
that output open for the tour.

**7 — Start the website:**

```powershell
php -S localhost:8081 -t public
```

Open **<http://localhost:8081>**. Leave the window open; `Ctrl+C` stops it.

> On Windows, if seeding fails with an OpenSSL/key-generation error, set
> `$env:OPENSSL_CONF = "C:\xampp\apache\conf\openssl.cnf"` (PowerShell) or
> `set OPENSSL_CONF=C:\xampp\apache\conf\openssl.cnf` (cmd) and run it again.

### A.3 Apache (XAMPP) instead of `php -S`

Point a virtual host at the **`public/`** folder (example in
[doc 06 §2](06_SETUP_AND_CONFIGURATION.md)) and restart Apache. If you
serve it at a different address than `http://localhost:8081`, set that
address **before** seeding, because it is printed into the QR codes:

```php
define('CV_BASE_URL', 'http://certivault.local');   // in config.local.php
```

### A.4 Linux / macOS

```sh
composer install
mysql -u root -p < database/schema.sql
cp src/config/config.local.php.example src/config/config.local.php   # then edit as in A.2 step 4
php scripts/set_super_admin.php
php scripts/seed_demo.php
php -S localhost:8081 -t public
```

If MySQL has a password for root, set `define('DB_PASS', '…');` in
`config.local.php` (or the `CV_DB_PASS` environment variable).

---

## Part B — Check it works

| Check | Expected |
|-------|----------|
| <http://localhost:8081> opens | Landing page with the Smart Verify box |
| <http://localhost:8081/verify.php?certificate_id=CV-2026-000001> (use the first ID `seed_demo.php` printed) | Green **VALID** seal |
| Log in as `demo.student@certivault.test` / `DemoStudent@2026` | *My Certificates* with the 5 demo certificates (the superseded one links to its current version) |
| `php scripts\pin_institution_keys.php --verify` | `All keys match their pins.` |
| `php tests\run_all.php` (optional, uses a separate test DB) | `ALL SUITES PASSED (16/16)` |

The login form shows a small sum (e.g. *What is 3 + 5?*) — that is the
offline CAPTCHA.

---

## Part C — Guided tour (what to explore)

The IDs below assume a fresh database; use the ones `seed_demo.php`
printed if yours differ (`CV-<year>-00000N`).

| Demo certificate | Expected verdict | Why |
|------------------|------------------|-----|
| `CV-2026-000001` B.Sc. Computer Science | ✅ VALID | Genuine, active |
| `CV-2026-000002` AWS Cloud Practitioner | ⏰ EXPIRED | Expiry date in the past |
| `CV-2026-000003` Internship Completion Certificate | 🚫 REVOKED | Withdrawn by the institution |
| `CV-2026-000004` Web Development Bootcamp (v1) | 🔁 SUPERSEDED | Replaced by a corrected version |
| `CV-2026-000005` Web Development Bootcamp (v2) | ✅ VALID | The corrected version |

Demo logins: institution **`demo.institution@certivault.test` /
`DemoInst@2026`**, student **`demo.student@certivault.test` /
`DemoStudent@2026`**.

### Act 1 — The verifier (no login) · 8 min

1. **Type an ID** on the home page: `CV-2026-000001` → **VALID**, with the
   certificate card, the issuing key's fingerprint and a **trust score**
   checklist. Try sloppy formats too: `cv 2026 1`, `CV20260001` — all
   resolve.
2. **See every verdict:** verify `…002` (EXPIRED), `…003` (REVOKED — note
   the reason), `…004` (SUPERSEDED — follow the link to `…005`).
3. **Nonsense input:** `<script>alert(1)</script>` → **INVALID**, nothing
   executes.
4. **Download the evidence** on a VALID result:
   * **Verification report (PDF)** — verdict, checks, QR back to the live page.
   * **Signed credential (JSON)** — keep this file for step 6.
5. **Shareable link:** copy
   `http://localhost:8081/verify.php?certificate_id=CV-2026-000005` into a
   new tab.
6. **Zero-trust check:** open *Check a credential file* (top menu) → load the
   JSON → **Verify in my browser** → *✓ Authentic*. Every check (digest, RSA
   signature, key fingerprint, published key, live status) ran in your
   browser.
   * Now open the JSON in Notepad, change the `title`, save, load it again →
     **✗ Not authentic** (the digest no longer matches).
7. **Status API:** open
   `http://localhost:8081/api_status.php?certificate_id=CV-2026-000001` —
   machine-readable JSON for other systems.
8. **QR scanning:** the QR images are in `public/qrcodes/`. Upload one with
   *Certificate file* on the verify page, or click **Scan QR with camera**
   and hold a printed/phone-displayed QR to the webcam.

### Act 2 — The student · 5 min

1. **Log in** as the demo student → *My Certificates*: five certificates;
   each card shows how many times it was verified.
2. **Open a certificate** → trust-score card, **Download**, **PDF report**,
   **Signed credential**.
3. **Generate Share Link (24h)** → *Copy* → open it in a private/incognito
   window: the certificate verifies without logging in.
4. **Upload the downloaded file** on the verify page:
   * normally → resolved by its **exact fingerprint**;
   * click **🔒 Hash in my browser** first → only the SHA-256 is sent, the
     file never leaves your computer.

### Act 3 — The institution · 10 min

Log out, then log in as the demo institution.

1. **Issue one certificate** (*Issue*): student email
   `demo.student@certivault.test`, name *Demo Student*, any title, today's
   date, and any small PDF/PNG/JPG (≤ 5 MB) → success message with the new
   ID. Verify it → VALID. (With `MAIL_TRANSPORT=file` the student's
   notification email appears in `private_data/mail/`.)
2. **Bulk issue** (*Bulk issue*): upload **`docs/samples/bulk_issue_sample.csv`**.
   * Preview: 3 rows ready, 1 flagged (invalid email) — nothing issued yet.
   * Confirm → results: 2 **issued** (generated PDFs with QR), 1 **pending
     activation** (`new.learner@example.com` has no account — an activation
     email was written to `private_data/mail/`), 1 **skipped**.
   * **Download results (CSV)**; click an issued ID → VALID.
3. **Revoke** (*Dashboard* → a certificate → *Revoke*, give a reason) →
   verify it again → **REVOKED** with your reason.
4. **Supersede** a certificate (issue a corrected version) → the old ID shows
   **SUPERSEDED** and links to the new one.
5. **Analytics** (top menu): KPI tiles, *Verifications per day* chart (hover
   or Tab through the days), verdict mix, most-checked certificates; switch
   between 7 / 30 / 90 days; *Show as table*.
6. **Audit Logs:** every lookup you made in Acts 1–2, with result and IP.

### Act 4 — Security features · 5 min

1. **Two-factor login:** *Two-factor auth* → **Set up** → scan the QR with
   an authenticator app → enter the 6-digit code → save the **recovery
   codes**. Log out and in again: after the password you are asked for the
   code. (Turn it off again with your password + a recovery code.)
2. **Tamper detection** (advanced, use a throw-away certificate): open
   `private_data/uploads/`, find the file of a certificate you just issued,
   add one character to it with Notepad and save → verify it → **TAMPERED**.
3. **Rate limiting:** 30 different lookups from one computer within 10
   minutes are allowed; the 31st different one gets **HTTP 429 Too Many
   Requests**, with no database lookup performed.
4. **Content-Security-Policy:** open the browser DevTools → *Network* → any
   page → response headers: `script-src 'self'`, `script-src-attr 'none'` —
   injected scripts cannot run.
5. **Key pinning:** `php scripts\pin_institution_keys.php --verify` lists
   every institution key as **MATCH**; a key swapped in the database would
   show **MISMATCH** and its certificates would verify as TAMPERED.

### Act 5 — The super admin and a new institution · 5 min

1. Log out → **Register** → *Register Institution* with a new email and
   password → an activation code is emailed (open the newest `.eml` in
   `private_data/mail/`) → enter it on the activation page.
2. Log in as the **super admin** (the login you created in A.2 step 5) →
   *Institutions* → **Pending** → **Approve** → the institution's RSA key is
   generated, encrypted and pinned.
3. Log in as the new institution → it can now issue certificates.
4. `php scripts\pin_institution_keys.php --verify` → the new key is listed.

### Act 6 — For developers · optional

```powershell
php tests\run_all.php                 # 16 PHP suites, 512 checks (separate certivault_test DB)
node tests\test_verify_ui.mjs         # Smart Verify in headless Chrome
node tests\test_pages_browser.mjs     # every page under the CSP, issuance, 2FA, analytics
```

The same suites run on GitHub Actions for every push (badge on the README).

---

## Part D — 5-minute presentation script

| Time | Show | Say |
|------|------|-----|
| 0:00 | Home page | "Certificates are PDFs anyone can edit. CertiVault binds each one to its issuer with a SHA-256 fingerprint and an RSA signature." |
| 0:40 | Verify `CV-2026-000001` | "No account needed — VALID, signed by this key, trust score from the actual checks." |
| 1:20 | Verify `…003`, `…004` | "Revocation and corrections are first-class: REVOKED with a reason, SUPERSEDED with a link to the new version." |
| 2:00 | Institution → Bulk issue with the sample CSV | "Institutions issue at scale: validation preview, then signed PDFs with QR codes." |
| 2:50 | Signed credential → *Check a credential file* | "The verifier can check it in their own browser — no trust in our server. Change one letter and it fails." |
| 3:40 | Analytics | "Institutions see how their certificates are being verified." |
| 4:10 | Two-factor login + key-pin script | "Security: 2FA, keys pinned outside the database, strict CSP, rate limiting." |
| 4:40 | README CI badge | "Every change is tested automatically — around 590 checks on every push." |

---

## Part E — Reset, troubleshooting, cheat sheet

### Reset the demo

* **Re-run the seed** — `php scripts\seed_demo.php` is safe to repeat (it
  reuses existing demo rows).
* **Start completely fresh** (deletes all CertiVault data):

  ```powershell
  C:\xampp\mysql\bin\mysql.exe -u root -e "DROP DATABASE certivault;"
  C:\xampp\mysql\bin\mysql.exe -u root < database\schema.sql
  Remove-Item private_data\pins\certivault.json   # its pins belong to the old keys
  php scripts\set_super_admin.php
  php scripts\seed_demo.php
  ```

### Troubleshooting

| Problem | Fix |
|---------|-----|
| `php` is not recognised | Use `C:\xampp\php\php.exe` or add `C:\xampp\php` to PATH |
| Database connection error | Start MySQL in the XAMPP Control Panel; check `DB_PASS` |
| Port 8081 in use | `php -S localhost:8090 -t public` (and set `CV_BASE_URL` before seeding) |
| Demo QR opens the wrong address | Set `CV_BASE_URL` to where you serve the app, then reseed |
| "Email delivery is not set up" | Add `define('MAIL_TRANSPORT', 'file');` or SMTP settings to `config.local.php` |
| Where is my activation code? | Newest `.eml` file in `private_data/mail/` |
| PDF report shows a fallback page / bulk issue disabled | `composer install` |
| Every certificate shows TAMPERED after a DB reset | Delete the stale pin file (`private_data/pins/certivault.json`) and re-run `pin_institution_keys.php` |
| Too Many Requests (429) | Wait 10 minutes (rate limit) |
| Upload rejected | PDF/PNG/JPG under 5 MB; see [doc 06 §7](06_SETUP_AND_CONFIGURATION.md) |

### Cheat sheet

| What | Where |
|------|-------|
| Website | <http://localhost:8081> |
| Verify by ID | `/verify.php?certificate_id=…` |
| Status API | `/api_status.php?certificate_id=…` |
| Credential file | `/credential.php?certificate_id=…` |
| Browser verifier | `/offline_verify.php` |
| Public keys | `/institutions.php`, `/well-known-keys.php` |
| Emails (dev) | `private_data/mail/*.eml` |
| Error log | `private_data/php_errors.log` |
| Settings | `src/config/config.local.php` |
| Sample CSV | `docs/samples/bulk_issue_sample.csv` |
