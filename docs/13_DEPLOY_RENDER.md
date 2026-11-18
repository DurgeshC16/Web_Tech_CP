# 13 — Deploy CertiVault on Render (free plan)

This guide puts CertiVault on the internet with no paid web hosting. You
need three outside services, each set up in a web browser:

| Service | What it does here | Cost |
|---------|-------------------|------|
| **Render** | Runs the app (Docker web service) | Free plan |
| **A MySQL-compatible database with TLS** (TiDB Cloud Starter — free; or Aiven) | Stores everything, including uploaded certificate files | Free (TiDB: 5 GiB) |
| **Brevo** | Sends email (activation codes, password resets, notifications) | Free plan (300 emails/day) |

Optional: **UptimeRobot** (free) to stop the app falling asleep.

You do **not** need a shell, SSH, or any command-line tool on the server.
The container sets itself up when it starts (database tables, super admin,
restored files).

> Facts about outside services were checked on **18 November 2026**.
> Providers change their free plans. Check the linked pages before you rely
> on a limit.

---

## 0. Why Render's free plan needs special settings

Render's free web services differ from a normal server in a few ways. Each
difference has a setting in CertiVault. All of these settings are **off by
default**, so local XAMPP, `docker compose` and the test suite are not
affected.

| Free-plan restriction | What CertiVault does (setting) |
|-----------------------|-------------------------------|
| Outbound SMTP ports 25/465/587 are blocked | Sends email over HTTPS through the Brevo API (`CV_MAIL_TRANSPORT=brevo`) |
| The disk is wiped on every restart, redeploy and spin-down, and there is no persistent disk | Copies every file that must survive into the database and writes it back at start-up (`CV_FILE_STORE=db`) |
| No managed MySQL | Connects to an external MySQL over TLS, on any port (`CV_DB_PORT`, `CV_DB_SSL_CA_PEM`) |
| No shell, so you cannot run `scripts/set_super_admin.php` | Creates or updates the super admin from env vars at start-up (`CV_SUPER_ADMIN_EMAIL` / `CV_SUPER_ADMIN_PASSWORD`) |
| TLS ends at Render's proxy, so the app sees plain HTTP and the proxy's IP | Reads the real client IP and HTTPS status from the proxy headers (`CV_TRUST_PROXY=1`) |
| The service must listen on `$PORT` (default 10000) | `docker/entrypoint.sh` points Apache at `${PORT:-80}` |
| The service sleeps after 15 minutes without traffic | `/health.php` gives an uptime monitor a cheap URL to ping |

The repository includes a **Blueprint** (`render.yaml`) that fills in most
of these settings for you.

---

## 1. Create the database

### Option A (free): TiDB Cloud Starter

TiDB Cloud Starter is MySQL-compatible and has a free quota per instance
(5 GiB row storage and 50 million Request Units per month, up to five free
instances per organization —
[limits](https://docs.pingcap.com/tidbcloud/serverless-limitations/),
[plans](https://docs.pingcap.com/tidbcloud/select-cluster-tier)).

> TiDB uses its own SQL engine. CertiVault's schema uses only standard
> features (stored generated column, foreign keys, LONGBLOB ≤ 5 MB per file),
> but it was tested on MariaDB, not on TiDB. If the first start logs a schema
> error, see Troubleshooting or use Option B.

1. Sign up at <https://tidbcloud.com/> and create a **Starter** (free) cluster
   in an AWS region close to Render's (e.g. `us-west-2` for Oregon).
2. Open the cluster → **Connect**. Choose **Connect with: General**, then
   **Generate password** and copy it immediately.
3. Copy the connection values:

   | TiDB shows | Put it in |
   |------------|-----------|
   | **HOST** (e.g. `gateway01.us-west-2.prod.aws.tidbcloud.com`) | `CV_DB_HOST` |
   | **PORT** `4000` | `CV_DB_PORT` |
   | **USERNAME** (e.g. `2abcXYZ.root` — keep the prefix) | `CV_DB_USER` |
   | **PASSWORD** | `CV_DB_PASS` |

4. Open **SQL Editor** in the TiDB console and run
   `CREATE DATABASE certivault;` then set `CV_DB_NAME=certivault`.
5. TLS: TiDB uses a publicly trusted certificate, so **don't** set
   `CV_DB_SSL_CA_PEM`. Instead set
   `CV_DB_SSL_CA=/etc/ssl/certs/ca-certificates.crt` (the container's
   system CA bundle).

Then continue with step 2 (email).

### Option B: Aiven MySQL

> **Important: Aiven's free MySQL plan is being retired.** Since
> **6 November 2026** you cannot create a new *free* Aiven for MySQL
> service. Existing free services keep working until
> **21 December 2026**. On that date Aiven powers them off and **deletes
> their data and backups**
> ([Aiven changelog](https://aiven.io/changelog/507f8b1b-dd8f-4841-ac4a-940ac492b688),
> [MySQL free tier page](https://aiven.io/docs/products/mysql/concepts/mysql-free-tier)).
> Your options:
>
> * **Aiven for MySQL, Developer plan** (paid, low cost, does not power off
>   when idle; see [Aiven pricing](https://aiven.io/docs/platform/concepts/service-pricing)).
>   The steps below are the same, except you choose that plan. If you
>   already have a free Aiven MySQL, you can upgrade it in place: the data
>   and the connection details stay the same.
> * **An existing free Aiven MySQL** that you created before
>   6 November 2026. It works until 21 December 2026. Upgrade or export
>   (`mysqldump`) before that date.
> * **Any other MySQL 8 / MariaDB server that is reachable from the
>   internet.** Fill in the same five connection values plus its CA
>   certificate. Some services that call themselves "MySQL-compatible" are
>   not tested with CertiVault. For example, TiDB Cloud uses a different
>   SQL engine.
>
> CertiVault needs MySQL (or MariaDB). It cannot use PostgreSQL.

### Steps

1. Go to <https://console.aiven.io/signup> and create an account.
2. In your project, click **Create service** → **MySQL**.
3. Choose a plan. See the warning above: the Developer plan, or your
   existing free service.
4. Choose a cloud and region if the plan offers a choice. Pick one close to
   Render's region. The blueprint uses Render's default region, Oregon (US
   West).
5. Give the service a name, for example `certivault-db`, and click
   **Create service**. Wait until the status shows **Running**. This takes a
   few minutes.
6. Open the service's **Overview** page. Under **Connection information**,
   copy these values:

   | Aiven shows | You will put it in |
   |-------------|--------------------|
   | **Host**, for example `certivault-db-yourproject.c.aivencloud.com` | `CV_DB_HOST` |
   | **Port**, for example `12345`. This is *not* 3306 | `CV_DB_PORT` |
   | **User**, usually `avnadmin` | `CV_DB_USER` |
   | **Password** (click the eye icon) | `CV_DB_PASS` |
   | **Database name**, usually `defaultdb` | `CV_DB_NAME` |
   | **CA certificate**: click **Download** (or **Show**) | `CV_DB_SSL_CA_PEM` |

7. Open the downloaded `ca.pem` in a text editor (Notepad is fine). Copy
   **all** of it, including the `-----BEGIN CERTIFICATE-----` and
   `-----END CERTIFICATE-----` lines. You will paste this text into
   `CV_DB_SSL_CA_PEM`.
   * You don't need to create tables or import anything. CertiVault does
     that on its first start.
   * Aiven requires TLS. CertiVault always checks the server's certificate
     against this CA, so the connection fails if the CA is wrong. That is
     intended.
   * Aiven MySQL requires a primary key on every table
     (`sql_require_primary_key`). Every CertiVault table has one.

---

## 2. Set up email (Brevo)

1. Create a free account at <https://www.brevo.com/>. The free plan allows
   300 emails per day.
2. **Verify a sender address.** Open **Senders, Domains & Dedicated IPs** →
   **Senders** → **Add a sender**. You can find it in the menu under your
   account name. Enter a name, for example `CertiVault`, and an email
   address that you can read. Brevo sends a code or link to that address.
   Confirm it.
   * Use this exact address as `CV_MAIL_FROM_EMAIL`. Brevo rejects mail
     from unverified senders.
   * Optional: authenticate your own domain under **Domains** (SPF/DKIM).
     Mail is then less likely to land in spam.
3. **Create an API key.** Open **SMTP & API** → **API Keys** → **Generate a
   new API key**. Name it `certivault` and copy the key. It starts with
   `xkeysib-`. This value goes in `CV_BREVO_API_KEY`.
   * Use an **API key**, not an SMTP key. Render's free plan blocks SMTP.
   * Brevo shows the key only once. Keep it secret: anyone with the key can
     send mail as you.

CertiVault posts every message to `https://api.brevo.com/v3/smtp/email`.
Activation codes, password resets, two-factor emails and issuance
notifications all use the same path, with a 20-second timeout. If Brevo
rejects a message, the app reacts the same way as to a failed SMTP send: it
reports "couldn't send the email", and a failed code does not count against
the resend limits.

---

## 3. Deploy on Render

Push the repository, including `render.yaml`, to your own GitHub account. A
fork of the project works.

### Option A — Blueprint (recommended)

1. Sign up at <https://render.com/> with your GitHub account.
2. Click **New** → **Blueprint**. Connect GitHub if Render asks, then select
   the CertiVault repository and the branch.
3. Render reads `render.yaml` and shows one web service, `certivault`,
   with **runtime Docker** and **plan Free**.
4. Render asks for every value marked `sync: false`. Fill them in:

   | Variable | Value |
   |----------|-------|
   | `CV_DB_HOST`, `CV_DB_PORT`, `CV_DB_USER`, `CV_DB_PASS`, `CV_DB_NAME` | From Aiven, step 1.6 |
   | `CV_DB_SSL_CA_PEM` | The whole text of `ca.pem` (step 1.7). Line breaks may be kept, written as `\n`, or lost; CertiVault rebuilds the certificate either way |
   | `CV_BREVO_API_KEY` | The `xkeysib-…` key (step 2.3) |
   | `CV_MAIL_FROM_EMAIL` | The sender address you verified in Brevo (step 2.2) |
   | `CV_BASE_URL` | Leave **empty** for now, or type a placeholder you will fix in step 4 |
   | `CV_SUPER_ADMIN_EMAIL` | The email address you will log in with |
   | `CV_SUPER_ADMIN_PASSWORD` | 8–72 characters with an upper-case letter, a lower-case letter, a digit and a special character, for example `Vault#2026-Admin` (make up your own) |

   The blueprint fixes these values, so you don't type them: `CV_ENV=production`,
   `CV_TRUST_PROXY=1`, `CV_FILE_STORE=db`, `CV_MAIL_TRANSPORT=brevo` and
   `CV_ERROR_LOG=stderr`. With the last one, PHP errors appear in Render's
   **Logs** tab.

   Render generates `CV_ENCRYPTION_KEY`, `CV_OTP_PEPPER` and `CV_SHARE_SECRET`
   as random 256-bit values (`generateValue: true`). The production guard
   accepts them, because it only refuses the development defaults.
   **Never change `CV_ENCRYPTION_KEY` after you approve the first
   institution.** It encrypts the institutions' private signing keys.
5. Click **Apply** (or **Deploy Blueprint**). The first build takes a few
   minutes.

### Option B — manual Docker web service

1. **New** → **Web Service** → select the repository.
2. Set **Language / Runtime** to **Docker**, **Instance type** to **Free**,
   and leave the Dockerfile path as `./Dockerfile`.
3. Under **Advanced**, set **Health Check Path** to `/health.php`.
4. Add the environment variables from the table above. Also add
   `CV_ENV=production`, `CV_TRUST_PROXY=1`, `CV_FILE_STORE=db`,
   `CV_MAIL_TRANSPORT=brevo` and `CV_ERROR_LOG=stderr`. Then add three random
   secrets: `CV_ENCRYPTION_KEY`, `CV_OTP_PEPPER` and `CV_SHARE_SECRET`. Use
   a different value for each, for example the output of
   `php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"` or
   `openssl rand -base64 32` on your own computer. Render's
   **Generate** button also works.
5. Click **Create Web Service**.

### What the first start does

Open the service → **Logs**. After the build you should see lines like
these:

```
[entrypoint] Apache will listen on port 10000
[render_boot] starting; database certivault-db-….aivencloud.com:12345/defaultdb (TLS); file store db
[render_boot] empty database: importing database/schema.sql …
[render_boot] schema imported (… statements).
[render_boot] ensured tables of 017_guest_verify_quota.sql, 018_file_store.sql.
[render_boot] super admin you@example.com: updated.
[render_boot] file store: 0 restored, 0 already present, 0 failed.
```

On later starts the import line is missing, the super admin shows
`unchanged.`, and `file store:` reports how many files were written back.
The password never appears in the log.

---

## 4. Set `CV_BASE_URL` and redeploy

1. At the top of the service page Render shows the public address, for
   example `https://certivault-ab12.onrender.com`.
2. Open **Environment**. Set `CV_BASE_URL` to that address: `https://`,
   no trailing slash, no `/public`.
3. Click **Save, rebuild, and deploy** (or **Save and deploy**).

Do this **before** you issue certificates. The address is printed into
every QR code and every email link. Without it the app works out the
address from each request, which works for pages but not for links built
in the background.

---

## 5. First login and approving institutions

1. Open `https://<your-app>.onrender.com/login.php` and log in with
   `CV_SUPER_ADMIN_EMAIL` and `CV_SUPER_ADMIN_PASSWORD`.
2. Recommended: turn on two-factor authentication on the **Two-factor**
   page.
3. Institutions register at `register_institution.php`. They activate their
   account with the emailed code, which tests Brevo. The super admin then
   approves them on the super-admin dashboard, and approval generates their
   RSA signing key. After that they can issue certificates.
4. About the super-admin env vars: every start of the container applies
   them again. If you change the super admin's password inside the app, the
   next restart resets it to `CV_SUPER_ADMIN_PASSWORD`. You can either:
   * keep the env vars as the single place where you change the password, or
   * **delete** `CV_SUPER_ADMIN_PASSWORD` (and the email) from the Render
     environment after your first login. Deleting them does not change the
     database.

---

## 6. Keep it awake with UptimeRobot (optional)

A free Render service falls asleep after 15 minutes without requests. The
next visitor then waits for a cold start, which can take about a minute. A
monitor that calls the health URL every 5 minutes keeps the service awake.
Every check runs `SELECT 1`, which also keeps the database connection in
use.

1. Create a free account at <https://uptimerobot.com/>.
2. Click **Add New Monitor**.
3. **Monitor type:** HTTP(s). **Friendly name:** CertiVault.
4. **URL:** `https://<your-app>.onrender.com/health.php`
5. **Monitoring interval:** 5 minutes.
6. Click **Create Monitor**.

`/health.php` returns `200 ok` when the database answers and
`503 db unavailable` when it does not. It never starts a session, never
uses the guest verification quota, never writes a log line, and never
reveals anything else.

> **Hours budget:** keeping one service awake all month uses about
> 720–744 hours of the **750 free instance hours per month** in your Render
> workspace. That is enough for one always-on free service, not two.

---

## 7. Limitations of this hosting mode

* **Free hours and cold starts.** 750 free instance hours per month per
  workspace. The service sleeps after 15 idle minutes, and the first
  request after that is slow, up to about a minute. Render may restart free
  instances at any time.
* **Files live in the database.** Certificate uploads (≤ 8 MB each),
  generated PDFs, QR images, attested-credential PDFs, the key-pin file and
  transparency checkpoint files are stored in the `stored_files` table. They
  count against your database storage. The container writes them back to
  disk at every start, so a large archive slows down the start.
  `max_allowed_packet` must be larger than your biggest file; MySQL 8's
  default of 64 MB is enough.
* **Key pins are in the database. This is weaker security.** Normally the
  key-pin file is kept **outside** the database, so an attacker who can
  write the database still cannot swap an institution's key unnoticed
  (attack S6 in [04 Security](04_SECURITY_AND_CRYPTOGRAPHY.md)). With
  `CV_FILE_STORE=db` the pin file, and the transparency signing key if you
  publish checkpoints, are also copied into the database. An attacker with
  full database write access could then change the pins too. For stronger
  guarantees, use a host with a persistent disk, keep `CV_FILE_STORE` unset,
  and put `CV_KEY_PINS_FILE` on storage the database cannot reach. Also
  publish the key fingerprints out of band; `/.well-known/certivault-keys.json`
  lists them.
* **Sessions are lost on restart.** PHP sessions are files inside the
  container, so a restart, redeploy or spin-down logs everyone out.
  "Remember me" logins, rate limits, quotas and OTP codes are stored in the
  database and survive.
* **No shell.** Scripts such as `seed_demo.php` and `publish_checkpoint.php`
  cannot run on the free plan. You can run them on your own computer against
  the same database with the same environment variables. Their files then
  only reach Render through `stored_files` if `CV_FILE_STORE=db` is set
  there too.
* **Database limits.** Check your MySQL plan's storage and connection
  limits. Aiven's free MySQL plan had 1 GB of storage and could be powered
  off when inactive. It is no longer available (see step 1).
* **Email limits.** Brevo's free plan allows 300 emails per day.

---

## 8. Security notes for this setup

* **Client IP header.** Render runs behind Cloudflare. Cloudflare
  **overwrites** `True-Client-IP` and `CF-Connecting-IP` with the address of
  the connection it actually received, so a visitor cannot forge them.
  Render's proxy **appends** to any `X-Forwarded-For` header the visitor
  sends instead of replacing it, so the first entry can be forged
  ([community report](https://feedback.render.com/features/p/send-the-correct-xforwardedfor),
  [write-up](https://rohitpaulk.com/articles/render-rails-remote-ip)).
  That is why `CV_TRUST_PROXY=1` reads `True-Client-IP`, then
  `CF-Connecting-IP`, and **never** `X-Forwarded-For`. A value that is not a
  valid IP address is ignored, and the proxy's address is then kept. Render
  does not officially guarantee these Cloudflare headers. If Render changes
  its edge, set `CV_TRUST_PROXY_HEADERS` to the header it documents. Never
  set `CV_TRUST_PROXY=1` on a server that clients can reach directly.
* `X-Forwarded-Proto: https` sets `HTTPS=on`. As a result, session and
  remember-me cookies get the `Secure` flag and HSTS is sent, as on any
  HTTPS server. The Content Security Policy is unchanged.
* The database connection always verifies the server's TLS certificate
  against the CA you provide.
* Keep the generated secrets (`CV_ENCRYPTION_KEY`, `CV_OTP_PEPPER`,
  `CV_SHARE_SECRET`) and your database password in a password manager.
  Losing `CV_ENCRYPTION_KEY` makes every institution's signing key unusable.

---

## 9. Troubleshooting

Look in the service's **Logs** tab first. Lines starting with
`[render_boot]` and `[CertiVault]` explain most problems.

| Symptom | Cause and fix |
|---------|---------------|
| Every page shows "500 — The service is misconfigured" | The production guard refused to start. The log says why (`FATAL: …`): a secret still has its development value, or `CV_MAIL_TRANSPORT` is not `brevo` with a non-empty `CV_BREVO_API_KEY` (or `smtp`) |
| `/health.php` returns `503 db unavailable`; the log shows `database not reachable` | Wrong host, port, user or password, or the database is powered off (Aiven console → power it on). TLS errors such as `certificate verify failed` or `SSL connection error` mean `CV_DB_SSL_CA_PEM` does not hold the full `ca.pem` text |
| Log: `giving up on the database for now` | The database did not answer at start-up. The app started anyway. Tables, super admin and file restore are retried on the next start; use **Manual Deploy → Restart** after fixing the database |
| `super admin not set …` in the log | The password does not meet the policy (8–72 characters, upper and lower case, digit, special character), or the email already belongs to another account |
| You can't log in as super admin | The env vars were not set on the first start. Set both and restart. Remember that the env value overrides a password you changed in the app |
| Codes or emails never arrive | The log shows `Brevo API send failed (HTTP …)`: `401` means the key is wrong or revoked; `400 … sender` means `CV_MAIL_FROM_EMAIL` is not a verified Brevo sender. Brevo can also block API calls from unknown IP addresses (**Security → Authorized IPs** in Brevo): turn the blocking off, or add Render's outbound IPs (listed in the service's **Connect → Outbound** tab). Also check the spam folder |
| QR codes or email links point to `localhost` or the wrong host | Set `CV_BASE_URL` (step 4). Certificates issued earlier keep their old QR codes; supersede them to get new ones |
| Uploaded certificates or QR images disappear after a restart | `CV_FILE_STORE` is not `db`, or the log shows `FileStore: could not persist …`, for example because the file was larger than `max_allowed_packet` |
| The deploy fails with "no open ports" or a port-scan timeout | The image must start through `docker/entrypoint.sh`. Do not override the Docker command. The script logs the port it set |
| Visitors are rate-limited together, or the audit log shows one IP for everyone | `CV_TRUST_PROXY` is not `1` |
| Login loops or "session expired" after every deploy | This is expected: sessions are lost on restart (section 7). Log in again |

---

## Reference: what changed in the code for this mode

| File | Purpose |
|------|---------|
| `render.yaml` | Render Blueprint (one free Docker web service) |
| `docker/entrypoint.sh` | Sets the Apache port from `$PORT`, runs `scripts/render_boot.php`, then starts Apache |
| `scripts/render_boot.php` | Schema import / safe migrations, super admin from env, file restore. Never stops the container from starting |
| `src/services/FileStore.php` + `database/migrations/018_file_store.sql` | Durable file copies in the `stored_files` table |
| `src/services/SchemaInstaller.php` | Imports `schema.sql` without the `mysql` client (idempotent) |
| `src/services/SuperAdminService.php` | Shared by `set_super_admin.php` and the boot script |
| `src/utils/helpers.php` (`deliver_mail`, `brevo_*`) | Brevo HTTP transport |
| `src/config/config.php`, `src/config/Database.php` | Trusted proxy, `CV_DB_PORT`, DB TLS, `CV_ERROR_LOG`, production guard accepts `brevo` + key |
| `public/health.php` | Health check |
| `tests/test_render_support.php` | Tests for all of the above (mocked HTTP, temporary database) |
