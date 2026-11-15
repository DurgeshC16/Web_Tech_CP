# 05 — Features & User Guide

## 1. Walkthroughs by role

### 1.1 Super admin

1. Set your login once: `php scripts/set_super_admin.php` (the seeded account
   is locked until you do). Turn on **two-factor authentication** at
   *Two-factor auth*.
2. **Institutions tab** — *Approve* generates the institution's RSA-2048 key,
   stores it encrypted and **pins its fingerprint** outside the database;
   *Reject* records a reason.
3. **External sources tab** — manage optional external verification sources.

### 1.2 Institution admin

1. Register (`register_institution.php`) → activate by email code → wait for
   approval. Turn on two-factor authentication (strongly recommended).
2. **Issue** one certificate (`issue_certificate.php`) with an uploaded file,
   or **Bulk issue** many from a CSV (`bulk_issue.php`, §3.4). Students are
   emailed their verify link; students without an activated account get an
   activation email first.
3. **Revoke** with a reason, or **Supersede** with a corrected version.
4. **Analytics** — verification activity for your certificates (§3.7).
5. **Audit logs** — every verification of your certificates.
6. Optional: attest students' external credentials; rotate your signing key.

### 1.3 Student

1. Register, or receive an activation email when an institution issues to you.
2. **Dashboard** — certificates with "Verified N×" counts.
3. **Certificate detail** — trust score, download, **24-hour share link**,
   **PDF verification report**, **signed credential (JSON)**.
4. Optional: declare external credentials; turn on two-factor authentication.

### 1.4 Verifier / employer (no account)

On `verify.php` (or the landing page):

* **Scan the QR** with the camera, or **type the ID** in any reasonable format.
* **Open a link** — `verify.php?certificate_id=CV-2026-000123` works as a
  shareable direct link.
* **Upload the certificate** (PDF/PNG/JPG ≤ 5 MB). The exact original is
  matched by its fingerprint; any other copy (re-saved, printed to PDF) is
  resolved through the **QR code inside it, read in your browser** — and the
  page then says plainly that your copy is not byte-exact.
* **Privacy mode** — only the SHA-256 and the decoded QR text leave your
  device, never the file.
* Received a **credential file**? Check it yourself at `offline_verify.php`
  (§3.3).

## 2. Verdicts

| Verdict | Meaning | Action |
|---------|---------|--------|
| ✅ VALID | Exists, untampered, signed by the pinned institution key, active, not expired | Accept |
| ❌ TAMPERED | Data/file changed, signature invalid, or the key does not match its pin | Reject |
| ⏰ EXPIRED | Genuine but past its expiry date | Genuine, no longer valid |
| 🚫 REVOKED | Withdrawn by the issuer | Reject |
| 🔁 SUPERSEDED | Replaced by a corrected version | Follow the link |
| ❓ INVALID | No such certificate / malformed input | Reject |

## 3. Feature reference

### 3.1 Smart Verify (ON by default)

One panel: ID / token / URL, or a file. Order of evidence for files: exact
file hash (`file_sha256`) → QR decoded in the browser (pdf.js renders up to 10
PDF pages locally; images are scanned with BarcodeDetector or ZXing, with
padded and upscaled retries) → server QR decode → text extraction. If the
same file backs an active and a superseded certificate, the active one wins.

### 3.2 Trust score, PDF report, status API

* **Trust score** 0–100 from the cascade's own checks; a critical failure caps
  it at 40.
* **PDF report** (`report.php`) — verdict, score, fields, digest, QR back to
  the live page; 5 per 10 min per IP.
* **Status API** — `GET api_status.php?certificate_id=…` → JSON (`api`,
  `generated_at`, `verdict`, `detail`, `certificate{certificate_id, title,
  awarded_to, issued_by, issue_date, status, …}`, `trust_score`). 30 API
  requests per IP per 10 min (website use does not count against it);
  `CV_API_ENABLED=0` disables it.

### 3.3 Signed credential + zero-trust verification

`credential.php?certificate_id=…` (linked from results and the student page)
downloads a `certivault-credential-v1` JSON file: fields, `file_sha256`,
canonical digest, RSA signature, the issuer's public key + fingerprint,
status at export and links. It contains no tokens, keys or paths.

`offline_verify.php` checks it **in your browser**: recomputes the digest,
verifies the signature with Web Crypto, recomputes the key fingerprint,
compares the key with the CertiVault key directory and/or a fingerprint you
paste, optionally hashes your certificate file, and checks the live status.
The headline says *Authentic* only when the signature is valid **and** the key
is confirmed independently — a forger who re-signs with their own key fails
that comparison.

The same check with OpenSSL:

```sh
jq -r .proof.digest_sha256    cred.json | tr -d '\n' > digest.txt
jq -r .proof.signature_base64 cred.json | base64 -d    > sig.bin
jq -r .proof.public_key_pem   cred.json                > issuer.pem
openssl dgst -sha256 -verify issuer.pem -signature sig.bin digest.txt   # → Verified OK
```

Compare `proof.key_fingerprint_sha256` with the institution's published
fingerprint (`/.well-known/certivault-keys.json` or `institutions.php`).

### 3.4 Bulk issuance from CSV

1. *Bulk issue* → download the template.
2. Columns: `student_email`, `student_name`, `title`, `issue_date`
   (YYYY-MM-DD); optional `expiry_date`, `certificate_id`. At most 200 rows
   and 1 MB.
3. Upload → **preview**: every row is checked with the same rules as single
   issuance (duplicate IDs inside the file are flagged). Nothing is written.
4. Confirm → each valid row is issued in its own transaction with a
   **generated certificate PDF** (QR embedded, hashed and signed like any
   upload). Rows for students without an active account become *pending
   activation* (activation email sent).
5. Results table + **results CSV** (certificate IDs and verify links).

### 3.5 Two-factor authentication (TOTP)

*Two-factor auth* in the menu (every role): scan the QR with any authenticator
app (or type the key), enter a code, and **save the 10 recovery codes**
(shown once). Signing in then asks for a code after the password; each
recovery code works once. Turning 2FA off needs your password and a code;
you are emailed whenever it is turned on or off.

### 3.6 Issuance emails

Every issued certificate (single or bulk) emails the student its title,
institution, ID and verify link. Delivery problems never undo issuance.

### 3.7 Institution analytics

*Analytics* (institution admins), for the last 7 / 30 / 90 days:

* KPI tiles — verifications (and the change vs the previous period), share
  of checks that were VALID, distinct verifiers, active certificates;
* **Verifications per day** chart — hover or Tab through the days for exact
  values; *Show as table* lists every day;
* **Verdict mix** and **most-checked certificates** as ranked bars.

Counted: lookups that resolved to your certificates (QR scans, typed IDs,
uploads, reports, credential exports, API calls).

### 3.8 Optional features (OFF by default)

| Feature | Enable | Notes |
|---------|--------|-------|
| External sources | `EXT_REGISTRY_ENABLED` / `EXT_SOURCE_ENABLED` | Shown as *Not verified by CertiVault*; offline demo via `seed_external_source.php` |
| Attested external credentials | `ATTESTED_EXTERNAL_CREDENTIALS_ENABLED` | Never VALID; trust score capped at 70 |
| Transparency log + key rotation | `CERTIFICATE_TRANSPARENCY_ENABLED` | `publish_checkpoint.php`, `compare_checkpoint.php` |
| Strict key pinning | `KEY_PINNING_STRICT` | Also rejects keys that were never pinned |

### 3.9 UI / UX

Responsive (360 → 1280 px), light/dark theme, validation on client and
server, no inline JavaScript, keyboard-accessible charts with table views.
