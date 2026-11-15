# 01 — Project Overview

## 1. What is CertiVault?

CertiVault is a web platform that lets **institutions issue digital
certificates** and lets **anyone verify whether a certificate is genuine** —
by scanning its QR code, typing its certificate ID, or uploading the
certificate file. No account is needed to verify.

### The problem

Certificates are normally shared as PDFs or images. These are trivially
edited (a grade changed from B to A+, a date moved, a name swapped), and the
person receiving the certificate — usually an employer — has no quick way to
check it. The traditional answer is to contact the issuer, which is slow and
rarely done. Blockchain-based answers remove the central registry but bring
transaction fees, write latency, and still cannot prove that a ledger
identity belongs to a real institution.

### The solution

CertiVault wraps every certificate in a verification layer built only from
conventional, well-understood cryptography:

| Mechanism | Purpose |
|-----------|---------|
| Unique **Certificate ID** (e.g. `CV-2026-000123`, or a custom ID) | Human-readable lookup key |
| **SHA-256 canonical fingerprint** of the identity fields *and* the file | Detects any change to the data or the file (integrity) |
| **RSA-2048 digital signature** by the issuing institution | Proves *who* issued it (authenticity) |
| **QR code** containing an unguessable 256-bit token | One-scan verification; carries no personal data |
| **Status tracking** — active / expired / revoked / superseded | Lifecycle management with a full audit trail |

> One-line summary: *CertiVault issues a certificate securely (hash +
> signature + QR) and ends every check with a clear, auditable verdict on
> whether that certificate is genuine, intact, active, and issued by the
> right institution.*

## 2. Users and roles

| Role | Account? | What they do |
|------|----------|--------------|
| **Super admin** (`super_admin`) | Yes (seeded, locked until configured) | Approves or rejects institution registrations (approval generates the institution's RSA key pair); manages external verification sources |
| **Institution admin** (`admin`) | Yes, must be **approved** | Issues certificates one by one or in bulk from a CSV, revokes and supersedes (corrects) them; views audit logs and analytics; attests students' external credentials; rotates signing keys |
| **Student** (`student`) | Yes, activated by email OTP | Views, downloads and shares own certificates (24-hour signed share links); sees how often each certificate was verified; declares external credentials (Coursera, Credly, NPTEL…) |
| **Verifier / employer** | **No account needed** | Scans the QR, enters the ID, or uploads the file; receives a verdict, trust score, PDF report and a signed credential they can re-check in their own browser |

## 3. Methodology — end to end

### Start

User opens CertiVault → registers / logs in → system authenticates (password
+ CAPTCHA, email-OTP activation) → role is identified → user is routed to
their dashboard. Verifiers skip this entirely.

### Issuance path (institution admin)

1. **Input & validation** — admin enters student email/name, title, issue
   date, optional expiry, optional custom certificate ID, and uploads the
   certificate file (PDF/PNG/JPG, 100 B – 5 MB; extension *and* real MIME
   type checked).
2. **Student resolution** — the student must have an activated account. If
   not, an unverified account is created, an activation OTP is emailed, and
   issuance stops until the student activates.
3. **Certificate ID** — auto-generated `CV-YYYY-NNNNNN`, or a validated
   custom ID (3–40 chars; the `CV-` namespace is reserved; uniqueness is
   case-insensitive).
4. **File storage** — saved under `private_data/uploads/` (outside the web
   root) with a sanitised, randomised filename.
5. **QR token & image** — a 256-bit random URL-safe token; the QR encodes
   `verify.php?token=…` only.
6. **Canonical hash** —
   `h = SHA-256(certificate_id | institution_id | student_id | title | issue_date | expiry_date | SHA-256(file))`.
7. **Digital signature** — the institution's private key (decrypted from
   AES-256-GCM storage and checked against its public key) signs `h` with
   RSA-PKCS#1 v1.5 / SHA-256.
8. **Commit** — everything is written in one DB transaction; on any failure
   the transaction rolls back and the stored file and QR image are deleted.
   When the transparency log is enabled, an `ISSUE` leaf is appended.
9. **Delivery** — the certificate appears on the student's dashboard for
   viewing, downloading and sharing.

### Verification path (anyone)

The input (QR token, ID in any format, URL, QR image, or the file itself) is
format-checked and rate-limited, then the **verification cascade** runs in a
fixed order (status before integrity, cheap checks before RSA):

| Step | Check | Verdict if it fails |
|------|-------|--------------------|
| 0 | Does the certificate exist? | **INVALID** |
| 1 | Has it been revoked? | **REVOKED** |
| 2 | Has it been replaced by a corrected version? | **SUPERSEDED** (with a link to the new one) |
| 3 | Does the recomputed canonical hash match? (integrity) | **TAMPERED** |
| 4 | Does the issuer's key match its pinned fingerprint? | **TAMPERED** |
| 5 | Is the RSA signature valid for that key? (authenticity) | **TAMPERED** |
| 6 | Is it past its expiry date / marked expired? | **EXPIRED** |
| — | All checks passed | **VALID** |

Revocation and supersession are server-side facts, so they win over
everything else (a revoked certificate shows REVOKED even if its file was
also altered). Every lookup is written to `verification_logs`.

### Lifecycle management

* **Revoke** — records reason, time and acting user; the verdict becomes
  REVOKED forever.
* **Supersede** — issues a corrected certificate with `version + 1`, links
  old ↔ new in both directions and marks the old one SUPERSEDED. Nothing is
  ever deleted, so the audit trail is complete.

### End

The system returns one final verdict — **VALID / TAMPERED / EXPIRED /
REVOKED / SUPERSEDED / INVALID** — plus a 0–100 rule-based trust score, the
attempt is recorded in the audit log, and the verifier can download a PDF
verification report.

## 4. Technology stack

| Layer | Technology |
|-------|-----------|
| Frontend | HTML5, CSS3 (custom responsive design system, light/dark theme), vanilla JavaScript |
| Backend | PHP 8.2 (sessions, cookies, PDO, OpenSSL) — no framework |
| Database | MySQL / MariaDB (InnoDB, utf8mb4) |
| Crypto | SHA-256, RSA-2048 (PKCS#1 v1.5), AES-256-GCM, HMAC-SHA-256, bcrypt |
| Libraries (vendored) | PHPMailer (SMTP), phpqrcode (QR generation), a ZXing PHP port (server QR decoding), html5-qrcode + pdf.js (browser QR/PDF decoding) |
| Libraries (Composer, optional) | dompdf (PDF verification report), smalot/pdfparser (PDF text extraction) |
| Dev environment | XAMPP (Apache + MariaDB + PHP) on Windows, or `php -S` |

## 5. Technical limitations (by design)

| Limitation | Explanation |
|------------|-------------|
| Centralised | One server and database; if it is down, verification is unavailable. |
| Private-key security | If an institution's private key is stolen, valid-looking signatures can be forged. |
| Hash ≠ proof of issuer | A hash proves the data didn't change; only the signature proves *who* issued it. |
| Fake institutions | Mitigated by mandatory super-admin approval. |
| QR codes can be copied | A copied QR still points to the real record; it cannot make a fake certificate verify. |
| Internet dependency | Verification requires reaching the CertiVault server. |
| Key management | Keys are encrypted with an app secret, not an HSM/KMS (college-project simplification). |
| Trust score is rule-based | It confirms the *record* passes technical checks, not the real-world achievement. |
| Single-operator trust | Key fingerprints are pinned outside the database, so a database-write attacker can no longer swap an institution's key unnoticed; the pin file itself must be protected (doc 04). |
| Prototype scope | Production would need backups, monitoring, HA and hardened infrastructure. |
