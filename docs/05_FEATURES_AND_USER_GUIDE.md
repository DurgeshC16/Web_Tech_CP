# 05 — Features & User Guide

## 1. Walkthroughs by role

### 1.1 Super admin

1. Log in (seeded account; set real credentials first with
   `php scripts/set_super_admin.php`).
2. **Institutions tab** — filter Pending / Approved / Rejected.
   * **Approve** → an RSA-2048 key pair is generated and the private key is
     stored encrypted. The institution can now issue.
   * **Reject** → enter a reason; the institution sees it and cannot access
     admin pages.
3. **External sources tab** — add, edit, test or disable managed external
   verification sources (Open Badges / Credly, remote read-only DB).
   Secrets are encrypted and never shown again.

### 1.2 Institution admin

1. **Register** at `register_institution.php` → activate by email OTP →
   wait for super-admin approval.
2. **Issue** (`issue_certificate.php`): student email + name, title, issue
   date, optional expiry (or validity in years), optional custom ID, file.
   If the student has no active account, an activation email is sent and you
   issue after they activate.
3. **Dashboard** lists issued certificates with effective status (an active
   certificate past its expiry date shows as expired).
4. **Revoke** with a reason, or **Supersede** to issue a corrected version
   (old version stays visible as SUPERSEDED and links to the new one).
5. **Audit logs** — every verification of your certificates, with an
   outcome mix and the most common non-VALID reasons.
6. **Attest external credentials** (when enabled) — open the official issuer
   link, compare evidence, then sign an attestation or withdraw it later.
7. **Rotate key** (when transparency is enabled) — new active key; old
   certificates keep verifying with the retired key.

### 1.3 Student

1. **Register** at `register_student.php` (or receive an activation email
   when an institution issues to you) → activate with the emailed code.
2. **Dashboard** — your certificates, each with "Verified N× · last …",
   plus an activity strip (total checks, VALID results, last check).
3. **Certificate detail** — trust-score card, download the original file,
   download the PDF verification report, and **generate a share link**
   (HMAC-signed, expires after 24 hours).
4. **External credentials** (when enabled) — declare a Coursera / Credly /
   NPTEL / custom-issuer credential with its official URL or code and an
   optional PDF; it shows as SELF_DECLARED until an institution attests it.
5. **Change password** — confirmed by an emailed code.

### 1.4 Verifier / employer (no account)

Go to `verify.php` (or the landing page) and use any of:

* **Scan the QR** on the certificate (opens `verify.php?token=…`).
* **Type the certificate ID** in any reasonable format — `CV-2026-000123`,
  `cv 2026 123`, `CV20260123`, or a custom ID with any spacing/punctuation.
* **Paste a link** — a CertiVault verify URL, or an issuer URL.
* **Upload the certificate file or a QR image** (PDF/PNG/JPG ≤ 5 MB).
  Privacy mode hashes the file in your browser so the bytes never leave
  your device.

You get a verdict seal, the certificate details, the issuing key's
fingerprint, a trust score with a per-check checklist, and a **Download
verification report** button.

## 2. Verdicts

| Verdict | Meaning | What to do |
|---------|---------|-----------|
| ✅ **VALID** | Exists, untampered, correctly signed, active, not expired | Accept |
| ❌ **TAMPERED** | Data/file changed after issuance, or signature invalid | Reject — likely forged or altered |
| ⏰ **EXPIRED** | Genuine, but past its expiry date | Genuine but no longer valid |
| 🚫 **REVOKED** | Withdrawn by the issuer (reason recorded) | Reject |
| 🔁 **SUPERSEDED** | Replaced by a corrected version | Follow the link to the current version |
| ❓ **INVALID** | No such certificate / malformed input | Reject |

External records use separate labels — `EXTERNAL_FOUND`, `ATTESTED`,
`SELF_DECLARED`, `WITHDRAWN` — and are **never** shown as VALID.

## 3. Feature reference

### 3.1 Smart Verify (`verify.php`, `index.php`) — ON by default

One panel accepts an ID, token, URL, QR image or certificate file. You must
supply at least one of *ID* or *file*; if both are given, the file is checked
first and the ID is the fallback. Text pipeline: self-verify URL → bare
token → CV-ID heuristics → allow-listed issuer links (never fetched by the
server). File pipeline: byte-hash match → QR decode → text extraction →
regex scan; temporary files are always deleted. Disable with
`CV_SMART_VERIFY=0`.

> ⚠️ Known bug: byte-hash matching of an *issued* file currently never hits
> (see doc 09, item 1). QR decoding and text extraction still resolve
> uploaded certificates.

### 3.2 Trust score

0–100, computed only from the checks the cascade already runs: exists 20,
hash 30, signature 30, not expired 10, not revoked 10. Any failed critical
check (exists / hash / signature) caps the score at 40, and the score can
never contradict the verdict. Disclaimer shown with it: *"CertiVault
confirms the record passes technical checks; it does not verify the
real-world achievement."*

### 3.3 PDF verification report (`report.php`)

One PDF per verification: verdict, trust score and checks, certificate
fields, SHA-256 digest, and a QR back to the live verify page. It contains
no tokens, keys or file paths. Limited to 5 downloads per 10 min per IP and
audit-logged. Needs dompdf (`composer install`); without it a fallback page
with the same facts is shown.

### 3.4 Public status API (`api_status.php`) — ON by default

```http
GET /api_status.php?certificate_id=CV-2026-000123
```

```json
{
  "api": "certivault-status",
  "generated_at": "2026-11-15T10:00:00+00:00",
  "verdict": "VALID",
  "detail": "All integrity, authenticity, expiry, and status checks passed.",
  "certificate": {
    "certificate_id": "CV-2026-000123", "title": "…", "awarded_to": "…",
    "issued_by": "…", "issue_date": "2026-06-01", "status": "active", "…": "…"
  },
  "trust_score": { "score": 100, "checks": [ … ], "disclaimer": "…" }
}
```

Unknown or malformed IDs → `404 NOT_FOUND` (never 500). Rate-limited and
audit-logged; never returns tokens, keys, signatures or paths. Disable with
`CV_API_ENABLED=0` (→ `403 api_disabled`). Exact field names are defined in
`src/services/StatusApiService.php`.

### 3.5 External verification sources — OFF by default

When an ID is not found locally, configured external sources are queried
and shown in a separate card marked **"Not verified by CertiVault"**.
Adapters: `OpenBadgesAdapter` (Open Badges 2.0 / Credly over HTTPS) and
`RemoteDbAdapter` (read-only PDO connection). Configure either through the
super-admin **External sources** tab (`EXT_REGISTRY_ENABLED=true`, migration
010) or legacy `EXT_*` constants. Offline demo: `php
scripts/seed_external_source.php` creates ten invented records
`DEMO-MOOC-001` … `DEMO-MOOC-010`.

CertiVault never scrapes issuer sites: scraping is brittle, may break terms
of service, can leak student identifiers, and would falsely imply that
CertiVault validated the credential.

### 3.6 Attested external credentials — OFF by default

Enable with `ATTESTED_EXTERNAL_CREDENTIALS_ENABLED=true` (migration 011).
A student declares a credential; an approved institution checks the
official link in its own browser and signs an attestation covering student,
issuer, code, URL, title, date, optional PDF SHA-256, institution and
timestamp. Public page: `external_credential.php?token=…`. Outcomes:
ATTESTED / SELF_DECLARED / TAMPERED / WITHDRAWN — never VALID. Trust score
capped at 70.

### 3.7 Key history & transparency log — OFF by default

Enable with `CERTIFICATE_TRANSPARENCY_ENABLED=true` (migration 012). See
doc 04 §1.4–1.5. Operator tasks:

```sh
php scripts/publish_checkpoint.php                       # sign + publish current root
php scripts/compare_checkpoint.php path/to/latest.json   # compare with an out-of-band copy
php tests/benchmark_transparency_log.php                 # timing CSV for the paper
```

### 3.8 UI / UX

* Responsive design verified at 360 / 768 / 1024 / 1280 px (stacked tables
  with `data-labels` on mobile, 44 px touch targets, hamburger nav < 768 px).
* Light/dark theme stored in the `cv_theme` cookie.
* "Remember email" (`cv_email`) and "remember me" login cookies.
* Every validator runs on the client (`validation.js`, UX only) **and** on
  the server (`validators.php`, authoritative).
