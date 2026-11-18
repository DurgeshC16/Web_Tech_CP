# 04 — Security & Cryptography

## 1. Cryptographic design

### 1.1 Canonical certificate digest

Every identity field **and** the file are bound into one SHA-256 digest
(`CryptoService::computeCertificateHash()`):

```
h = SHA-256( certificate_id | institution_id | student_id | title |
             issue_date | expiry_date | SHA-256(file bytes) )
```

`title` is the only free-text field; all others are identifiers or ISO dates
that cannot contain `|`, so the encoding is unambiguous (200 000 random
combinations, no collision — doc 08). The expiry date is inside the digest,
so extending a validity period needs a new signature. The raw file hash is
also stored separately (`certificates.file_sha256`) so an uploaded original
can be matched.

### 1.2 Digital signature

```
σ = RSASSA-PKCS1-v1_5-Sign( sk_institution , hex(h) )   — OpenSSL, SHA-256
```

* RSA-2048 per institution, created when the super admin approves it.
* The 64-character hex digest is signed. The same signature verifies with
  OpenSSL CLI, PHP, Python and the browser's Web Crypto API (all tested).

### 1.3 Private-key storage

* AES-256-GCM (96-bit nonce, 128-bit tag), `GCM1.` blobs; key =
  `SHA-256(APP_ENCRYPTION_KEY)`. **Set the key before approving the first
  institution.** Legacy CBC blobs remain readable.
* Decrypted keys must parse and match their public key before use.
* External-source secrets and **TOTP secrets** use the same AES-GCM (`CFG1.`).

### 1.4 Versioned keys, fingerprints and **pinning**

* Each certificate records its signing `key_id`; rotated keys are retired,
  never deleted.
* Fingerprints (SHA-256 of the PEM) are public: verify page,
  `institutions.php`, `/.well-known/certivault-keys.json` (always on).
* **Key pinning (`KeyPinService`)** — every key's fingerprint is pinned in an
  append-only JSON file **outside the database**
  (`private_data/pins/<DB_NAME>.json`, `CV_KEY_PINS_FILE`). Keys are pinned on
  approval, rotation, repair and demo seeding; existing installs bootstrap
  with `php scripts/pin_institution_keys.php`. Verification checks the pin
  **before** the RSA signature: a swapped key → **TAMPERED**. Pins are never
  overwritten (conflicts are refused and logged); a corrupt pin file fails
  closed; `KEY_PINNING_STRICT` also rejects keys that were never pinned.
  Keep the pin file on storage the web/DB layer cannot write, back it up, and
  publish `pin_institution_keys.php --export` out of band.
  **Exception — `CV_FILE_STORE=db`** (ephemeral hosts such as Render's free
  plan, [13 Deploy on Render](13_DEPLOY_RENDER.md)): the pin file is also
  copied into the `stored_files` table so it survives restarts, which means
  an attacker with full database write access could alter the pins as well.
  That mode trades this guarantee for free hosting.

### 1.5 Portable signed credentials

`credential.php` exports a certificate as JSON with the signed fields, digest,
signature and the issuer's public key. `offline_verify.php` re-checks it
**entirely in the browser** (Web Crypto). Because the file carries its own
key, the verifier also compares the key with the published key directory or
a fingerprint the user trusts — this is what defeats a forger who re-signs
with their own key.

### 1.6 Transparency log (opt-in)

Issue/revoke/supersede append SHA-256 leaves to a Merkle log (RFC 6962/9162
domain separation); `publish_checkpoint.php` signs roots with a separate
platform key; `compare_checkpoint.php` checks an out-of-band copy.

## 2. Verification cascade

```
exists? ──────────────── no ─► INVALID
revoked? ─────────────── yes ► REVOKED
superseded? ──────────── yes ► SUPERSEDED (+ link to the current version)
recomputed h == stored? ─ no ─► TAMPERED   (data or file altered)
key matches its pin? ──── no ─► TAMPERED   (key record replaced)
RSA verify(h, σ, pk)? ─── no ─► TAMPERED   (forged / wrong key)
expired? ─────────────── yes ► EXPIRED
                                VALID
```

The trust score replays the same checks, so it can never contradict the
verdict.

## 3. Security controls

### Authentication & sessions

| Control | Implementation |
|---------|----------------|
| Passwords | bcrypt; 8–72 chars with upper, lower, digit, special |
| **Two-factor (TOTP)** | Optional for every role (`two_factor.php`); RFC 6238, ±1 step, replay protection (`totp_last_step`), encrypted secret, 10 single-use recovery codes (HMAC-SHA-256 hashes); login requires the code after the password (5 attempts / 5 minutes); emails on enable/disable |
| Login lockout | 5 failures per email + IP in 15 min |
| CAPTCHA | reCAPTCHA v2 when configured, else offline arithmetic |
| Email OTP | HMAC-SHA-256 with `OTP_PEPPER`; 10 min; 5 attempts; 60 s cooldown; 5/hour |
| Sessions | HttpOnly, SameSite=Strict, Secure on HTTPS; regenerated at login (and before the 2FA step); 30 min idle / 8 h absolute |
| Remember me | `selector:validator`, only SHA-256(validator) stored; issued only after the full login (incl. 2FA) |

### Authorization

`require_role()`, `require_approved_institution()`, `require_owned_certificate()`
(row level) on every protected page.

### Input handling & web hardening

| Threat | Control |
|--------|---------|
| SQL injection | Prepared statements, emulation off; strict SQL mode |
| XSS | Escaped output; **CSP `script-src 'self'` + `script-src-attr 'none'`** — no inline scripts or handlers anywhere (verified page-by-page in a real browser; an injected inline script is blocked) |
| CSRF | Token on every POST |
| Malicious uploads | Extension + real MIME; size limits; stored outside the web root; served via `download.php` with `nosniff` |
| CSV formula injection | Exported cells starting `= + - @` are prefixed |
| Enumeration | 256-bit tokens; **pre-lookup** rate gate (31st distinct lookup / IP / 10 min → 429 + `Retry-After`) with constant-cost state (`verify_rate`); status API has its own request budget |
| SSRF (external sources) | HTTPS only, allow-list, public IPs only, redirects re-checked |
| Clickjacking / sniffing / leakage | `X-Frame-Options`, `frame-ancestors`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, HSTS on HTTPS |
| Direct file access | Only `public/` is web content; every other folder denies HTTP; root `.htaccess` 404s dotfiles (tested against Apache) |
| Default credentials | Seeded super admin is locked until `set_super_admin.php` runs |
| Dev shortcuts in production | Production guard refuses default secrets and `MAIL_TRANSPORT=file` |

## 4. Threat model

| Adversary | Can do | Stopped by |
|-----------|--------|-----------|
| Stranger with a PDF copy | Edit the file | File hash in the signed digest → TAMPERED |
| Storage writer | Replace the stored file | Same |
| DB writer (fields) | Edit fields, recompute the digest | Signature mismatch → TAMPERED |
| DB writer re-signing with own key | Forge with attacker key | Verification uses the issuer's key → TAMPERED |
| DB writer **incl. key table** | Swap the issuer key and re-sign (paper S6) | **Key pinning** → TAMPERED (pin file outside the DB) |
| Forger handing out a credential file | Embed their own key | Offline verifier compares with the published key directory |
| Password thief | Log in | 2FA (when enabled) |
| Silent history edit | Change/delete records | Transparency log + external checkpoints |
| Dishonest approved institution | Issue false certificates | Not preventable by cryptography — approval gate + audit trail |

## 5. Remaining gaps

* `style-src` keeps `'unsafe-inline'` only when reCAPTCHA is enabled (its
  third-party widget may inject inline styles); the app itself ships no
  `style=""` attributes or `<style>` blocks, so the default policy is strict.
* Pinning is trust-on-first-use, and its strength depends on keeping the pin
  file out of reach of the web/DB layer.
* Single operator: availability and trust rest on one server.
* `php -S` ignores `.htaccess` — always use `-t public`.
* 2FA is optional, not enforced per role.
