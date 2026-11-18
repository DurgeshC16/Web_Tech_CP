# 11 — Novelties & Comparison with Existing Approaches

*Last reviewed (and fact-checked against code and sources): 2026-11-18. Competitor facts come from public vendor pages,
standards documents and third-party reviews listed under
[References](#9-references); anything that could not be confirmed from a
primary source is marked **(unverified)**. Every CertiVault claim names the
file that implements it.*

## 1. Executive summary

Commercial credential platforms (Credly, Certifier, Accredible, Sertifier)
are **hosted SaaS registries**: the certificate is trusted because the
vendor's web page says it is valid. They are excellent at design,
distribution, LinkedIn sharing and analytics, and are moving to the open
**Open Badges 3.0 / W3C Verifiable Credentials 2.0** standards (Accredible
also writes a hash of each credential to Ethereum). Blockchain systems
(Blockcerts) remove the central registry by anchoring Merkle roots on
Bitcoin/Ethereum, at the cost of transaction fees, wallets and complexity. India's **DigiLocker / National Academic Depository (NAD)** is a
free, government-run repository with legal standing, but verification by an
employer requires API registration and the student's consent, and can take
up to 24 hours.

**CertiVault takes a different design point:** a self-hostable, free web
platform in which *every* certificate is bound to its exact file and signed
with the issuing institution's own RSA key, and in which **the verifier does
not have to trust the server** — the issuer key is pinned outside the
database, issuance history can be committed to a signed Merkle log, and a
signed credential can be re-checked entirely in the browser (Web Crypto) or
with OpenSSL. On top of that it offers verification features no surveyed
platform documents: upload-the-PDF verification with in-browser QR
decoding, a privacy mode that never uploads the file, a six-verdict cascade
(VALID / TAMPERED / EXPIRED / REVOKED / SUPERSEDED / INVALID), an
explainable 0–100 trust score and a downloadable PDF verification report.

Where CertiVault is **weaker**: no Open Badges 3.0 / W3C VC export yet, no
LinkedIn "Add to profile", no certificate designer, no public HTTPS
deployment, no ecosystem/marketplace, and keys are custodied by the server
(encrypted, not in an HSM). Section 7 turns these gaps into a prioritised
roadmap.

## 2. The problem being solved

1. Certificates circulate as PDFs and images that are trivial to edit.
2. Employers rarely contact issuers; manual checks are slow and costly.
3. A "verified" badge on a vendor page is only as trustworthy as that
   vendor's database — and it disappears if the vendor or account goes away.
4. Blockchain anchoring removes the central database but adds fees, latency
   and wallet friction, and still cannot prove that an on-chain identity is a
   real institution ([doc 08 §1](08_RESEARCH_SUMMARY.md#1-positioning)).
5. Indian colleges must also fit into DigiLocker/NAD, which serves degrees
   and mark sheets well but not the long tail of workshop, course and event
   certificates that colleges issue every week.

## 3. How existing approaches work

### 3.1 Credly (Pearson) — hosted badge registry
* **Issue:** organisations create badge templates and award them on the
  Credly platform; earners claim the badge by setting up a Credly account
  (ISC2's earner instructions, ref. 4).
* **Verify:** anyone opens the badge's public overview page on credly.com;
  trust rests on Credly's hosted record.
* **Standards:** announced Open Badges 3.0 support on 16 Oct 2024 — earners can
  *upload and verify* OB 2.0/3.0 badges from other platforms. Whether Credly's
  own badges are issued as signed OB 3.0 credentials is not stated on the
  pages reviewed **(unverified)**; Credly's own OB 3.0 page does not mention
  blockchain, although one third-party review claims blockchain storage
  **(unverified)**.
* **Strengths:** one-click LinkedIn sharing (ref. 4); a large corporate
  issuer network and skills/labour-market analytics are vendor-marketing
  claims not re-checked here **(unverified)**.
* **Model:** commercial SaaS, quote-based pricing; vendor lock-in for the
  hosted verification page.

### 3.2 Certifier — certificate & badge SaaS
* **Issue:** designer with 2,000+ certificate and 300+ badge templates, bulk
  issuance from spreadsheets, native integrations (Google Sheets, Excel,
  HubSpot, Salesforce) and connectors (Zapier, Make, Pipedream).
* **Verify:** login-free credential page reachable via URL / verification QR
  code.
* **Standards:** states it is "Open Badge 3.0 compliant". This is
  self-reported: no 1EdTech OB 3.0 certification listing for Certifier was
  found **(unverified)**.
* **Blockchain:** not mentioned on Certifier's compare page; a third-party
  review table marks it "Blockchain Verified" **(unverified)**.
* **Security:** displays ISO 27001 / ISO 9001 badges; SSO (Okta, SAML,
  Entra ID) for enterprise.
* **Model:** "free-forever plan with unlimited credentials", paid
  per-credential tiers; SaaS only.

### 3.3 Accredible — enterprise credential platform
* **Issue:** certificates, badges and diplomas; priced "by the number of
  recipients — not credentials".
* **Verify:** hosted credential page, no account needed; since **Jan 2026**
  credentials are packaged as Open Badge 2.0, Open Badge 3.0 or W3C VC when
  shared or verified, and the wallet can import OB 3.0 / VC credentials from
  other issuers, keeping their signatures.
* **Blockchain:** at issuance a hash of each credential (no personal data)
  is recorded on Ethereum; "blockchain verification is included on every
  plan". Older credentials were anchored on Bitcoin (help-centre summary,
  **unverified**).
* **Security:** MFA and SSO listed on the pricing page (tier not stated).
* **Model:** commercial SaaS; entry "Launch" plan from US$45/month (50
  recipients), higher tiers quote-based.

### 3.4 Sertifier — SaaS with optional blockchain layer
Supports "Open Badges standards" (version not stated on its homepage; a
third-party review says OB 2.0 **(unverified)**); "for added trust, you can
enable blockchain-backed validation" — i.e. blockchain is an *optional*
layer. Native LMS/CRM integrations (Canvas, Moodle, Salesforce…), REST API
and webhooks, trigger-based auto-issuance.

### 3.5 Blockcerts (MIT Media Lab → Hyland) — open standard on blockchain
* **Issue:** `cert-issuer` hashes each certificate of a batch into a Merkle
  tree and writes the 256-bit root into one Bitcoin/Ethereum transaction;
  every certificate carries a `MerkleProof2019` receipt.
* **Verify:** the open-source Blockcerts verifier recomputes the hash, walks
  the Merkle path and checks the root on-chain; v3 follows the W3C VC model
  (not backward-compatible with v2) and can name a DID as issuer.
* **Revocation:** revocation lists published by the issuer (needs network).
* **Model:** open source (`cert-issuer` is MIT-licensed); the issuer pays
  transaction fees and must run issuing infrastructure. The MIT Media Lab is
  no longer actively involved; Hyland (formerly Learning Machine) is the
  project's primary steward.

### 3.6 Open Badges 3.0 and W3C Verifiable Credentials 2.0 (standards)
* **OB 3.0** (1EdTech Final Release; the current specification page is dated
  29 Jun 2026) re-bases badges on the W3C VC Data Model 2.0 — every
  assertion is a Verifiable Credential carrying a cryptographic proof, so
  verification relies on the embedded proof rather than on the issuer's
  hosted record.
* **W3C VC 2.0 family** (seven specifications) became W3C Recommendations on
  **15 May 2025**, including
  **Bitstring Status List v1.0** — a privacy-preserving, compressed
  revocation/suspension list.
* These are the interoperability target every serious platform is moving to.

### 3.7 Europass Digital Credentials (EU)
Institutions seal credentials with an **advanced or qualified electronic
seal** (eIDAS); the seal is re-checked every time the credential is viewed in
the EDC viewer. Strong legal standing in the EU; needs a seal from a trust
service provider.

### 3.8 DigiLocker / National Academic Depository (India)
* **Issue:** registered academic institutions lodge awards as CSV (bulk data
  can also go through a secure API) using NAD's standard templates —
  institutions cannot add their own certificate designs, and scanned images
  are not accepted.
* **Access:** students fetch awards into "Issued Documents" in DigiLocker.
* **Verify:** verifiers register on the API Setu partner portal; every
  verification needs the **student's consent** (Aadhaar/OTP-based approval,
  eSign, or a paper consent form) and the record is available **within 24
  hours of that consent**.
* **Legal:** the NAD FAQ states these documents are recognised as
  equivalent to the original physical documents (DigiLocker rules under the
  IT Act, 2000). The FAQ does not describe a digital signature on the award
  itself.
* **Model:** free; government-operated; India only; not self-hostable.

## 4. Feature comparison matrix

Legend: ✅ supported · ⚠️ partial / limited / unverified (see note) ·
❌ not supported or not documented.

| # | Capability | CertiVault | Credly | Certifier | Accredible | Blockcerts | DigiLocker/NAD |
|---|------------|:-:|:-:|:-:|:-:|:-:|:-:|
| 1 | Cryptographic signature on each certificate | ✅ | ⚠️¹ | ⚠️¹ | ✅² | ✅ | ⚠️³ |
| 2 | Per-institution signing key | ✅⁴ | ❌ | ❌ | ⚠️¹ | ✅ | ❌ |
| 3 | Issuer-key pinning outside the database | ✅ | ❌ | ❌ | ❌ | ⚠️⁵ | ❌ |
| 4 | Transparency log / Merkle checkpoints | ✅⁶ | ❌ | ❌ | ⚠️²² | ✅ | ❌ |
| 5 | Offline / zero-trust verification in the browser or CLI | ✅ | ❌ | ⚠️⁷ | ⚠️⁷ | ✅ | ❌ |
| 6 | Verify by uploading the exact certificate file (hash match) | ✅ | ❌ | ❌ | ❌ | ⚠️⁸ | ⚠️³ |
| 7 | Smart Verify: ID / URL / token / file / PDF→QR decoded in browser | ✅ | ⚠️⁹ | ⚠️⁹ | ⚠️⁹ | ⚠️⁹ | ⚠️⁹ |
| 8 | Privacy mode (file hashed in the browser, never uploaded) | ✅ | ❌ | ❌ | ❌ | ✅¹⁰ | ❌ |
| 9 | Trust score + downloadable PDF verification report | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| 10 | Public status API for verifiers | ✅ | ⚠️¹¹ | ⚠️¹¹ | ⚠️¹¹ | ⚠️¹¹ | ⚠️¹² |
| 11 | Revocation | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| 12 | Supersession with bidirectional version chain | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| 13 | External credentials inside the same profile | ⚠️¹³ | ✅ | ❌ | ✅ | ❌ | ❌ |
| 14 | Bulk issuance with generated certificate PDFs | ✅¹⁴ | ✅ | ✅ | ✅ | ⚠️ | ✅ |
| 15 | Two-factor authentication for issuers | ✅¹⁵ | ⚠️¹ | ⚠️²³ | ✅²³ | n/a | ⚠️¹ |
| 16 | Issuer analytics | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| 17 | Open Badges 3.0 / W3C VC format | ❌¹⁶ | ⚠️²⁴ | ✅²⁴ | ✅ | ✅ | ❌ |
| 18 | Public-blockchain anchoring | ❌ | ⚠️²⁵ | ⚠️²⁵ | ✅²² | ✅ | ❌ |
| 19 | Wallet / LinkedIn sharing | ⚠️¹⁷ | ✅ | ✅ | ✅ | ⚠️ | ⚠️¹⁸ |
| 20 | Verifier needs no account | ⚠️¹⁹ | ✅ | ✅ | ✅ | ✅ | ❌ |
| 21 | Issuer vetting before issuing | ✅ | ⚠️¹ | ❌ | ⚠️¹ | ❌ | ✅ |
| 22 | Certificate design templates / designer | ⚠️²⁰ | ✅ | ✅ | ✅ | ❌ | ⚠️ |
| 23 | Free & self-hostable | ✅²¹ | ❌ | ⚠️ free tier | ❌ | ✅ (+ chain fees) | free, ❌ self-host |

**Notes**

1. Not documented on the pages reviewed; treat as **unverified**.
2. Since Jan 2026, credentials are packaged as OB 2.0, OB 3.0 or W3C VC
   when shared or verified; the hosted page remains the usual verification
   path.
3. Issued documents are retrieved from the issuer's repository through
   DigiLocker; the FAQ does not describe a signature on the award itself
   **(unverified)**.
4. One RSA-2048 key pair per approved institution (`CryptoService::generateRSAKeyPair()`,
   created on approval in `public/super_admin.php`); opt-in rotation in
   `public/rotate_key.php` (only when `CERTIFICATE_TRANSPARENCY_ENABLED`).
   **Custody:** the private key is stored on the
   CertiVault server, AES-256-GCM-encrypted — not in an HSM, and not held
   by the institution itself.
5. Blockcerts publishes issuer keys in an issuer profile / DID, which serves
   a similar purpose; there is no separate pin store.
6. Opt-in (`CERTIFICATE_TRANSPARENCY_ENABLED`); roots are signed with a
   platform key and compared out of band — not anchored on a public chain.
7. Possible in principle through OB 3.0 / VC exports and third-party VC
   verifiers; not a product feature advertised by the vendor.
8. The Blockcerts JSON *is* the certificate; a PDF rendering is not what is
   verified.
9. Verification by URL / QR / badge ID only; no documented
   "upload any copy of the PDF and decode its QR in the browser".
10. Blockcerts' verifier also runs client-side on the credential file.
11. Issuer-side REST APIs (badges, recipients); no documented anonymous
    verifier status endpoint. Blockcerts publishes revocation lists, not a
    status API.
12. API Setu verifier API — registration + student consent required.
13. CertiVault: an institution can **attest** a student's Coursera / Credly /
    NPTEL credential (opt-in, `ATTESTED_EXTERNAL_CREDENTIALS_ENABLED`, off by
    default), shown as *ATTESTED*, never *VALID*, score capped at 70; with
    `EXT_SOURCE_ENABLED` / `EXT_REGISTRY_ENABLED` (also off by default) it can
    read hosted Open Badges 2.0 assertions from allow-listed HTTPS hosts.
    Credly verifies uploaded OB 2.0/3.0 badges and Accredible keeps imported
    OB 3.0 / VC signatures, which is stronger.
14. CSV up to 200 rows / 1 MB, preview before commit, generated PDF with the
    QR embedded (`BulkIssueService`, `CertificatePdfService`).
15. TOTP (RFC 6238) + 10 recovery codes for every role; optional, not
    enforced.
16. Own signed JSON format `certivault-credential-v1`; OB 2.0 assertions can
    be *read* from external sources (opt-in, see note 13) but not issued.
17. 24-hour HMAC-signed share links and a downloadable signed credential; no
    LinkedIn button, no mobile wallet.
18. DigiLocker app acts as a wallet; no LinkedIn sharing.
19. New in this release: visitors who are not logged in get 5 free
    verifications per rolling 24 h on the website (`GuestQuotaService`,
    `GUEST_VERIFY_LIMIT` / `GUEST_VERIFY_WINDOW`; counted per IP and per
    session) and are then asked to log in or register — an account is free.
    The JSON status API (own rate budget) and the offline credential check do
    not use this quota — see §5.12.
20. Bulk issuance renders one standard generated layout; no visual designer.
21. Runs on XAMPP, `php -S` or Docker (`Dockerfile`, `docker-compose.yml`);
    the repository has no licence file yet (see §7).
22. Accredible records a hash of each credential on Ethereum — public
    anchoring, but not a documented auditable Merkle log of issue / revoke /
    supersede events.
23. Accredible's pricing page lists MFA and SSO (tier not stated); Certifier's
    compare page lists SSO (Okta / SAML / Entra ID) but does not mention 2FA.
24. Credly documents *uploading and verifying* OB 2.0/3.0 badges; issuing its
    own badges as signed OB 3.0 credentials is not documented on the pages
    reviewed **(unverified)**. Certifier's OB 3.0 compliance is self-reported
    (no 1EdTech certification listing found).
25. Neither vendor's own pages reviewed mention blockchain; a third-party
    review claims it for both **(unverified)**.

## 5. Novelties of CertiVault

Each item: **what** · **why it matters** · **how** (files) · **who lacks it**.

### 5.1 File-bound canonical digest + per-institution signature
* **What:** one SHA-256 digest binds certificate ID, institution, student,
  title, issue and expiry dates **and the SHA-256 of the exact file**; the
  digest is signed with the institution's RSA-2048 key (PKCS#1 v1.5).
* **Why:** changing a single byte of the PDF, a date or the title yields
  TAMPERED; the signature also says *who* issued it. 3 500 random edits were
  all detected ([doc 08 §3](08_RESEARCH_SUMMARY.md#3-key-results)).
* **How:** `CryptoService::computeCertificateHash()`,
  `signCertificateHash()`, `verifyCertificateSignature()`;
  `IssuanceService::issue()`.
* **Lacking:** hosted platforms verify a database record, not the file the
  employer actually received.

### 5.2 Issuer-key pinning outside the database
* **What:** the fingerprint of every institution key is written to an
  append-only JSON pin file outside the DB and checked *before* the RSA
  signature; a swapped key → TAMPERED; corrupt pin file fails closed.
* **Why:** closes the attack in which a database writer replaces the
  institution's public key and re-signs (paper attack S6).
* **How:** `src/services/KeyPinService.php` (`pin()`, `check()`,
  `acceptable()`), `KEY_PINS_FILE`, `KEY_PINNING_STRICT`.
* **Lacking:** no surveyed SaaS documents an equivalent; Blockcerts relies
  on issuer profiles/DIDs instead.

### 5.3 Signed Merkle transparency log (no blockchain)
* **What:** issue / revoke / supersede events become SHA-256 leaves of an
  RFC 6962-style Merkle tree; checkpoints are signed with a separate platform
  key and can be compared with an out-of-band copy.
* **Why:** silent edits or deletions of history become detectable, with
  640-byte proofs at 10⁶ records and no gas fees.
* **How:** `TransparencyLogService` (`append()`, `checkpoint()`,
  `inclusionProof()`, `verifyInclusionProof()`), `scripts/publish_checkpoint.php`,
  `scripts/compare_checkpoint.php`.
* **Lacking:** Credly, Certifier, DigiLocker; Accredible anchors per-credential
  hashes on Ethereum but documents no auditable event log.

### 5.4 Zero-trust, offline verification of a portable credential
* **What:** `credential.php` exports a signed JSON credential;
  `offline_verify.php` recomputes the digest, verifies the RSA signature with
  Web Crypto, recomputes the key fingerprint and only says *Authentic* when
  the key is also confirmed against the published key directory
  (`/.well-known/certivault-keys.json`) or a fingerprint the user pastes.
  The same check works with plain OpenSSL.
* **Why:** an employer can verify without trusting (or even reaching) the
  CertiVault server, and a forger who re-signs with their own key fails.
* **How:** `CredentialService::build()` / `verifyOffline()`,
  `public/assets/js/credential-verify.js`, `public/well-known-keys.php`.
* **Lacking:** Credly and DigiLocker (hosted record only); Certifier and
  Accredible only indirectly, through OB 3.0 / VC exports checked by
  third-party verifiers.

### 5.5 Smart Verify — "upload whatever you were given"
* **What:** one input accepts an ID in any reasonable format, a token, a URL,
  a QR image or the certificate file. Files are matched by exact hash first;
  otherwise the QR inside the PDF/image is decoded **in the browser**
  (pdf.js renders up to 10 pages; BarcodeDetector → ZXing with padded /
  upscaled retries), then server QR decode, then text extraction. The page
  says plainly when the copy is not byte-exact.
* **Why:** employers usually receive a re-saved or printed PDF, not a link.
* **How:** `SmartVerifyService`, `FileVerifyService`,
  `public/assets/js/smart-verify.js`, `public/verify.php`.
* **Lacking:** all surveyed platforms verify by link / QR / ID only.

### 5.6 Privacy mode
* **What:** the file is hashed with Web Crypto; only the SHA-256 and the
  decoded QR text are sent — never the document.
* **Why:** verifiers may not upload personal documents to third parties
  (DPDP Act 2023 / GDPR data-minimisation).
* **How:** `public/assets/js/smart-verify.js` (privacy toggle).

### 5.7 Six-verdict cascade with fixed precedence
* **What:** INVALID → REVOKED → SUPERSEDED → TAMPERED (hash, pin, signature)
  → EXPIRED → VALID; status facts win over integrity; every lookup is logged.
* **Why:** a binary "verified / not verified" hides *why*; the verdict tells
  an employer what to do ([doc 05 §2](05_FEATURES_AND_USER_GUIDE.md#2-verdicts)). Precedence matched an oracle in 16/16
  cases.
* **How:** `VerificationService::verify()` / `effectiveStatus()`.

### 5.8 Explainable trust score + PDF verification report
* **What:** a 0–100 score that replays the cascade's own checks (critical
  failure caps it at 40) and a downloadable PDF report with verdict, score,
  fields, digest and a QR back to the live result.
* **Why:** HR files need an artefact; the score can never contradict the
  verdict.
* **How:** `TrustScoreService::compute()`, `ReportService::buildReportPdf()`,
  `public/report.php`.
* **Lacking:** no surveyed platform documents a scored, downloadable report.

### 5.9 Supersession with a bidirectional version chain
* **What:** a corrected certificate gets `version + 1`; old ↔ new are linked
  both ways; the old one verifies as SUPERSEDED with a link to the current
  one. Nothing is deleted.
* **How:** `public/supersede_certificate.php`, `VerificationService`.
* **Lacking:** competitors offer revoke/edit/re-issue but no public version
  chain.

### 5.10 Anonymous public status API + key directory
* **What:** `GET api_status.php?certificate_id=…` returns verdict, fields and
  trust score as JSON with its own rate budget (30 / IP / 10 min);
  `/.well-known/certivault-keys.json` publishes all institution public keys
  and fingerprints.
* **How:** `StatusApiService`, `public/api_status.php`,
  `public/well-known-keys.php`.
* **Lacking:** DigiLocker requires registration and consent; SaaS APIs are
  issuer-side.

### 5.11 Institution attestation of external credentials
* **What:** a student declares a Coursera / Credly / NPTEL credential; an
  institution admin can attest that it checked it. It is shown as ATTESTED
  (never VALID) with the score capped at 70 and a clear disclaimer.
* **Why:** brings MOOC certificates (NPTEL is common in Indian colleges) into
  one profile without pretending CertiVault verified them.
* **How:** `AttestedCredentialService`, `TrustScoreService::computeExternalCredential()`,
  `public/attest_external_credentials.php` (opt-in:
  `ATTESTED_EXTERNAL_CREDENTIALS_ENABLED`, off by default).

### 5.12 Security engineering visible to the user
Pre-lookup rate limiter with constant-cost state (`VerificationService::checkAndRecordLookup()`),
strict CSP with **no inline scripts**, TOTP 2FA with replay protection
(`TotpService`), super-admin approval before an institution gets a key,
AES-256-GCM key storage, SSRF-hardened external lookups
(`ExternalSourceService::isHostAllowed()` / `isIpBlocked()`).
**New in this release:** a guest verification allowance (5 free
verifications per 24 h for visitors on the verify / share / report pages,
then a clear "free limit reached — log in or register" message;
`src/services/GuestQuotaService.php`, migration
`database/migrations/017_guest_verify_quota.sql`), a resumable registration
and a two-step forgot-password flow whose second page
(`public/reset_password.php`) has a field for the emailed verification code,
and a reproducible ~100-person dummy certificate dataset generated through
the real issuance code (`scripts/generate_dataset.php`, accounts on the
reserved `@dataset.example.com` domain).

## 6. Where existing platforms are stronger

| Area | Why they lead | Impact on CertiVault |
|------|---------------|----------------------|
| **Interoperability** | OB 3.0 / W3C VC issuance and import (Accredible, Certifier, Credly upload) | CertiVault credentials cannot yet be imported into other wallets |
| **Network effect** | Credly's earner network and employer recognition | A new platform has no brand recognition with recruiters |
| **Sharing** | LinkedIn "Add to profile", social share cards, public profiles | CertiVault has 24-hour share links only |
| **Design** | Visual designers with 2,000+ certificate templates (Certifier) | One generated layout for bulk issuance |
| **Integrations** | LMS, CRM, Zapier, Google Sheets, webhooks | CSV upload only |
| **Legal standing (India)** | DigiLocker/NAD records are at par with originals under the IT Act | CertiVault certificates have no statutory status |
| **Decentralisation** | Blockcerts survives the issuer/platform disappearing | CertiVault verification needs its server (except the offline check) |
| **Operations** | SaaS: HTTPS, uptime SLAs, backups, ISO 27001 (badge shown by Certifier), MFA/SSO (Accredible, Certifier SSO) | CertiVault is a prototype; key custody without HSM/KMS |
| **Analytics depth** | Skills/labour-market insights (Credly) | Verification analytics only |

## 7. Gaps & roadmap (features yet to be added)

Effort: S ≈ ≤ 2 days, M ≈ 1 week, L ≈ 2–4 weeks (one developer).

### P1 — high value, do next
| Feature | Why | Effort |
|---------|-----|:-:|
| **Open Badges 3.0 / W3C VC 2.0 export** with `did:web` issuer identifiers (JWT or Data Integrity proof), next to `certivault-credential-v1` | Interoperability with Credly/Accredible wallets and VC verifiers | M |
| **LinkedIn "Add to profile" + share cards** (Open Graph image per certificate, permanent public link) | The #1 reason students value Credly | S |
| **Public HTTPS deployment** (`Dockerfile` / `docker-compose.yml` already exist) + automated backups | Real employers can use it; Secure cookies/HSTS take effect | S–M |
| **Mandatory 2FA for admin and super-admin roles** | Issuer accounts are the highest-value target | S |
| **Bitstring Status List (W3C)** / append-only revocation list | Privacy-preserving, cacheable revocation for offline verifiers | M |
| **Add an open-source licence** (e.g. MIT/Apache-2.0) | The code is public but legally not reusable without one | S |

### P2 — strengthens trust and adoption
| Feature | Why | Effort |
|---------|-----|:-:|
| **RFC 3161 trusted timestamps** on signatures, or anchoring Merkle checkpoints on a public chain / in a public Git repo | Proves *when* something was issued; removes single-operator trust | M |
| **Employer accounts** with verification history, saved reports and bulk verification (CSV of IDs) | Turns one-off checks into a recruiter workflow | M |
| **API keys + webhooks** (issued / revoked events) for HR and LMS systems | Integrations comparable to SaaS platforms | M |
| **Certificate template designer** (drag-and-drop, institution logo, signature images) | Closes the biggest UX gap vs Certifier | L |
| **Institution domain verification** (DNS TXT or email on the institution's domain) | Stronger vetting before approval | S |
| **DigiLocker / NAD push** (as an Issuer via API Setu) for degree-type awards | Legal standing in India; CertiVault keeps the long tail of event certificates | L (needs govt onboarding) |
| **HSM / cloud KMS** or institution-held keys (sign locally, upload signature) | Removes server custody of private keys | L |
| ~~Remove `style-src 'unsafe-inline'`~~ (done) | Completes the CSP hardening | S–M |

### P3 — polish and reach
| Feature | Why | Effort |
|---------|-----|:-:|
| **PWA / mobile wallet** (offline storage of credentials, camera scan) | Students carry certificates on the phone | M |
| **Multi-language UI** (Hindi, Marathi, …) | Indian user base | M |
| **Accessibility audit** (WCAG 2.2 AA, screen-reader test) | Inclusive use; required by many institutions | S–M |
| Skills / competency metadata (ESCO, NSQF levels) on certificates | Matches OB 3.0 achievement model; enables skills search | M |
| Public institution profile pages and certificate galleries | Discoverability, SEO | S |
| LMS integrations (Moodle, Google Classroom) for auto-issuance | Fewer manual CSV uploads | M |
| Usability study with real employers; multi-core load tests | Evidence for the research paper | M |

## 8. Positioning in one table

| Question | Answer for CertiVault |
|----------|----------------------|
| Who do I have to trust? | The institution's key (pinned and published); not the server, if the verifier uses the offline check |
| What does the employer need? | The PDF, a link, an ID, or the credential file — and no account for the offline check / API |
| What does it cost? | Nothing; self-hosted on a PHP + MariaDB stack or Docker |
| What is not solved? | Interoperability (OB 3.0/VC), social sharing, legal status, server custody of keys |

## 9. References

1. Credly — Open Badge 3.0 product page: <https://info.credly.com/product/open-badge-3.0>
2. Credly blog, "Credly supports Open Badge 3.0" (16 Oct 2024): <https://learn.credly.com/blog/credly-supports-open-badge-3.0>
3. Pearson & Credly: <https://pearson.com/languages/en-sa/why-pearson/collaborations/credly.html>
4. ISC2 digital badges (Credly verify/LinkedIn flow): <https://isc2.org/certifications/digital-badges>
5. Certifier — compare page (free plan, OB 3.0 claim, verification QR, templates, integrations, SSO, ISO badges): <https://certifier.io/compare>
6. Geekflare, "Best digital credential platforms 2026" (third-party): <https://geekflare.com/guides/best-digital-credential-platforms/>
7. Accredible — OB 3.0 and W3C VC support (13 Jan 2026): <https://www.accredible.com/blog/now-supporting-open-badge-3-0-and-w3c-verifiable-credentials>
8. Accredible pricing (recipient-based plans, Launch from US$45/month, blockchain credentials, MFA/SSO): <https://www.accredible.com/pricing>
   · Accredible blog, "How does blockchain secure credentials": <https://www.accredible.com/blog/how-does-blockchain-secure-credentials>
9. Sertifier — homepage (Open Badges, optional blockchain validation, integrations, REST API/webhooks): <https://sertifier.com>
10. Blockcerts — About: <https://www.blockcerts.org/about> · Guide: <https://www.blockcerts.org/guide/>
11. Blockcerts `cert-issuer` (Merkle batching, MerkleProof2019, v3 / VC): <https://github.com/blockchain-certificates/cert-issuer>
12. 1EdTech Open Badges 3.0 specification: <https://www.imsglobal.org/spec/ob/v3p0> · certification guide: <https://www.imsglobal.org/spec/ob/v3p0/cert/>
13. W3C — VC 2.0 family is a Recommendation (2025): <https://www.w3.org/news/2025/the-verifiable-credentials-2-0-family-of-specifications-is-now-a-w3c-recommendation>
14. W3C — Bitstring Status List v1.0: <https://www.w3.org/TR/vc-status-list/>
15. Europass — stakeholder information on European Digital Credentials (seals): <https://europass.europa.eu/et/skateholders/european-digital-credentials/stakeholder-information-about-european-digital-credentials>
16. Europass — how to issue EDC: <https://europass.europa.eu/en/how-issue-european-digital-credentials-learning>
17. National Academic Depository — FAQ (CSV issuance, standard templates, consent, 24 h, free, legal recognition): <https://nad.digilocker.gov.in/faq>
18. National Academic Depository — Wikipedia: <https://en.wikipedia.org/wiki/National_Academic_Depository>
19. CertiVault internal: [01](01_PROJECT_OVERVIEW.md), [04](04_SECURITY_AND_CRYPTOGRAPHY.md), [05](05_FEATURES_AND_USER_GUIDE.md), [08](08_RESEARCH_SUMMARY.md) in this folder.

> **Caveat.** Vendor features change quickly and several sources are
> marketing or competitor pages. Before quoting this comparison externally,
> re-check rows marked ⚠️ against the vendor's current documentation.
