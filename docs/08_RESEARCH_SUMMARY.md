# 08 — Research Summary

CertiVault is accompanied by an IEEE-style research paper, *"CertiVault: A
Signature-Anchored Web Platform for Tamper-Evident Certificate Issuance and
Six-Verdict Public Verification."* The draft is kept out of the public
repository until it is published; this page summarises its content.

## 1. Positioning

Most recent work on certificate verification (15 studies, 2022–2026,
reviewed in the paper) uses blockchain. That removes the central registry
but brings per-transaction fees (≈120 000 gas to issue on Polygon), write
latency (seconds on permissioned chains), device-dependent read latency, and
— as a published forgery attack shows — no guarantee that a ledger identity
belongs to a real institution. CertiVault takes the opposite design point: an
institution-operated web platform using only conventional cryptography, with
issuer keys created **after** super-admin approval.

## 2. Research questions

| RQ | Question | Answer |
|----|----------|--------|
| RQ1 Authenticity | Does the design detect every alteration of signed data and order statuses correctly? | Yes for all tested classes except a key-table swap; precedence matched an oracle in 16/16 cases |
| RQ2 Importance | What does each component contribute? | Each component stops a distinct attacker class (see ablation) |
| RQ3 Cost & scale | How do latency/throughput change with file size, table size, concurrency? | File hashing and rate-limiter state dominate; lookups stay flat to 100 000 rows |
| RQ4 Trust gap | Can the single-operator trust gap be narrowed cheaply? | Key pinning (0.047 ms) and Merkle anchoring (≤ 640 B proofs) — only if their storage is outside the app |

## 3. Key results

### Correctness

* 15/15 targeted modifications (title, dates, ID, student, institution, file
  bit-flip, file replace/delete, copied/foreign/random/removed signature) →
  **TAMPERED**.
* Swapping the institution's public key **and** re-signing → accepted as
  VALID (the known limit); with fingerprint pinning → rejected.
* 3 500 random edits (2 000 file bit-flips + 1 500 field edits) all detected
  — 95% upper bound on miss rate 0.086%.
* 300/300 bit-flips of the wrapped private key rejected by AES-GCM.
* 100 signatures independently verified (OpenSSL CLI + Python).

### Component ablation (30 trials per cell)

| Attack | File digest | Canonical digest | **Signed (CertiVault)** | Signed + pinning |
|--------|:-:|:-:|:-:|:-:|
| S1 File bit flipped | ✔ | ✔ | ✔ | ✔ |
| S2 Title edited (DB) | ✘ | ✔ | ✔ | ✔ |
| S3 Title edited + digest recomputed | ✘ | ✘ | ✔ | ✔ |
| S4 File edited + digest recomputed | ✘ | ✘ | ✔ | ✔ |
| S5 …re-signed with attacker key | ✘ | ✘ | ✔ | ✔ |
| S6 …plus issuer public key replaced | ✘ | ✘ | ✘ | ✔ |

### Performance (single vCPU, PHP 8.3, nginx + PHP-FPM)

| Operation | Mean |
|-----------|------|
| RSA-2048 sign / verify | 1.09 ms / 0.35 ms |
| Verification service, 6 KB / 1 MB / 5 MB file | 0.55 / 5.43 / 23.1 ms |
| `verify.php` over HTTP (valid) | 3.04 ms |
| Lookup at 1 000 → 100 000 rows | 0.81 → 0.80 ms (flat; 1.81 ms at 10⁶ rows when the table outgrows the buffer pool) |
| Throughput, 16 clients | ≈ 399 req/s with the redesigned limiter |
| Merkle proof at 10⁶ records | build 787 ms, verify 18.6 µs, 640 bytes |

**Rate-limiter finding:** counting distinct lookups over the whole
`verification_logs` history made the check grow from 3.8 ms to 54.7 ms at
30 000 logged rows (an algorithmic-complexity weakness). The paper's patch
keeps limiter state in a small dedicated table (≤ 31 rows per address),
holding latency at ≈ 3.4 ms. The patch is now in the repository
(migration 014, `VerificationService::checkAndRecordLookup()`).

## 4. Limitations stated in the paper

* Single operator: no server → no verification; a DB writer can swap keys.
* A signature proves *who* issued, not that the content is true.
* CSP still allows inline scripts/styles.
* Synthetic data; one shared CPU; MariaDB instead of MySQL; no network
  latency — absolute numbers will differ, trends should hold.

## 5. Future work (from the paper)

Pinning and anchoring stored outside the application; an append-only
revocation log; trusted timestamping; multi-core production load tests;
usability testing with employers.

## 6. Keeping the paper and the code consistent

The paper describes an earlier snapshot. Numbers that have changed since:

| Paper says | Repository now |
|-----------|----------------|
| 8 database tables | 15 tables |
| 78 automated tests | 512 PHP checks in 16 suites + 78 browser checks, run in CI |
| Key pinning / Merkle anchoring are in-memory prototypes | Both implemented: Merkle transparency log (opt-in) and key pinning in an append-only file outside the DB (`KeyPinService`, on by default) — S6 now verifies as TAMPERED (`test_key_pinning.php`) |
| CSP permits inline scripts | Scripts are external only (`script-src 'self'`, `script-src-attr 'none'`); `style-src` has no `'unsafe-inline'` (all styles in external CSS) |
| Verification via the server only | Portable signed credentials can be verified in the browser (Web Crypto) or with OpenSSL |
| Redesigned rate limiter (`verify_rate`) | Implemented (migration 014): ≤ 30 rows per IP, checked before any lookup; 0.65 ms vs 22.8 ms for the old query at 30 000 logged rows (XAMPP, Windows) |
