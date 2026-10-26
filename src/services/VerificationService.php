<?php
// src/services/VerificationService.php
// ─────────────────────────────────────────────────────────────────────
// Shared certificate verification pipeline:
//   existence → revoked/superseded → hash integrity → RSA signature →
//   expiry → VALID
// Status is checked first because it is server-authoritative (it lives in
// the database, not in the file): a revoked certificate reports REVOKED
// even if its file was also altered, and likewise for SUPERSEDED.
// Used by public/verify.php and public/share.php so both pages always
// produce the same verdict for the same certificate.
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/CryptoService.php';

class VerificationService {

    // ── Public verification rate limiting (per IP) ──────────────────────
    // At most VERIFY_RATE_MAX *distinct* lookups are allowed from one IP
    // within VERIFY_RATE_WINDOW_MINUTES. The next distinct lookup in the
    // window is rejected (HTTP 429). Repeated lookups of the same value
    // cost nothing, so a legitimate reload/refresh never trips the limit.
    const VERIFY_RATE_MAX = 30;
    const VERIFY_RATE_WINDOW_MINUTES = 10;
    // Distinct lookups past this count in the window are logged as a
    // possible enumeration attempt (warning only, never blocks).
    const VERIFY_ENUM_WARN = 20;

    /**
     * Count the distinct query values this IP has looked up inside the
     * current window. Must be called BEFORE the current lookup is logged
     * so the boundary is "already-seen count".
     */
    public static function recentLookupCount($db, $ip) {
        // VERIFY_RATE_WINDOW_MINUTES is an int class constant (never user
        // input), so inlining it here is injection-safe.
        $stmt = $db->prepare(
            'SELECT COUNT(DISTINCT query_value) FROM verification_logs
             WHERE verifier_ip = :ip
               AND verified_at > DATE_SUB(NOW(), INTERVAL ' . (int)self::VERIFY_RATE_WINDOW_MINUTES . ' MINUTE)'
        );
        $stmt->execute(['ip' => $ip]);
        return (int)$stmt->fetchColumn();
    }

    /**
     * True when this IP has already made VERIFY_RATE_MAX distinct lookups
     * in the window, i.e. the request about to be served is over the limit.
     */
    public static function isRateLimited($db, $ip) {
        return self::recentLookupCount($db, $ip) >= self::VERIFY_RATE_MAX;
    }

    /**
     * Fetch a certificate row (with institution name, public key, and
     * student name) by QR token, or null when not found.
     */
    public static function findByToken($db, $token) {
        return self::findOne($db, 'c.qr_token', $token);
    }

    /**
     * Fetch a certificate row by its public certificate_id, or null when not found.
     */
    public static function findByCertificateId($db, $certificate_id) {
        return self::findOne($db, 'c.certificate_id', $certificate_id);
    }

    /**
     * Compact form used for the last-chance lookup: strip every space,
     * dash, slash and dot, lowercase — both sides. E.g. "bsc/cs/2026/044",
     * "BSC CS 2026 044" and "bsc.cs.2026.044" all compact to
     * "bsccs2026044" and therefore match the same stored ID.
     *
     * @param  string $input Any user-typed certificate id.
     * @return string        Compact representation.
     */
    private static function compactId($input) {
        return strtolower(preg_replace('/[\s\-\/.]+/', '', (string)$input));
    }

    /**
     * Lenient lookup for human-typed IDs, tried in layers:
     *   1. exact match, case-insensitive, trimmed (covers a stored ID typed
     *      back verbatim in any casing);
     *   2. normalize_certificate_id() — "cv-2026-1" / "cv 2026 1" resolve to
     *      the canonical CV-YYYY-NNNNNN form;
     *   3. "compact" match: separators and case ignored on BOTH sides, so
     *      any spacing/punctuation variant of a custom ID still resolves.
     * Returns null (no DB hit) for empty/overlong input, and null when no
     * layer matches — callers render that as INVALID. Always prepared
     * statements; the compact layer is computed with LOWER()/REPLACE() on
     * a short varchar column (≤64 chars) instead of a migration so it
     * stays portable; the certificate table size keeps this cheap.
     */
    public static function findByFlexibleCertificateId($db, $input) {
        $raw = trim((string)$input);
        if ($raw === '' || strlen($raw) > 64) {
            return null;
        }

        // Layer 1: exact match, case-insensitive.
        $sql = '
            SELECT c.*, i.name AS institution_name, ik.public_key, ik.status AS signing_key_status,
                   s.full_name AS student_name
            FROM certificates c
            JOIN institutions i ON c.institution_id = i.id
            LEFT JOIN institution_keys ik ON ik.institution_id = c.institution_id AND ik.key_id = c.key_id
            JOIN students     s ON c.student_id     = s.id
            WHERE LOWER(c.certificate_id) = LOWER(:val)
            LIMIT 1
        ';
        $stmt = $db->prepare($sql);
        $stmt->execute(['val' => $raw]);
        $cert = $stmt->fetch();
        if ($cert) {
            return $cert;
        }

        // Layer 2: canonical CV-YYYY-NNNNNN normalization.
        $norm = function_exists('normalize_certificate_id')
            ? normalize_certificate_id($raw)
            : null;
        if ($norm !== null && strcasecmp($norm, $raw) !== 0) {
            $sql = '
                SELECT c.*, i.name AS institution_name, ik.public_key, ik.status AS signing_key_status,
                       s.full_name AS student_name
                FROM certificates c
                JOIN institutions i ON c.institution_id = i.id
                LEFT JOIN institution_keys ik ON ik.institution_id = c.institution_id AND ik.key_id = c.key_id
                JOIN students     s ON c.student_id     = s.id
                WHERE c.certificate_id = :norm
                LIMIT 1
            ';
            $stmt = $db->prepare($sql);
            $stmt->execute(['norm' => $norm]);
            $cert = $stmt->fetch();
            if ($cert) {
                return $cert;
            }
        }

        // Layer 3: compact match — separators and case ignored both sides.
        $compact = self::compactId($raw);
        if ($compact === '') {
            return null;
        }
        $sql = '
            SELECT c.*, i.name AS institution_name, ik.public_key, ik.status AS signing_key_status,
                   s.full_name AS student_name
            FROM certificates c
            JOIN institutions i ON c.institution_id = i.id
            LEFT JOIN institution_keys ik ON ik.institution_id = c.institution_id AND ik.key_id = c.key_id
            JOIN students     s ON c.student_id     = s.id
            WHERE LOWER(REPLACE(REPLACE(REPLACE(REPLACE(c.certificate_id, " ", ""), "-", ""), "/", ""), ".", "")) = :compact
            LIMIT 1
        ';
        $stmt = $db->prepare($sql);
        $stmt->execute(['compact' => $compact]);
        $cert = $stmt->fetch();
        return $cert ?: null;
    }

    private static function findOne($db, $column, $value) {
        // Never interpolate anything but a fixed column name.
        $sql = '
            SELECT c.*, i.name AS institution_name, ik.public_key, ik.status AS signing_key_status,
                   s.full_name AS student_name
            FROM certificates c
            JOIN institutions i ON c.institution_id = i.id
            LEFT JOIN institution_keys ik ON ik.institution_id = c.institution_id AND ik.key_id = c.key_id
            JOIN students     s ON c.student_id     = s.id
            WHERE ' . $column . ' = :val
            LIMIT 1
        ';
        $stmt = $db->prepare($sql);
        $stmt->execute(['val' => $value]);
        return $stmt->fetch();
    }

    /**
     * Run the verification cascade on an already-fetched row.
     *
     * Order matters: revoked/superseded are server-side status, so they
     * are evaluated before file integrity — a revoked certificate reports
     * REVOKED (not TAMPERED) even if its file was altered afterwards, and
     * a superseded one reports SUPERSEDED. After that, integrity and
     * signature failures report TAMPERED, then expiry, then VALID.
     *
     * @return array{verdict:string, detail:string, superseded_by:?array}
     */
    public static function verify($db, $cert) {
        // Step 1 – Revocation (server-authoritative: wins over everything
        // below, including tampering and expiry)
        if ($cert['status'] === 'revoked') {
            return [
                'verdict' => 'REVOKED',
                'detail'  => 'This certificate has been revoked by the issuing institution.',
                'superseded_by' => null,
            ];
        }

        // Step 2 – Supersession (server-authoritative, same reason)
        if ($cert['status'] === 'superseded') {
            $superseded_by = null;
            if (!empty($cert['superseded_by_id'])) {
                $sbStmt = $db->prepare('SELECT certificate_id, qr_token FROM certificates WHERE id = :id');
                $sbStmt->execute(['id' => $cert['superseded_by_id']]);
                $superseded_by = $sbStmt->fetch() ?: null;
            }
            return [
                'verdict' => 'SUPERSEDED',
                'detail'  => 'This certificate has been superseded by a newer corrected version.',
                'superseded_by' => $superseded_by,
            ];
        }

        // Step 3 – Integrity: recompute SHA-256 hash and compare
        $filePath = __DIR__ . '/../../private_data/uploads/' . $cert['file_path'];
        $hashOK   = false;

        if (file_exists($filePath) && !empty($cert['sha256_hash'])) {
            $certData = [
                'certificate_id' => $cert['certificate_id'],
                'institution_id' => $cert['institution_id'],
                'student_id'     => $cert['student_id'],
                'title'          => $cert['title'],
                'issue_date'     => $cert['issue_date'],
                'expiry_date'    => $cert['expiry_date'],
            ];
            $recomputedHash = CryptoService::computeCertificateHash($certData, $filePath);
            $hashOK = hash_equals($cert['sha256_hash'], $recomputedHash);
        }

        if (!$hashOK) {
            return [
                'verdict' => 'TAMPERED',
                'detail'  => 'Data integrity check failed — the certificate data or file has been altered since issuance.',
                'superseded_by' => null,
            ];
        }

        // Step 4 – Authenticity: verify RSA signature
        $sigOK = false;
        if (!empty($cert['digital_signature']) && !empty($cert['public_key'])) {
            $sigOK = CryptoService::verifyCertificateSignature(
                $recomputedHash,
                $cert['digital_signature'],
                $cert['public_key']
            );
        }

        if (!$sigOK) {
            return [
                'verdict' => 'TAMPERED',
                'detail'  => 'Digital signature verification failed — the certificate may be forged or the issuing institution\'s key does not match.',
                'superseded_by' => null,
            ];
        }

        // Step 5 – Expiry: explicit status first, then the date.
        // (Revoked/superseded win over expired by construction.)
        if (($cert['status'] ?? '') === 'expired') {
            return [
                'verdict' => 'EXPIRED',
                'detail'  => 'This certificate has been marked as expired.',
                'superseded_by' => null,
            ];
        }
        if (!empty($cert['expiry_date']) && strtotime($cert['expiry_date']) < strtotime('today')) {
            return [
                'verdict' => 'EXPIRED',
                'detail'  => 'This certificate expired on ' . date('F j, Y', strtotime($cert['expiry_date'])) . '.',
                'superseded_by' => null,
            ];
        }

        // Step 6 – All checks passed
        return [
            'verdict' => 'VALID',
            'detail'  => 'All integrity, authenticity, expiry, and status checks passed.',
            'superseded_by' => null,
        ];
    }

    /**
     * Effective status for display: an 'active' certificate whose
     * expiry_date is in the past must be presented as 'expired' so
     * lists and detail pages never overstate its validity.
     */
    public static function effectiveStatus($cert) {
        if (($cert['status'] ?? '') === 'active' && !empty($cert['expiry_date']) && strtotime($cert['expiry_date']) < strtotime('today')) {
            return 'expired';
        }
        return $cert['status'];
    }
}
