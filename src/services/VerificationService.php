<?php
// src/services/VerificationService.php
// ─────────────────────────────────────────────────────────────────────
// Shared certificate verification pipeline:
//   existence → hash integrity → RSA signature → revoked/superseded →
//   expiry → VALID
// Used by public/verify.php and public/share.php so both pages always
// produce the same verdict for the same certificate.
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/CryptoService.php';

class VerificationService {

    /**
     * Fetch a certificate row (with institution name, public key, and
     * student name) by QR token, or null when not found.
     */
    public static function findByToken($db, $token) {
        return self::findOne($db, 'c.qr_token', $token);
    }

    /**
     * Fetch a certificate row by its public certificate_id, or null.
     */
    public static function findByCertificateId($db, $certificate_id) {
        return self::findOne($db, 'c.certificate_id', $certificate_id);
    }

    private static function findOne($db, $column, $value) {
        // Never interpolate anything but a fixed column name.
        $sql = '
            SELECT c.*, i.name AS institution_name, i.public_key,
                   s.full_name AS student_name
            FROM certificates c
            JOIN institutions i ON c.institution_id = i.id
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
     * Order matters: a certificate that is BOTH revoked and expired is
     * reported REVOKED; a certificate that is BOTH superseded and
     * expired is reported SUPERSEDED.
     *
     * @return array{verdict:string, detail:string, superseded_by:?array}
     */
    public static function verify($db, $cert) {
        // Step 1 – Integrity: recompute SHA-256 hash and compare
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

        // Step 2 – Authenticity: verify RSA signature
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

        // Step 3 – Revocation (before expiry: revoked wins)
        if ($cert['status'] === 'revoked') {
            return [
                'verdict' => 'REVOKED',
                'detail'  => 'This certificate has been revoked by the issuing institution.',
                'superseded_by' => null,
            ];
        }

        // Step 4 – Supersession (before expiry: superseded wins)
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

        // Step 5 – Expiry (explicit status, then the date)
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
