<?php
// src/services/CredentialService.php
// ─────────────────────────────────────────────────────────────────────
// Portable, self-verifying certificate credential (JSON).
//
// The export carries everything needed to re-check a certificate WITHOUT
// trusting CertiVault's verdict: the signed fields, the canonical digest,
// the RSA signature, and the issuer's public key + fingerprint. Anyone can
// verify it in a browser (public/offline_verify.php, Web Crypto) or with
// OpenSSL:
//
//   printf '%s' "$DIGEST" > digest.txt
//   base64 -d sig.b64 > sig.bin
//   openssl dgst -sha256 -verify issuer.pem -signature sig.bin digest.txt
//
// Trust in the KEY still has to come from somewhere independent of the
// file: compare proof.key_fingerprint_sha256 with the institution's
// published fingerprint (/.well-known/certivault-keys.json, institutions
// page, or an out-of-band pin export).
//
// Canonical digest (identical to CryptoService::computeCertificateHash):
//   SHA-256( certificate_id | institution_id | student_id | title |
//            issue_date | expiry_date-or-empty | SHA-256(file) )
// The signature is RSASSA-PKCS1-v1_5 / SHA-256 over the 64-char hex digest.
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/CryptoService.php';
require_once __DIR__ . '/VerificationService.php';

class CredentialService
{
    public const FORMAT = 'certivault-credential-v1';
    public const CANONICAL_FIELDS = ['certificate_id', 'institution_id', 'student_id', 'title', 'issue_date', 'expiry_date', 'file_sha256'];

    /**
     * Build the credential array for a certificate row as returned by
     * VerificationService::find*() (needs public_key, institution_name,
     * student_name). Returns null when the stored file is missing.
     */
    public static function build($db, array $cert): ?array
    {
        $path = __DIR__ . '/../../private_data/uploads/' . basename((string)$cert['file_path']);
        if (!is_file($path) || empty($cert['public_key']) || empty($cert['digital_signature'])) {
            return null;
        }
        $fileHash = hash_file('sha256', $path);
        $result = VerificationService::verify($db, $cert);
        $base = rtrim(BASE_URL, '/');

        return [
            'format' => self::FORMAT,
            'exported_at' => gmdate('c'),
            'issuer' => [
                'name' => (string)$cert['institution_name'],
                'institution_id' => (int)$cert['institution_id'],
                'key_id' => (int)($cert['key_id'] ?? 1),
            ],
            'subject' => [
                'name' => (string)$cert['student_name'],
                'student_id' => (int)$cert['student_id'],
            ],
            'certificate' => [
                'certificate_id' => (string)$cert['certificate_id'],
                'title' => (string)$cert['title'],
                'issue_date' => (string)$cert['issue_date'],
                'expiry_date' => $cert['expiry_date'] === null ? null : (string)$cert['expiry_date'],
                'version' => (int)($cert['version'] ?? 1),
                'file_sha256' => $fileHash,
            ],
            'status_at_export' => [
                'verdict' => $result['verdict'],
                'detail' => $result['detail'],
                'note' => 'Revocation can happen after export — check the live status before relying on this file.',
            ],
            'proof' => [
                'type' => 'RSASSA-PKCS1-v1_5-SHA256',
                'canonicalization' => 'SHA-256 of "|"-joined fields in canonical_fields order (expiry_date empty when null); the signature covers the 64-char lowercase hex digest as ASCII.',
                'canonical_fields' => self::CANONICAL_FIELDS,
                'digest_sha256' => (string)$cert['sha256_hash'],
                'signature_base64' => (string)$cert['digital_signature'],
                'public_key_pem' => trim((string)$cert['public_key']),
                'key_fingerprint_sha256' => CryptoService::fingerprintPublicKey((string)$cert['public_key']),
            ],
            'links' => [
                'verify' => $base . '/verify.php?certificate_id=' . rawurlencode((string)$cert['certificate_id']),
                'status_api' => $base . '/api_status.php?certificate_id=' . rawurlencode((string)$cert['certificate_id']),
                'key_directory' => $base . '/.well-known/certivault-keys.json',
                'offline_verifier' => $base . '/offline_verify.php',
            ],
        ];
    }

    /** The canonical string the digest is computed over. */
    public static function canonicalString(array $credential): string
    {
        $c = $credential['certificate'];
        return implode('|', [
            $c['certificate_id'],
            $credential['issuer']['institution_id'],
            $credential['subject']['student_id'],
            $c['title'],
            $c['issue_date'],
            $c['expiry_date'] ?? '',
            $c['file_sha256'],
        ]);
    }

    /**
     * Independent server-side re-check of a credential (used by tests and
     * by anyone embedding CertiVault). Never consults the database.
     * @return array{digest:bool, signature:bool, fingerprint:bool, valid:bool}
     */
    public static function verifyOffline(array $credential): array
    {
        $p = $credential['proof'] ?? [];
        $digest = hash('sha256', self::canonicalString($credential));
        $digestOk = hash_equals((string)($p['digest_sha256'] ?? ''), $digest);
        $sigOk = $digestOk && CryptoService::verifyCertificateSignature($digest, (string)($p['signature_base64'] ?? ''), (string)($p['public_key_pem'] ?? ''));
        $fpOk = !empty($p['public_key_pem'])
            && hash_equals((string)($p['key_fingerprint_sha256'] ?? ''), CryptoService::fingerprintPublicKey((string)$p['public_key_pem']));
        return ['digest' => $digestOk, 'signature' => $sigOk, 'fingerprint' => $fpOk, 'valid' => $digestOk && $sigOk && $fpOk];
    }
}
