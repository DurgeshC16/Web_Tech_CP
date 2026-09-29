<?php
// src/services/CryptoService.php
require_once __DIR__ . '/../config/config.php';

class CryptoService {
    
    /**
     * Generate an RSA Key Pair
     */
    public static function generateRSAKeyPair() {
        $config = array(
            "digest_alg" => "sha256",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        
        $res = openssl_pkey_new($config);
        
        if (!$res) {
            throw new Exception("RSA key generation failed.");
        }
        
        openssl_pkey_export($res, $privKey);
        
        $pubKeyDetails = openssl_pkey_get_details($res);
        $pubKey = $pubKeyDetails["key"];
        
        return [
            'private_key' => $privKey,
            'public_key' => $pubKey
        ];
    }
    
    /**
     * Encrypt private key for storage at rest using AES-256-CBC.
     * NOTE: In production, the encryption key would come from a KMS, not a config constant.
     */
    public static function encryptPrivateKey($privateKey) {
        $key = substr(hash('sha256', APP_ENCRYPTION_KEY, true), 0, 32);
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $encrypted = openssl_encrypt($privateKey, 'aes-256-cbc', $key, 0, $iv);
        return base64_encode($iv . $encrypted);
    }
    
    /**
     * Decrypt private key for usage.
     */
    public static function decryptPrivateKey($encryptedData) {
        $key = substr(hash('sha256', APP_ENCRYPTION_KEY, true), 0, 32);
        $data = base64_decode($encryptedData);
        $ivLength = openssl_cipher_iv_length('aes-256-cbc');
        $iv = substr($data, 0, $ivLength);
        $encrypted = substr($data, $ivLength);
        return openssl_decrypt($encrypted, 'aes-256-cbc', $key, 0, $iv);
    }
    
    /**
     * Compute the canonical SHA-256 hash for a certificate.
     *
     * The canonical string is a pipe-delimited concatenation of the certificate's
     * immutable fields in a fixed order. This deterministic format means the exact
     * same hash can be recomputed later for verification — any field change will
     * produce a different hash, proving tampering.
     *
     * Fields: certificate_id | institution_id | student_id | title | issue_date | expiry_date | file_sha256
     *
     * @param array  $certData  Associative array with certificate fields
     * @param string $filePath  Absolute path to the uploaded certificate file
     * @return string           64-char lowercase hex SHA-256 hash
     */
    public static function computeCertificateHash($certData, $filePath) {
        $fileHash = hash_file('sha256', $filePath);
        
        $canonical = implode('|', [
            $certData['certificate_id'],
            $certData['institution_id'],
            $certData['student_id'],
            $certData['title'],
            $certData['issue_date'],
            $certData['expiry_date'] ?? '',
            $fileHash
        ]);
        
        return hash('sha256', $canonical);
    }
    
    /**
     * Sign a SHA-256 hash using the institution's RSA private key.
     *
     * @param string $hash       The 64-char hex hash to sign
     * @param string $privateKey PEM-encoded RSA private key (already decrypted)
     * @return string            Base64-encoded signature
     */
    public static function signCertificateHash($hash, $privateKey) {
        $success = openssl_sign($hash, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        if (!$success) {
            throw new Exception("RSA signing failed: " . openssl_error_string());
        }
        return base64_encode($signature);
    }
    
    /**
     * Verify a certificate's digital signature against the institution's public key.
     *
     * @param string $hash      The recomputed 64-char hex hash
     * @param string $signature Base64-encoded signature from the DB
     * @param string $publicKey PEM-encoded RSA public key
     * @return bool             True if the signature is valid
     */
    public static function verifyCertificateSignature($hash, $signature, $publicKey) {
        $binarySignature = base64_decode($signature);
        $result = openssl_verify($hash, $binarySignature, $publicKey, OPENSSL_ALGO_SHA256);
        return $result === 1;
    }
}
