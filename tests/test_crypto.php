<?php
// tests/test_crypto.php — RSA key generation, AES-256-GCM private-key
// round trip, RSA sign + verify, and a failing verify after flipping
// one byte of the signed hash.
// Run: php tests/test_crypto.php
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/services/CryptoService.php';

// ── Key generation ──
$keys = CryptoService::generateRSAKeyPair();
t_check('keygen: private PEM', strpos($keys['private_key'], '-----BEGIN') === 0);
t_check('keygen: public PEM', strpos($keys['public_key'], '-----BEGIN') === 0);
t_check('keygen: pair matches', CryptoService::verifyKeyPair($keys['private_key'], $keys['public_key']));
$fingerprint = CryptoService::fingerprintPublicKey($keys['public_key']);
t_check('key fingerprint: 32 colon-separated SHA-256 bytes', strlen($fingerprint) === 95
    && preg_match('/^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/', $fingerprint) === 1);

// ── Encrypt / decrypt round trip ──
$blob = CryptoService::encryptPrivateKey($keys['private_key']);
t_check('encrypt: GCM1 prefix', strpos($blob, 'GCM1.') === 0);
t_check('decrypt: round trip', CryptoService::decryptPrivateKey($blob) === $keys['private_key']);
$configBlob = CryptoService::encryptConfig('{"api_token":"sensitive-test-value"}');
t_check('config encryption: CFG1 authenticated round trip', str_starts_with($configBlob, 'CFG1.')
    && CryptoService::decryptConfig($configBlob) === '{"api_token":"sensitive-test-value"}');
$tamperedConfig = $configBlob;
$tamperedConfig[strlen($tamperedConfig) - 2] = $tamperedConfig[strlen($tamperedConfig) - 2] === 'A' ? 'B' : 'A';
try {
    CryptoService::decryptConfig($tamperedConfig);
    t_check('config encryption: tamper rejected', false);
} catch (Exception $e) {
    t_check('config encryption: tamper rejected', true);
}

// ── Sign + verify ──
$hash = hash('sha256', 'certivault-test-payload');
$sig = CryptoService::signCertificateHash($hash, $keys['private_key']);
t_check('sign/verify: valid signature', CryptoService::verifyCertificateSignature($hash, $sig, $keys['public_key']));

// ── Tampered hash must fail verification ──
$bad = $hash;
$bad[0] = ($bad[0] === 'a' ? 'b' : 'a'); // flip exactly one hex digit
t_check('sign/verify: 1-byte hash change fails', !CryptoService::verifyCertificateSignature($bad, $sig, $keys['public_key']));

// ── Wrong key must fail verification ──
$other = CryptoService::generateRSAKeyPair();
t_check('sign/verify: wrong public key fails', !CryptoService::verifyCertificateSignature($hash, $sig, $other['public_key']));

exit(t_summary('test_crypto') ? 0 : 1);
