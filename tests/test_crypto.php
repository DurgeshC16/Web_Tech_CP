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

// ── Encrypt / decrypt round trip ──
$blob = CryptoService::encryptPrivateKey($keys['private_key']);
t_check('encrypt: GCM1 prefix', strpos($blob, 'GCM1.') === 0);
t_check('decrypt: round trip', CryptoService::decryptPrivateKey($blob) === $keys['private_key']);

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
