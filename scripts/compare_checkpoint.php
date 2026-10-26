<?php
if (PHP_SAPI !== 'cli') { http_response_code(403); exit("CLI only.\n"); }
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
if (!CERTIFICATE_TRANSPARENCY_ENABLED) { fwrite(STDERR, "Enable CERTIFICATE_TRANSPARENCY_ENABLED in local config first.\n"); exit(1); }

$externalPath = $argv[1] ?? '';
if ($externalPath === '' || !is_file($externalPath)) {
    fwrite(STDERR, "Usage: php scripts/compare_checkpoint.php path-to-out-of-band-checkpoint.json\n");
    exit(2);
}
$localPath = __DIR__ . '/../public/checkpoints/latest.json';
if (!is_file($localPath) || !is_file(TLOG_PUBLIC_KEY_FILE)) {
    fwrite(STDERR, "Local latest checkpoint or trusted platform public key is missing.\n"); exit(2);
}
$local = json_decode((string)file_get_contents($localPath), true);
$external = json_decode((string)file_get_contents($externalPath), true);
$pub = (string)file_get_contents(TLOG_PUBLIC_KEY_FILE);
if (!is_array($local) || !is_array($external)) { fwrite(STDERR, "Checkpoint JSON is invalid.\n"); exit(2); }
$fingerprint = CryptoService::fingerprintPublicKey($pub);
$validLocal = hash_equals($fingerprint, (string)($local['public_key_fingerprint'] ?? ''))
    && CryptoService::verifyCertificateSignature((string)($local['root_hash'] ?? ''), (string)($local['signature'] ?? ''), $pub);
$validExternal = hash_equals($fingerprint, (string)($external['public_key_fingerprint'] ?? ''))
    && CryptoService::verifyCertificateSignature((string)($external['root_hash'] ?? ''), (string)($external['signature'] ?? ''), $pub);
$same = (string)($local['root_hash'] ?? '') === (string)($external['root_hash'] ?? '')
    && (int)($local['tree_size'] ?? -1) === (int)($external['tree_size'] ?? -2);
if (!$validLocal || !$validExternal || !$same) {
    fwrite(STDERR, "MISMATCH: local and out-of-band checkpoints do not reconcile (or signature invalid).\n"); exit(1);
}
echo "MATCH: signed root {$local['root_hash']} at tree size {$local['tree_size']}\n";
