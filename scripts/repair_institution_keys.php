<?php
// scripts/repair_institution_keys.php <institution_id> [--force]
// CLI only. Generates a fresh key pair for ONE institution.
//
// Safety:
// - Refuses if the current key already decrypts and matches the stored public key.
// - Refuses if the institution has issued certificates unless --force is passed.
//   With --force, old certificates will fail re-verification because their signatures
//   were made with the previous public key.
// - Requires typed confirmation of the institution id before changing anything.

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die('This script must be run from the command line.');
}

if ($argc < 2) {
    fwrite(STDERR, "Usage: php scripts/repair_institution_keys.php <institution_id> [--force]\n");
    exit(1);
}

$institutionId = (int)$argv[1];
$force = in_array('--force', $argv, true);

if (!getenv('OPENSSL_CONF')) {
    foreach (['C:\\xampp\\php\\extras\\openssl\\openssl.cnf', 'C:\\xampp\\php\\extras\\ssl\\openssl.cnf', 'C:\\xampp\\apache\\conf\\openssl.cnf'] as $candidate) {
        if (is_file($candidate)) { putenv('OPENSSL_CONF=' . $candidate); break; }
    }
}

require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/services/CryptoService.php';

$db = Database::getInstance();
$stmt = $db->prepare('SELECT id, name, status, public_key, encrypted_private_key FROM institutions WHERE id = :id');
$stmt->execute(['id' => $institutionId]);
$inst = $stmt->fetch();

if (!$inst) {
    fwrite(STDERR, "Error: institution {$institutionId} not found.\n");
    exit(1);
}

$currentDecrypts = false;
$currentMatches = false;
try {
    $currentPrivate = CryptoService::decryptPrivateKey($inst['encrypted_private_key'] ?? '');
    $currentDecrypts = true;
    $currentMatches = !empty($inst['public_key']) && CryptoService::verifyKeyPair($currentPrivate, $inst['public_key']);
} catch (Exception $e) {
    $currentDecrypts = false;
    $currentMatches = false;
}

if ($currentDecrypts && $currentMatches) {
    fwrite(STDOUT, "Refused: institution {$institutionId} already has a decryptable, matching key pair.\n");
    exit(0);
}

$countStmt = $db->prepare('SELECT COUNT(*) FROM certificates WHERE institution_id = :id');
$countStmt->execute(['id' => $institutionId]);
$certCount = (int)$countStmt->fetchColumn();

if ($certCount > 0 && !$force) {
    fwrite(STDERR, "Refused: institution {$institutionId} has {$certCount} certificate(s). Re-running with --force will make old certificates fail verification because the public key changes.\n");
    exit(1);
}

fwrite(STDOUT, "You are about to replace the signing key for institution id={$institutionId} name={$inst['name']} status={$inst['status']}.\n");
fwrite(STDOUT, "Certificates issued: {$certCount}. --force: " . ($force ? 'yes' : 'no') . "\n");
fwrite(STDOUT, "Type the institution id to confirm: ");
$typed = trim((string)fgets(STDIN));
if ($typed !== (string)$institutionId) {
    fwrite(STDERR, "Aborted: confirmation did not match. No changes made.\n");
    exit(1);
}

try {
    $db->beginTransaction();
    $keys = CryptoService::generateRSAKeyPair();
    $encrypted = CryptoService::encryptPrivateKey($keys['private_key']);
    $roundTrip = CryptoService::decryptPrivateKey($encrypted);
    if (!CryptoService::verifyKeyPair($roundTrip, $keys['public_key'])) {
        throw new Exception('Generated key pair failed round-trip verification.');
    }
    $upd = $db->prepare('UPDATE institutions SET public_key = :pub, encrypted_private_key = :priv WHERE id = :id');
    $upd->execute(['pub' => $keys['public_key'], 'priv' => $encrypted, 'id' => $institutionId]);
    $db->commit();
} catch (Exception $e) {
    if ($db->inTransaction()) { $db->rollBack(); }
    fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
    exit(1);
}

fwrite(STDOUT, "Updated institution {$institutionId}: public_key length=" . strlen($keys['public_key']) . ", encrypted_private_key length=" . strlen($encrypted) . "\n");
fwrite(STDOUT, "Old public key invalidated for future signature checks on old certificates.\n");
exit(0);
