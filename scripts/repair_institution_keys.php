<?php
// scripts/repair_institution_keys.php <institution_id>
// CLI-only recovery rotation for ONE institution. Historical key versions
// remain in institution_keys and continue verifying old certificates.
//
// Safety:
// - Refuses if the current active key already decrypts and matches its public key.
// - Rotation preserves retired public keys; it never re-signs certificates.
// - Requires typed confirmation of the institution id before changing anything.

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die('This script must be run from the command line.');
}

if ($argc < 2) {
    fwrite(STDERR, "Usage: php scripts/repair_institution_keys.php <institution_id>\n");
    exit(1);
}

$institutionId = (int)$argv[1];

if (!getenv('OPENSSL_CONF')) {
    foreach (['C:\\xampp\\php\\extras\\openssl\\openssl.cnf', 'C:\\xampp\\php\\extras\\ssl\\openssl.cnf', 'C:\\xampp\\apache\\conf\\openssl.cnf'] as $candidate) {
        if (is_file($candidate)) { putenv('OPENSSL_CONF=' . $candidate); break; }
    }
}

require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/services/CryptoService.php';

$db = Database::getInstance();
$stmt = $db->prepare('SELECT id, name, status FROM institutions WHERE id = :id');
$stmt->execute(['id' => $institutionId]);
$inst = $stmt->fetch();

if (!$inst) {
    fwrite(STDERR, "Error: institution {$institutionId} not found.\n");
    exit(1);
}

$keyStmt=$db->prepare('SELECT key_id,public_key,encrypted_private_key FROM institution_keys WHERE institution_id=:iid AND status="active" ORDER BY key_id DESC LIMIT 1');
$keyStmt->execute(['iid'=>$institutionId]);
$currentKey=$keyStmt->fetch(PDO::FETCH_ASSOC);
$currentDecrypts = false;
$currentMatches = false;
try {
    $currentPrivate = CryptoService::decryptPrivateKey($currentKey['encrypted_private_key'] ?? '');
    $currentDecrypts = true;
    $currentMatches = !empty($currentKey['public_key']) && CryptoService::verifyKeyPair($currentPrivate, $currentKey['public_key']);
} catch (Exception $e) {
    $currentDecrypts = false;
    $currentMatches = false;
}

if ($currentDecrypts && $currentMatches) { fwrite(STDOUT,"Active key is healthy; use the dashboard Rotate key action for a planned rotation.\n"); exit(0); }

$countStmt = $db->prepare('SELECT COUNT(*) FROM certificates WHERE institution_id = :id');
$countStmt->execute(['id' => $institutionId]);
$certCount = (int)$countStmt->fetchColumn();

fwrite(STDOUT, "You are about to replace the signing key for institution id={$institutionId} name={$inst['name']} status={$inst['status']}.\n");
fwrite(STDOUT, "Certificates issued: {$certCount}. Previous key versions remain available for verification.\n");
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
    if ($currentKey) $db->prepare('UPDATE institution_keys SET status="retired",valid_to=NOW() WHERE institution_id=:iid AND key_id=:kid AND status="active"')->execute(['iid'=>$institutionId,'kid'=>(int)$currentKey['key_id']]);
    $max=$db->prepare('SELECT COALESCE(MAX(key_id),0)+1 FROM institution_keys WHERE institution_id=:iid'); $max->execute(['iid'=>$institutionId]); $keyId=(int)$max->fetchColumn();
    $upd = $db->prepare('INSERT INTO institution_keys (institution_id,key_id,public_key,encrypted_private_key,status,valid_from) VALUES (:iid,:kid,:pub,:priv,"active",NOW())');
    $upd->execute(['iid'=>$institutionId,'kid'=>$keyId,'pub' => $keys['public_key'], 'priv' => $encrypted]);
    $db->commit();
} catch (Exception $e) {
    if ($db->inTransaction()) { $db->rollBack(); }
    fwrite(STDERR, "Error: " . $e->getMessage() . "\n");
    exit(1);
}

fwrite(STDOUT, "Rotated institution {$institutionId} to key v{$keyId}: fingerprint=" . CryptoService::fingerprintPublicKey($keys['public_key']) . "\n");
fwrite(STDOUT, "Retired key remains available for existing certificates.\n");
exit(0);
