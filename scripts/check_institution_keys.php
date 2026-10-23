<?php
// scripts/check_institution_keys.php
// Read-only audit: prints lengths/booleans only, never key material.

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    die('This script must be run from the command line.');
}

if (!getenv('OPENSSL_CONF')) {
    foreach (['C:\\xampp\\php\\extras\\openssl\\openssl.cnf', 'C:\\xampp\\php\\extras\\ssl\\openssl.cnf', 'C:\\xampp\\apache\\conf\\openssl.cnf'] as $candidate) {
        if (is_file($candidate)) { putenv('OPENSSL_CONF=' . $candidate); break; }
    }
}

require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/services/CryptoService.php';

$db = Database::getInstance();
$stmt = $db->query('SELECT id, name, status, public_key, encrypted_private_key FROM institutions ORDER BY id');
$rows = $stmt->fetchAll();

if (!$rows) {
    echo "No institutions found.\n";
    exit(0);
}

foreach ($rows as $row) {
    $hasPublic = is_string($row['public_key']) && trim($row['public_key']) !== '';
    $hasEncrypted = is_string($row['encrypted_private_key']) && trim($row['encrypted_private_key']) !== '';
    $decrypts = false;
    $matches = false;

    if ($hasEncrypted) {
        try {
            $privatePem = CryptoService::decryptPrivateKey($row['encrypted_private_key']);
            $decrypts = true;
            if ($hasPublic) {
                $matches = CryptoService::verifyKeyPair($privatePem, $row['public_key']);
            }
        } catch (Exception $e) {
            $decrypts = false;
            $matches = false;
        }
    }

    $countStmt = $db->prepare('SELECT COUNT(*) FROM certificates WHERE institution_id = :id');
    $countStmt->execute(['id' => $row['id']]);
    $certCount = (int)$countStmt->fetchColumn();

    echo "id={$row['id']} name=" . str_replace("\n", ' ', $row['name']) . " status={$row['status']}\n";
    echo "  public_key_present=" . ($hasPublic ? 'true' : 'false') . " length=" . ($hasPublic ? strlen($row['public_key']) : 0) . "\n";
    echo "  encrypted_private_key_present=" . ($hasEncrypted ? 'true' : 'false') . " length=" . ($hasEncrypted ? strlen($row['encrypted_private_key']) : 0) . "\n";
    echo "  private_key_decrypts=" . ($decrypts ? 'true' : 'false') . "\n";
    echo "  private_key_matches_public=" . ($matches ? 'true' : 'false') . "\n";
    echo "  certificates_issued={$certCount}\n";
    echo "\n";
}

exit(0);
