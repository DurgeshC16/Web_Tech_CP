<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
if (!CERTIFICATE_TRANSPARENCY_ENABLED) { http_response_code(404); header('Content-Type: application/json'); echo json_encode(['error'=>'key_directory_disabled']); exit; }
header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
try {
    $db=Database::getInstance();
    $stmt=$db->query("SELECT i.name AS institution,k.key_id,k.public_key,k.status,k.valid_from,k.valid_to
        FROM institutions i JOIN institution_keys k ON k.institution_id=i.id
        WHERE i.status='approved' ORDER BY i.name,k.key_id");
    $keys=[];
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $keys[]=[
            'institution'=>$row['institution'],'key_id'=>(int)$row['key_id'],'status'=>$row['status'],
            'public_key'=>$row['public_key'],'fingerprint_sha256'=>CryptoService::fingerprintPublicKey((string)$row['public_key']),
            'valid_from'=>$row['valid_from'],'valid_to'=>$row['valid_to'],
        ];
    }
    echo json_encode(['format'=>'certivault-institution-keys-v1','generated_at'=>date('c'),'keys'=>$keys],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    error_log('[CertiVault] Well-known keys endpoint unavailable: '.$e->getMessage());
    http_response_code(503);
    echo json_encode(['error'=>'keys_unavailable']);
}
