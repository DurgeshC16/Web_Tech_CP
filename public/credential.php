<?php
// public/credential.php — download a portable, self-verifying credential.
//   GET credential.php?token=<qr token>   or   ?certificate_id=<id>
// Returns application/json as an attachment (see CredentialService). Public
// like verify.php: it exposes only what the verify page already shows, plus
// the signature and the issuer's PUBLIC key. Rate-limited with the same
// pre-lookup gate and audit-logged.
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/CredentialService.php';

$db = Database::getInstance();
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$token = trim((string)($_GET['token'] ?? ''));
$certId = trim((string)($_GET['certificate_id'] ?? ''));

function credential_error(int $code, string $error, string $message): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: no-store');
    echo json_encode(['error' => $error, 'message' => $message]);
    exit;
}

if ($token === '' && $certId === '') {
    credential_error(400, 'missing_identifier', 'Pass ?token= or ?certificate_id=.');
}
$key = $token !== '' ? 'credential-token:' . $token : 'credential-id:' . mb_strtolower(mb_substr($certId, 0, 255));
$gate = VerificationService::checkAndRecordLookup($db, $ip, $key);
if ($gate['limited']) {
    header('Retry-After: ' . (VerificationService::VERIFY_RATE_WINDOW_MINUTES * 60));
    credential_error(429, 'rate_limited', 'Too many lookups. Wait a few minutes and try again.');
}

$cert = null;
if ($token !== '') {
    $cert = preg_match('/^[A-Za-z0-9_-]{43}$/', $token) ? VerificationService::findByToken($db, $token) : null;
} elseif (mb_strlen($certId) <= 64 && preg_match('/^[A-Za-z0-9\-_\/. ]+$/', $certId)) {
    $cert = VerificationService::findByFlexibleCertificateId($db, $certId);
}
$credential = $cert ? CredentialService::build($db, $cert) : null;

try {
    $db->prepare('INSERT INTO verification_logs (query_type, query_value, certificate_id_found, result, detail, verifier_ip)
                  VALUES (:qt, :qv, :cid, :res, :det, :ip)')
       ->execute([
           'qt' => $token !== '' ? 'token' : 'certificate_id',
           'qv' => mb_substr(log_safe_text($token !== '' ? $token : $certId), 0, 255),
           'cid' => $cert ? $cert['certificate_id'] : null,
           'res' => $credential ? $credential['status_at_export']['verdict'] : 'INVALID',
           'det' => 'credential export' . ($credential ? '' : ' (not found)'),
           'ip' => $ip,
       ]);
} catch (Throwable $e) {
    error_log('[CertiVault] credential export audit log failed: ' . get_class($e));
}

if ($credential === null) {
    credential_error(404, 'not_found', 'No exportable certificate matches this identifier.');
}

$name = preg_replace('/[^A-Za-z0-9._-]+/', '_', $credential['certificate']['certificate_id']);
header('Content-Type: application/json; charset=UTF-8');
header('Content-Disposition: attachment; filename="certivault-credential-' . $name . '.json"');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
echo json_encode($credential, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
