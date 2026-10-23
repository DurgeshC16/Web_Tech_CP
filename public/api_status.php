<?php
// public/api_status.php
// ─────────────────────────────────────────────────────────────────────
// Phase 3 — PUBLIC read-only JSON status endpoint (transparency).
// Usage: GET api_status.php?certificate_id=CV-2026-1 (or ?id=…)
// No outbound requests. Feature-gated by API_ENABLED (default ON; set
// CV_API_ENABLED=0 to disable an installation's endpoint). Emits JSON
// with no-store; every request is audit-logged (result mapped into the
// verification_logs ENUM).
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/config/config.php';
require_once __DIR__ . '/../src/services/StatusApiService.php';
require_once __DIR__ . '/../src/utils/helpers.php';

header('Content-Type: application/json; charset=UTF-8');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');

if (!API_ENABLED) {
    http_response_code(403);
    echo json_encode(['error' => 'api_disabled', 'message' => 'The public status API is disabled on this CertiVault installation.']);
    exit;
}

$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
try {
    $db = Database::getInstance();
} catch (Throwable $dbError) {
    error_log('[CertiVault] Status API DB connect failed: ' . $dbError->getMessage());
    http_response_code(503);
    echo json_encode(['error' => 'unavailable', 'message' => 'Verification service temporarily unavailable.']);
    exit;
}

$idInput = (string)($_GET['certificate_id'] ?? $_GET['id'] ?? '');
[$httpStatus, $payload] = StatusApiService::resolve($db, $idInput, $ip);

// Audit-log every hit EXCEPT rate-limit rejections (their lookups are
// suppressed, mirroring verify.php).
if ($httpStatus !== 429) {
    $result = in_array(($payload['verdict'] ?? ''), ['VALID', 'TAMPERED', 'EXPIRED', 'REVOKED', 'SUPERSEDED'], true)
        ? $payload['verdict']
        : 'INVALID'; // NOT_FOUND / errors map to INVALID in the ENUM
    StatusApiService::logRequest(
        $db,
        $idInput,
        $payload['certificate']['certificate_id'] ?? null,
        $result,
        $httpStatus,
        $ip
    );
}

http_response_code($httpStatus);
echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
exit;
