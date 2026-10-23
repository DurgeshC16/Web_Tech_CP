<?php
// src/services/StatusApiService.php
// ─────────────────────────────────────────────────────────────────────
// Phase 3 — PUBLIC read-only verification status API (transparency).
// Testable core: builds the JSON payload without touching TCP so
// public/api_status.php stays a thin HTTP wrapper.
//
// Contains ONLY public verification facts (verdict, detail, trust score
// breakdown, public certificate fields) — NO tokens, NO keys, NO file
// paths. Every hit is audit-logged with an 'API status' marker; the
// rate limit reuses verification_logs (mirrors verify.php).
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/VerificationService.php';
require_once __DIR__ . '/TrustScoreService.php';

class StatusApiService
{
    public const RATE_LIMIT = 30; // requests per IP per 10 minutes

    /**
     * @param string $idInput raw, user-supplied certificate id
     * @param string $ip      remote address (from the HTTP wrapper)
     * @return array{0:int,1:array} [httpStatus, payloadArray]
     */
    public static function resolve($db, string $idInput, string $ip): array
    {
        $meta = ['api' => 'certivault-status', 'generated_at' => date('c')];

        // Rate limit FIRST — an abuser gets nothing from the engine.
        if (self::rateLimited($db, $ip)) {
            error_log("[CertiVault] Rate limit exceeded for IP $ip on the status API — returned 429.");
            return [429, $meta + ['error' => 'rate_limited', 'message' => 'Too many requests. Wait a few minutes and try again.']];
        }

        $id = trim($idInput);

        // Malformed / missing input → NOT_FOUND (never a server error).
        if ($id === '' || mb_strlen($id) > 64
            || !preg_match('/^[A-Za-z0-9\-_\/. ]+$/', $id)) {
            return [404, $meta + ['verdict' => 'NOT_FOUND', 'detail' => 'No certificate found for the provided identifier.']];
        }

        try {
            $cert = VerificationService::findByFlexibleCertificateId($db, $id);
        } catch (Throwable $dbError) {
            error_log("[CertiVault] Status API lookup failed: " . $dbError->getMessage());
            return [500, $meta + ['error' => 'unavailable', 'message' => 'Verification service temporarily unavailable.']];
        }

        if (!$cert) {
            return [404, $meta + ['verdict' => 'NOT_FOUND', 'detail' => 'No certificate found for the provided identifier.']];
        }

        // Verdict from THE canonical engine — the API never decides alone.
        $result  = VerificationService::verify($db, $cert);
        $trusted = TrustScoreService::compute($db, $cert);

        $payload = $meta + [
            'verdict' => $result['verdict'],
            'detail'  => $result['detail'],
            'certificate' => [
                'certificate_id' => $cert['certificate_id'],
                'title'          => $cert['title'],
                'awarded_to'     => $cert['student_name'] ?? '',
                'issued_by'      => $cert['institution_name'] ?? '',
                'issue_date'     => $cert['issue_date'],
                'status'         => $cert['status'],
            ],
            'trust_score' => [
                'score'   => $trusted['score'],
                'checks'  => array_map(
                    fn($c) => [
                        'label'  => $c['label'],
                        'pass'   => (bool)$c['pass'],
                        'points' => $c['pass'] ? (int)$c['points'] : 0,
                        'of'     => (int)$c['points'],
                    ],
                    $trusted['checks']
                ),
                'disclaimer' => TrustScoreService::DISCLAIMER,
            ],
        ];
        if (is_array($result['superseded_by'] ?? null)) {
            $payload['superseded_by'] = $result['superseded_by']['certificate_id'] ?? null;
        }

        return [200, $payload];
    }

    private static function rateLimited($db, string $ip): bool
    {
        $stmt = $db->prepare('
            SELECT COUNT(*) FROM verification_logs
            WHERE verifier_ip = :ip
              AND verified_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
        ');
        $stmt->execute(['ip' => $ip]);
        return (int)$stmt->fetchColumn() > self::RATE_LIMIT;
    }

    /**
     * Audit-log ONE api status request. $result must be a verification_logs
     * ENUM value (NOT_FOUND / 429 / 5xx map to INVALID by the caller).
     */
    public static function logRequest($db, string $queryValue, ?string $certId, string $result, int $httpStatus, string $ip): void
    {
        try {
            $stmt = $db->prepare('
                INSERT INTO verification_logs
                    (query_type, query_value, certificate_id_found, result, detail, verifier_ip)
                VALUES
                    ("certificate_id", :qv, :cid, :res, :det, :ip)
            ');
            $stmt->execute([
                'qv'  => mb_substr(log_safe_text($queryValue !== '' ? $queryValue : '(api empty)'), 0, 255),
                'cid' => $certId,
                'res' => $result,
                'det' => mb_substr(log_safe_text('API status request (HTTP ' . $httpStatus . ')'), 0, 255),
                'ip'  => $ip,
            ]);
        } catch (Throwable $logError) {
            error_log("[CertiVault] Status API audit log failed: " . $logError->getMessage());
            // ENUM not widened (old installs) — retry with historical type.
            try {
                $stmt->execute([
                    'qv'  => mb_substr(log_safe_text('[' . $httpStatus . '] ' . $queryValue), 0, 255),
                    'cid' => $certId,
                    'res' => $result,
                    'det' => log_safe_text('API status request'),
                    'ip'  => $ip,
                ]);
            } catch (Throwable $ignored) {
            }
        }
    }
}
