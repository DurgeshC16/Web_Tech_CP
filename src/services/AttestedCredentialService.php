<?php
// External credentials are student-declared information. This service never
// fetches, scrapes, or contacts issuer sites; it only validates outbound URLs.
require_once __DIR__ . '/CryptoService.php';

class AttestedCredentialService
{
    private const ISSUERS = [
        'coursera' => ['label' => 'Coursera', 'hosts' => ['www.coursera.org', 'coursera.org']],
        'credly' => ['label' => 'Credly', 'hosts' => ['www.credly.com', 'credly.com']],
        'nptel' => ['label' => 'NPTEL', 'hosts' => ['nptel.ac.in', 'www.nptel.ac.in']],
    ];

    public static function knownIssuers(): array { return self::ISSUERS; }

    /** Custom issuer hosts come only from the managed external-source allow-list. */
    public static function issuerOptions($db): array
    {
        $options = self::ISSUERS;
        try {
            foreach ($db->query('SELECT label, allowed_host FROM external_sources WHERE enabled = 1 ORDER BY label')->fetchAll(PDO::FETCH_ASSOC) as $row) {
                foreach (explode(',', strtolower((string)$row['allowed_host'])) as $host) {
                    $host = trim($host);
                    if (self::validDnsHost($host)) $options['custom:' . $host] = ['label' => (string)$row['label'], 'hosts' => [$host]];
                }
            }
        } catch (Throwable $e) {
            // Custom issuer management is optional; known issuers remain available.
        }
        return $options;
    }

    private static function validDnsHost(string $host): bool
    {
        return strlen($host) <= 253 && (bool)preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $host);
    }

    /** Exact-host HTTPS validation; no subdomains, userinfo, or custom ports. */
    public static function validateIssuerUrl($db, string $issuerSlug, string $url): array
    {
        $url = trim($url);
        $options = self::issuerOptions($db);
        if (!isset($options[$issuerSlug])) return [null, 'Choose an allow-listed issuer.'];
        $issuer = $options[$issuerSlug];
        $parts = parse_url($url);
        if (!$parts || strtolower((string)($parts['scheme'] ?? '')) !== 'https'
            || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
            || (isset($parts['port']) && (int)$parts['port'] !== 443)) {
            return [null, 'Use an HTTPS verification URL without credentials or a non-standard port.'];
        }
        $host = strtolower((string)$parts['host']);
        if (!in_array($host, $issuer['hosts'], true)) return [null, 'This URL host is not exactly allow-listed for the selected issuer.'];
        if (strlen($url) > 2048 || preg_match('/[\x00-\x20\\]/', $url)) return [null, 'Verification URL is malformed or too long.'];
        return [['url' => $url, 'label' => $issuer['label'], 'host' => $host], null];
    }

    /** Build only known official URLs; custom issuers must provide their URL. */
    public static function urlFromCode(string $issuerSlug, string $code): ?string
    {
        $code = trim($code);
        if ($code === '' || strlen($code) > 255 || !preg_match('/^[A-Za-z0-9._:-]+$/', $code)) return null;
        $segment = rawurlencode($code);
        if ($issuerSlug === 'coursera') return 'https://www.coursera.org/verify/' . $segment;
        if ($issuerSlug === 'credly') return 'https://www.credly.com/badges/' . $segment;
        if ($issuerSlug === 'nptel') return 'https://nptel.ac.in/noc/Ecertificate/?q=' . $segment;
        return null;
    }

    /** Fixed-order canonical JSON. Every value covered by the signature is explicit. */
    public static function canonicalPayload(array $record): string
    {
        $payload = [
            'student_id' => (int)$record['student_id'],
            'student_name' => (string)$record['student_name'],
            'issuer_slug' => (string)$record['issuer_slug'],
            'issuer_label' => (string)$record['issuer_label'],
            'issuer_code' => ($record['issuer_code'] ?? null) === '' ? null : ($record['issuer_code'] ?? null),
            'verification_url' => (string)$record['verification_url'],
            'title' => (string)$record['title'],
            'issue_date' => (string)$record['issue_date'],
            'file_sha256' => ($record['file_sha256'] ?? null) ?: null,
            'attesting_institution_id' => (int)$record['attesting_institution_id'],
            'attesting_institution_name' => (string)$record['attesting_institution_name'],
            'attested_at' => (string)$record['attested_at'],
        ];
        return json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    public static function canonicalHash(array $record): string
    {
        return hash('sha256', self::canonicalPayload($record));
    }

    public static function logEvent($db, array $record, string $verdict, ?string $detail = null): void
    {
        $allowed = ['ATTESTED', 'SELF_DECLARED', 'TAMPERED', 'WITHDRAWN'];
        if (!in_array($verdict, $allowed, true)) $verdict = 'TAMPERED';
        $stmt = $db->prepare('INSERT INTO verification_logs (query_type,query_value,certificate_id_found,result,detail,verifier_ip) VALUES ("external_credential",:qv,NULL,:result,:detail,:ip)');
        $stmt->execute([
            'qv' => 'external-credential:' . (int)($record['id'] ?? 0),
            'result' => $verdict,
            'detail' => $detail !== null ? mb_substr(log_safe_text($detail), 0, 255) : null,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
        ]);
    }

    /** Verify file bytes, canonical fields and institution signature. */
    public static function verdict($db, array $record): string
    {
        $state = (string)($record['status'] ?? '');
        if ($state === 'WITHDRAWN') return 'WITHDRAWN';
        if ($state === 'SELF_DECLARED') {
            return (!empty($record['signature']) || !empty($record['attestation_hash']) || !empty($record['attested_at']))
                ? 'TAMPERED' : 'SELF_DECLARED';
        }
        if ($state !== 'ATTESTED' || !empty($record['withdrawn_at']) || !empty($record['withdrawn_by'])) return 'TAMPERED';
        if (empty($record['signature']) || empty($record['attestation_hash']) || empty($record['attested_at'])
            || empty($record['attesting_institution_id'])) return 'TAMPERED';
        if (!empty($record['file_path'])) {
            $filePath = __DIR__ . '/../../private_data/external_credentials/' . basename((string)$record['file_path']);
            if (!is_file($filePath) || empty($record['file_sha256']) || !hash_equals((string)$record['file_sha256'], (string)hash_file('sha256', $filePath))) return 'TAMPERED';
        } elseif (!empty($record['file_sha256'])) {
            return 'TAMPERED';
        }
        try {
            $hash = self::canonicalHash($record);
            if (!hash_equals((string)$record['attestation_hash'], $hash)) return 'TAMPERED';
            $stmt = $db->prepare('SELECT public_key FROM institution_keys WHERE institution_id=:iid AND key_id=:kid');
            $stmt->execute(['iid' => (int)$record['attesting_institution_id'],'kid'=>(int)$record['attesting_key_id']]);
            $publicKey = $stmt->fetchColumn();
            return is_string($publicKey) && CryptoService::verifyCertificateSignature($hash, (string)$record['signature'], $publicKey)
                ? 'ATTESTED' : 'TAMPERED';
        } catch (Throwable $e) {
            return 'TAMPERED';
        }
    }

    /** Lock, sign and persist a SELF_DECLARED record with the approved institution key. */
    public static function attest($db, int $credentialId, int $institutionId): void
    {
        $db->beginTransaction();
        try {
            $stmt = $db->prepare('SELECT * FROM external_credentials WHERE id = :id FOR UPDATE');
            $stmt->execute(['id' => $credentialId]);
            $record = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$record || $record['status'] !== 'SELF_DECLARED') throw new RuntimeException('This credential is no longer awaiting attestation.');
            $stmt = $db->prepare('SELECT i.name,k.key_id,k.public_key,k.encrypted_private_key FROM institutions i JOIN institution_keys k ON k.institution_id=i.id AND k.status="active" WHERE i.id=:iid AND i.status="approved" ORDER BY k.key_id DESC LIMIT 1 FOR UPDATE');
            $stmt->execute(['iid' => $institutionId]);
            $institution = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$institution || empty($institution['public_key']) || empty($institution['encrypted_private_key'])) throw new RuntimeException('Institution signing keys are unavailable.');
            $record['attesting_institution_id'] = $institutionId;
            $record['attesting_key_id'] = (int)$institution['key_id'];
            $record['attesting_institution_name'] = (string)$institution['name'];
            $record['attested_at'] = date('Y-m-d H:i:s');
            $hash = self::canonicalHash($record);
            $privateKey = CryptoService::decryptPrivateKey($institution['encrypted_private_key']);
            $signature = CryptoService::signCertificateHash($hash, $privateKey);
            if (!CryptoService::verifyCertificateSignature($hash, $signature, $institution['public_key'])) throw new RuntimeException('Institution signature self-check failed.');
            $update = $db->prepare('UPDATE external_credentials SET status="ATTESTED",attesting_institution_id=:iid,attesting_key_id=:kid,attesting_institution_name=:iname,attested_at=:at,attestation_hash=:hash,signature=:sig WHERE id=:id AND status="SELF_DECLARED"');
            $update->execute(['iid'=>$institutionId,'kid'=>$record['attesting_key_id'],'iname'=>$record['attesting_institution_name'],'at'=>$record['attested_at'],'hash'=>$hash,'sig'=>$signature,'id'=>$credentialId]);
            if ($update->rowCount() !== 1) throw new RuntimeException('Credential changed while it was being attested.');
            $db->commit();
        } catch (Throwable $e) {
            if ($db->inTransaction()) $db->rollBack();
            throw $e;
        }
    }
}
