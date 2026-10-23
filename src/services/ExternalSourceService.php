<?php
// src/services/ExternalSourceService.php
// ─────────────────────────────────────────────────────────────────────
// Optional external certificate sources for verify.php. CertiVault's own
// verdict pipeline is NEVER applied to external records: they are shown
// in a clearly separate card as "found elsewhere", never as VALID.
//
// Adapters implement ExternalSourceInterface::fetch($id) and return a
// NORMALIZED array with exactly these keys (null = not found / unusable):
//   holder, title, issuer, issue_date, status, source_url
//
// Security posture (see README §external sources):
//  - Disabled by default (EXT_SOURCE_ENABLED=false).
//  - HTTPS only + host allow-list (EXT_ALLOWED_HOSTS).
//  - SSRF guard: resolved A/AAAA records may not be private/reserved/
//    loopback/link-local; redirects re-validated on every hop.
//  - 5-second timeout, 1 MB response cap, JSON schema validation.
//  - 10-minute file cache (hits AND misses), per-IP rate limit.
//  - Every lookup attempt is written to verification_logs.
// ─────────────────────────────────────────────────────────────────────

interface ExternalSourceInterface
{
    public function name(): string;
    /** @return array{holder:string,title:string,issuer:string,issue_date:string,status:string,source_url:string}|null */
    public function fetch(string $id): ?array;
}

class ExternalSourceService
{
    /** Max redirects followed; each hop must pass the same SSRF validation. */
    const REDIRECT_LIMIT = 3;
    /** Response size cap in bytes. */
    const RESPONSE_CAP = 1048576;
    /** Connect/read timeout in seconds. */
    const HTTP_TIMEOUT = 5;
    /** Cache TTL in seconds (hits and misses). */
    const CACHE_TTL = 600;

    /**
     * Facade used by verify.php: runs the adapters (configured in
     * config.local.php) with cache + rate limit + audit logging.
     * Never throws — any failure degrades to ['hit' => null].
     *
     * @return array{hit:?array, blocked:bool, source:?string}
     */
    public static function lookup($db, string $id): array
    {
        $out = ['hit' => null, 'blocked' => false, 'source' => null];
        try {
            $id = trim($id);
            $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

            // Per-IP rate limit: too many external lookups → skip this one.
            if (defined('EXT_RATE_LIMIT')) {
                $stmt = $db->prepare("
                    SELECT COUNT(*) FROM verification_logs
                    WHERE verifier_ip = :ip AND result LIKE 'EXTERNAL%'
                      AND verified_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
                ");
                $stmt->execute(['ip' => $ip]);
                if ((int)$stmt->fetchColumn() >= (int)EXT_RATE_LIMIT) {
                    error_log("[CertiVault] External-source rate limit hit for IP $ip — skipping external lookup.");
                    $out['blocked'] = true;
                    return $out;
                }
            }

            $cacheKey = hash('sha256', strtolower($id));
            $cache = self::cacheGet($cacheKey);
            if ($cache !== null) {
                $out['hit'] = $cache['fields'];
                $out['source'] = $cache['source'];
                self::logLookup($db, $id, $ip, 'EXTERNAL_FOUND', 'cached (warm)');
                $out['hit']['_from_cache'] = true;
                return $out;
            }

            foreach (self::adapters() as $adapter) {
                $fields = $adapter->fetch($id);
                if ($fields !== null) {
                    $out['hit'] = $fields;
                    $out['source'] = $adapter->name();
                    self::cachePut($cacheKey, ['fields' => $fields, 'source' => $adapter->name()]);
                    self::logLookup($db, $id, $ip, 'EXTERNAL_FOUND', 'source: ' . $adapter->name());
                    return $out;
                }
            }

            self::cachePut($cacheKey, ['miss' => true]);
            self::logLookup($db, $id, $ip, 'EXTERNAL_NOT_FOUND', null);
            return $out;
        } catch (Throwable $e) {
            error_log('[CertiVault] External source lookup failed: ' . get_class($e) . ': ' . $e->getMessage());
            try {
                self::logLookup($db, trim($id), $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0', 'EXTERNAL_ERROR', null);
            } catch (Throwable $ignored) {
                // logging must never break the page
            }
            return $out;
        }
    }

    /** @return ExternalSourceInterface[] */
    public static function adapters(): array
    {
        $adapters = [];
        $template = (string)(defined('EXT_OB_URL_TEMPLATE') ? EXT_OB_URL_TEMPLATE : '');
        if ($template !== '') {
            $adapters[] = new OpenBadgesAdapter($template);
        }
        $dsn = (string)(defined('EXT_DB_DSN') ? EXT_DB_DSN : '');
        if ($dsn !== '') {
            $adapters[] = new RemoteDbAdapter([
                'dsn'    => $dsn,
                'user'   => (string)(defined('EXT_DB_USER') ? EXT_DB_USER : ''),
                'pass'   => (string)(defined('EXT_DB_PASS') ? EXT_DB_PASS : ''),
                'table'  => (string)(defined('EXT_DB_TABLE') ? EXT_DB_TABLE : 'external_certificates'),
                'cols'   => [
                    'id'     => (string)(defined('EXT_DB_ID_COLUMN') ? EXT_DB_ID_COLUMN : 'certificate_id'),
                    'holder' => (string)(defined('EXT_DB_HOLDER_COLUMN') ? EXT_DB_HOLDER_COLUMN : 'holder'),
                    'title'  => (string)(defined('EXT_DB_TITLE_COLUMN') ? EXT_DB_TITLE_COLUMN : 'title'),
                    'issuer' => (string)(defined('EXT_DB_ISSUER_COLUMN') ? EXT_DB_ISSUER_COLUMN : 'issuer'),
                    'date'   => (string)(defined('EXT_DB_DATE_COLUMN') ? EXT_DB_DATE_COLUMN : 'issue_date'),
                    'status' => (string)(defined('EXT_DB_STATUS_COLUMN') ? EXT_DB_STATUS_COLUMN : 'status'),
                ],
                'label'  => (string)(defined('EXT_DB_LABEL') ? EXT_DB_LABEL : 'external database'),
            ]);
        }
        return $adapters;
    }

    // ── Logging (row appended to verification_logs) ────────────────────

    public static function logLookup($db, string $id, string $ip, string $result, ?string $detail): void
    {
        if (!in_array($result, ['EXTERNAL_FOUND', 'EXTERNAL_NOT_FOUND', 'EXTERNAL_ERROR'], true)) {
            $result = 'EXTERNAL_ERROR';
        }
        try {
            $stmt = $db->prepare('
                INSERT INTO verification_logs
                    (query_type, query_value, certificate_id_found, result, detail, verifier_ip)
                VALUES ("certificate_id", :qv, :cid, :res, :det, :ip)
            ');
            $stmt->execute([
                'qv'  => mb_substr(self::sanitizeText($id), 0, 255),
                'cid' => mb_substr($id, 0, 64),
                'res' => $result,
                'det' => $detail !== null ? mb_substr(self::sanitizeText($detail), 0, 255) : null,
                'ip'  => $ip,
            ]);
        } catch (PDOException $e) {
            // Fresh installs may not have database/migrations/008 applied yet
            // (the result ENUM would reject the EXTERNAL_* value). Never let
            // that break the page — retry as a plain INVALID marker.
            error_log('[CertiVault] verification_logs insert failed for external lookup (run migration 008?): ' . $e->getMessage());
            try {
                $stmt = $db->prepare('
                    INSERT INTO verification_logs
                        (query_type, query_value, certificate_id_found, result, detail, verifier_ip)
                    VALUES ("certificate_id", :qv, :cid, "INVALID", :det, :ip)
                ');
                $stmt->execute([
                    'qv'  => mb_substr(self::sanitizeText($id), 0, 255),
                    'cid' => mb_substr($id, 0, 64),
                    'det' => mb_substr(self::sanitizeText('[external] ' . $result . ($detail ? ': ' . $detail : '')), 0, 255),
                    'ip'  => $ip,
                ]);
            } catch (Throwable $ignored) {
            }
        }
    }

    /**
     * Log-safety for user-controlled text in log columns. prefers the app's
     * log_safe_text() when loaded, with a sane inline fallback so this
     * service stays self-sufficient.
     */
    private static function sanitizeText(string $s): string
    {
        return function_exists('log_safe_text') ? log_safe_text($s) : (preg_replace('/[\x00-\x1F\x7F]/u', '?', $s) ?: '');
    }

    // ── File cache (private_data/cache/external) ───────────────────────

    private static function cacheDir(): string
    {
        static $dir = null;
        if ($dir === null) {
            $dir = __DIR__ . '/../../private_data/cache/external';
            if (!is_dir($dir)) {
                @mkdir($dir, 0770, true);
            }
        }
        return $dir;
    }

    private static function cacheGet(string $key): ?array
    {
        $path = self::cacheDir() . '/' . $key . '.json';
        $raw = @file_get_contents($path);
        if ($raw === false) {
            return null;
        }
        $data = json_decode($raw, true);
        if (!is_array($data) || !isset($data['t']) || (time() - (int)$data['t']) > self::CACHE_TTL) {
            @unlink($path);
            return null;
        }
        if (!empty($data['miss'])) {
            return ['miss' => true];
        }
        return is_array($data['fields'] ?? null) && isset($data['source'])
            ? ['fields' => $data['fields'], 'source' => (string)$data['source']]
            : null;
    }

    private static function cachePut(string $key, array $value): void
    {
        $value['t'] = time();
        @file_put_contents(self::cacheDir() . '/' . $key . '.json', json_encode($value), LOCK_EX);
    }

    // ── SSRF-safe HTTP fetch (shared by network adapters) ──────────────

    /**
     * Fetch a public HTTPS resource under all the security constraints.
     * @param string $url absolute URL, https scheme required
     * @return array{0:?string,1:?string} [body|null, errorReason|null]
     */
    public static function httpGet(string $url): array
    {
        for ($hop = 0; $hop <= self::REDIRECT_LIMIT; $hop++) {
            $parts = parse_url($url);
            if (!$parts) {
                return [null, 'Malformed source URL.'];
            }
            // HTTPS-only on EVERY hop — redirects learn no downgrade.
            if (($parts['scheme'] ?? '') !== 'https') {
                return [null, 'External sources must use HTTPS (redirects included).'];
            }
            $host = strtolower($parts['host'] ?? '');

            // Allow-list: exact match, or subdomain of an allow-listed host.
            if (!self::isHostAllowed($host)) {
                return [null, 'Source host is not on the allow-list (EXT_ALLOWED_HOSTS).'];
            }

            // Resolve every A/AAAA record and make sure all are public.
            $ips = self::resolveHost($host);
            if ($ips === null) {
                return [null, 'Source host could not be resolved.'];
            }
            foreach ($ips as $ip) {
                if (self::isIpBlocked($ip)) {
                    error_log("[CertiVault] SSRF guard: host $host resolves to blocked IP $ip while fetching external source.");
                    return [null, 'Source host resolves to a private/reserved address (SSRF guard).'];
                }
            }

            $port = isset($parts['port']) ? (int)$parts['port'] : (strtolower($parts['scheme'] ?? '') === 'https' ? 443 : 80);
            $scheme = $parts['scheme'];
            if (!in_array($port, $scheme === 'https' ? [443] : [80], true)) {
                return [null, 'Non-standard ports are not allowed for external sources.'];
            }
            $path = ($parts['path'] ?? '/')
                . (isset($parts['query']) ? '?' . $parts['query'] : '')
                . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
            $requestUrl = $scheme . '://' . $host . $path;

            $ctx = stream_context_create([
                'http' => [
                    'method'           => 'GET',
                    'timeout'          => self::HTTP_TIMEOUT,
                    'follow_location'  => 0,   // we validate each hop ourselves
                    'max_redirects'    => 0,
                    'ignore_errors'    => false,
                    'protocol_version' => 1.1,
                    'header'           => "Accept: application/json\r\nConnection: close\r\n",
                ],
                'ssl' => [
                    'verify_peer'      => true,
                    'verify_peer_name' => true,
                    'SNI_enabled'      => true,
                    'peer_name'        => $host,
                ],
            ]);

            $fp = @fopen($requestUrl, 'rb', false, $ctx);
            if (!$fp) {
                return [null, 'Source could not be reached within ' . self::HTTP_TIMEOUT . 's.'];
            }

            // Response metadata: treat 3xx as a redirect (Location re-validated above loop).
            $meta = stream_get_meta_data($fp);
            foreach ($meta['wrapper_data'] ?? [] as $header) {
                if (is_string($header)) {
                    if (preg_match('#^HTTP/\S+ 30[12378]#i', $header)) {
                        $isRedirect = true;
                    }
                    if (preg_match('#^\s*location:\s*(\S+)#i', $header, $m)) {
                        $redirectTo = $m[1];
                    }
                    if (preg_match('#^\s*content-length:\s*(\d+)#i', $header, $m)) {
                        $contentLength = (int)$m[1];
                    }
                }
            }

            $body = false;
            if (!empty($isRedirect)) {
                fclose($fp);
                if (empty($redirectTo)) {
                    return [null, 'Redirect without Location header.'];
                }
                if ($hop === self::REDIRECT_LIMIT) {
                    return [null, 'Too many redirects.'];
                }
                $url = self::absoluteUrl($redirectTo, $requestUrl);
                continue; // re-validate everything for the next hop
            }

            $body = '';
            if (isset($contentLength) && $contentLength > self::RESPONSE_CAP) {
                fclose($fp);
                return [null, 'Response exceeds the 1 MB size cap.'];
            }
            while (!feof($fp)) {
                $chunk = fread($fp, 65536);
                if ($chunk === false) {
                    break;
                }
                $body .= $chunk;
                if (strlen($body) > self::RESPONSE_CAP) {
                    fclose($fp);
                    return [null, 'Response exceeds the 1 MB size cap.'];
                }
            }
            fclose($fp);
            return [$body, null];
        }
        return [null, 'Too many redirects.'];
    }

    private static function absoluteUrl(string $loc, string $base): string
    {
        if (preg_match('#^https?://#i', $loc)) {
            return $loc;
        }
        $p = parse_url($base);
        $root = strtolower($p['scheme']) . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
        if ($loc[0] === '/') {
            return $root . $loc;
        }
        return $root . '/' . $loc;
    }

    /**
     * Host allow-list check: exact match or subdomain of an entry.
     * @param string $host lowercase host
     */
    public static function isHostAllowed(string $host): bool
    {
        $list = defined('EXT_ALLOWED_HOSTS') ? (string)EXT_ALLOWED_HOSTS : '';
        foreach (explode(',', $list) as $entry) {
            $entry = strtolower(trim($entry));
            if ($entry === '') {
                continue;
            }
            if ($host === $entry || str_ends_with($host, '.' . $entry)) {
                return true;
            }
        }
        return false;
    }

    /** All A/AAAA records for a host (null = unresolvable). */
    private static function resolveHost(string $host): ?array
    {
        // Literal IP → single candidate.
        if (filter_var(trim($host, '[]'), FILTER_VALIDATE_IP)) {
            return [trim($host, '[]')];
        }
        $ips = [];
        try {
            foreach (dns_get_record($host, DNS_A) as $rec) {
                if (!empty($rec['ip'])) {
                    $ips[] = $rec['ip'];
                }
            }
        } catch (Throwable $e) {
            // dns_get_record may emit warnings; fall through to checklist
        }
        if (empty($ips)) {
            $v4 = @gethostbynamel($host);
            if (is_array($v4)) {
                $ips = $v4;
            }
        }
        try {
            $v6 = @dns_get_record($host, DNS_AAAA);
            foreach ($v6 as $rec) {
                if (!empty($rec['ipv6'])) {
                    $ips[] = $rec['ipv6'];
                }
            }
        } catch (Throwable $e) {
        }
        return $ips ?: null;
    }

    /**
     * True when the IP must not be contacted (private/reserved/loopback/
     * link-local ranges). Works for IPv4 and IPv6.
     */
    public static function isIpBlocked(string $ip): bool
    {
        $ip = trim($ip, '[]');
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return true;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return true;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // Belt-and-braces (filter flags have historical gaps):
            $n = ip2long($ip);
            $lo = ip2long('100.64.0.0');   // CGNAT 100.64/10
            $hi = ip2long('100.127.255.255');
            $prefixes = ['127.' => 'loopback', '169.254.' => 'link-local', '0.' => 'this-network'];
            if ($n >= $lo && $n <= $hi) {
                return true;
            }
            foreach ($prefixes as $prefix => $label) {
                if (str_starts_with($ip, $prefix)) {
                    return true;
                }
            }
            // 10/8, 172.16/12, 192.168/16 (defense in depth; flags cover these)
            [$a, $b] = [$n >> 24 & 0xFF, $n >> 16 & 0xFF];
            if ($a === 10 || ($a === 172 && $b >= 16 && $b <= 31) || ($a === 192 && $b === 168)) {
                return true;
            }
        } else {
            $lower = strtolower($ip);
            if (str_starts_with($lower, '::1') || str_starts_with($lower, 'fc') || str_starts_with($lower, 'fd')
                || preg_match('/^fe[89ab]/', $lower)) {
                return true;
            }
        }
        return false;
    }

    // ── Open Badges assertion validation (shared, testable) ────────────

    /**
     * Validate a decoded Open Badges 2.0 assertion and normalize it.
     * Returns the normalized record, or [null, reason].
     */
    public static function validateAssertion($data, string $id): array
    {
        if (!is_array($data)) {
            return [null, 'Response is not a JSON object.'];
        }
        if (($data['type'] ?? '') !== 'Assertion') {
            return [null, 'Not an Open Badges Assertion ("type" != Assertion).'];
        }
        if (empty($data['issuedOn']) || false === strtotime((string)$data['issuedOn'])) {
            return [null, 'Assertion has no valid issuedOn date.'];
        }
        if (!isset($data['recipient']) || !is_array($data['recipient'])
            || empty($data['recipient']['identity'])
            || !array_key_exists('hashed', $data['recipient'])) {
            return [null, 'Assertion has no valid recipient identity.'];
        }
        $revoked = $data['revoked'] ?? false;
        if (!is_bool($revoked)) {
            return [null, 'Assertion "revoked" flag must be a boolean.'];
        }
        $badge = is_array($data['badge'] ?? null) ? $data['badge'] : [];
        $title = $badge['name'] ?? ($data['title'] ?? 'Certificate');
        $issuer = '';
        if (is_array($badge['issuer'] ?? null)) {
            $issuer = $badge['issuer']['name'] ?? ($badge['issuer']['id'] ?? '');
        } elseif (is_string($badge['issuer'] ?? null) && $badge['issuer'] !== '') {
            $issuer = $badge['issuer'];
        }

        $recipient = $data['recipient'];
        $hashed = $recipient['hashed'] === true;
        $holder = $hashed
            ? 'Recipient identity withheld (hashed by issuer)'
            : (string)$recipient['identity'];

        return [[
            'holder'     => $holder,
            'title'      => (string)$title,
            'issuer'     => (string)$issuer,
            'issue_date' => substr((string)$data['issuedOn'], 0, 10),
            'status'     => $revoked ? 'revoked' : 'active',
            'source_url' => (string)($data['id'] ?? $id),
        ], null];
    }
}

class OpenBadgesAdapter implements ExternalSourceInterface
{
    private $template;
    public function __construct(string $urlTemplate)
    {
        $this->template = $urlTemplate;
    }

    public function name(): string
    {
        return defined('EXT_OB_SOURCE_NAME') && EXT_OB_SOURCE_NAME !== ''
            ? EXT_OB_SOURCE_NAME
            : 'Open Badges (hosted)';
    }

    public function fetch(string $id): ?array
    {
        $url = str_replace('{id}', rawurlencode($id), $this->template);
        [$body, $err] = ExternalSourceService::httpGet($url);
        if ($body === null) {
            error_log("[CertiVault] OpenBadgesAdapter($id): $err");
            return null;
        }
        $data = json_decode($body, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            error_log("[CertiVault] OpenBadgesAdapter($id): invalid JSON response.");
            return null;
        }
        [$fields, $verr] = ExternalSourceService::validateAssertion($data, $id);
        if ($fields === null) {
            error_log("[CertiVault] OpenBadgesAdapter($id): $verr");
            return null;
        }
        return $fields;
    }
}

class RemoteDbAdapter implements ExternalSourceInterface
{
    private $opts;
    private $pdo = null;

    /**
     * @param array $opts dsn,user,pass,table,cols{...},label
     */
    public function __construct(array $opts)
    {
        $this->opts = $opts;
        // Table/view + column names are interpolated into SQL (identifiers
        // cannot be bound), so they are strictly validated even though they
        // come from a trusted config file.
        foreach ($this->identifiers() as $identifier) {
            if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/', $identifier)) {
                throw new InvalidArgumentException("RemoteDbAdapter: unsafe identifier '$identifier' (use [A-Za-z_][A-Za-z0-9_]).");
            }
        }
    }

    private function identifiers(): array
    {
        return [$this->opts['table']]
            + array_values($this->opts['cols']);
    }

    public function name(): string
    {
        return $this->opts['label'] !== '' ? $this->opts['label'] : 'external database';
    }

    private function connect(): PDO
    {
        if ($this->pdo === null) {
            $this->pdo = new PDO($this->opts['dsn'], $this->opts['user'], $this->opts['pass'], [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
                PDO::ATTR_TIMEOUT            => 5,
            ]);
        }
        return $this->pdo;
    }

    public function fetch(string $id): ?array
    {
        $c = $this->opts['cols'];
        $sql = sprintf(
            'SELECT %s AS eid, %s AS holder, %s AS title, %s AS issuer,
                    %s AS issue_date, %s AS status
             FROM %s
             WHERE LOWER(TRIM(%s)) = LOWER(TRIM(:id))
             LIMIT 1',
            $c['id'], $c['holder'], $c['title'], $c['issuer'], $c['date'], $c['status'],
            $this->opts['table'], $c['id']
        );
        try {
            $stmt = $this->connect()->prepare($sql);
            $stmt->execute(['id' => $id]);
            $row = $stmt->fetch();
        } catch (Throwable $e) {
            error_log('[CertiVault] RemoteDbAdapter query failed: ' . $e->getMessage());
            return null;
        }
        if (!$row) {
            return null;
        }
        $status = strtolower(trim((string)$row['status']));
        $date = (string)$row['issue_date'];
        $ts = strtotime($date);
        return [
            'holder'     => (string)($row['holder'] ?? ''),
            'title'      => (string)($row['title'] ?? 'Certificate'),
            'issuer'     => (string)($row['issuer'] ?? ''),
            'issue_date' => $ts ? date('Y-m-d', $ts) : $date,
            'status'     => $status,
            'source_url' => '',  // relational source has no public URL
        ];
    }
}
