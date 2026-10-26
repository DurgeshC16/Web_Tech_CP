<?php
// src/services/SmartVerifyService.php
// ─────────────────────────────────────────────────────────────────────
// Smart Verify TEXT pipeline (Phase 1). Takes any pasted/scanned text and
// classifies it into lookup candidates IN PRIORITY ORDER:
//   1. token        — 43-char QR token, or ?token= extracted from a URL
//                     on OUR OWN host (self-host detection, no outbound
//                     request — just string parsing);
//   2. certificate_id — layered local lookup id (exact → normalized →
//                     compact); VerificationService decides the verdict;
//   3. external_ref — an issuer code matched against an allow-list map
//                     of PUBLIC VERIFICATION LINK BUILDERS. We NEVER
//                     fetch or scrape issuer pages: the card we render is
//                     a plain link the user opens themselves, and it is
//                     ALWAYS labelled "Not verified by CertiVault".
// External codes can NEVER yield a CertiVault verdict — verify.php only
// renders the "Open at <issuer>" card for them.
// ─────────────────────────────────────────────────────────────────────

class SmartVerifyService
{
    /**
     * Allow-listed external issuers. The host is validated with a strict
     * hostname pattern; URL templates build https-only links with only
     * [A-Za-z0-9._-] code characters (path-segment safe).
     */
    public static function externalIssuers(): array
    {
        return [
            'coursera' => [
                'label' => 'Coursera',
                'host'  => 'www.coursera.org',
                'template' => 'https://www.coursera.org/verify/{code}',
            ],
            'credly' => [
                'label' => 'Credly',
                'host'  => 'www.credly.com',
                'template' => 'https://www.credly.com/badges/{code}',
            ],
        ];
    }

    /**
     * Normalize a subject's own-host check: BASE_URL host + all PHP
     * SERVER_NAME candidates; used to decide that a pasted URL points at
     * our own verification page (?token= extraction is then safe).
     */
    public static function selfHosts(): array
    {
        $hosts = [];
        $base = defined('BASE_URL') && BASE_URL ? parse_url(BASE_URL, PHP_URL_HOST) : null;
        if (is_string($base) && $base !== '') {
            $hosts[] = strtolower($base);
        }
        $srvHost = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? '');
        if (is_string($srvHost) && preg_match('/^[A-Za-z0-9.\-]+(:\d+)?$/', $srvHost)) {
            $hosts[] = strtolower(explode(':', $srvHost)[0]);
        }
        $hosts[] = 'localhost';
        $hosts[] = '127.0.0.1';
        return array_values(array_unique(array_filter($hosts)));
    }

    /**
     * Classify arbitrary text into prioritized candidates.
     * @return array of ['type' => 'token'|'certificate_id'|'external_ref', 'value', 'issuer'?, 'reason'?, 'kind'?]
     *         (deduped, at most one token + one id + one external ref)
     */
    public const SV_EITHER_OR_MSG = 'Enter a certificate ID or upload a certificate file.';

    /**
     * Smart Verify "either/or" planning (pure, no I/O — unit-testable).
     * At least one of ID / file / hash must be present; when both ID and
     * file/hash are provided the FILE result is consulted first and the
     * ID becomes the fallback resolver.
     *
     * @return array{action:'either_or'|'id'|'file'|'file_first', message?:string, note?:string, fallback_to_id:bool}
     */
    public static function planVerifyInput(string $id, bool $hasFile, bool $hasHash): array
    {
        if (trim($id) === '' && !$hasFile && !$hasHash) {
            return ['action' => 'either_or', 'message' => self::SV_EITHER_OR_MSG, 'fallback_to_id' => false];
        }
        if (trim($id) !== '' && ($hasFile || $hasHash)) {
            return [
                'action' => 'file_first',
                'fallback_to_id' => true,
                'note' => 'Both provided: checking the file first, then the ID.',
            ];
        }
        if (trim($id) !== '') {
            return ['action' => 'id', 'fallback_to_id' => false];
        }
        return ['action' => 'file', 'fallback_to_id' => false];
    }

    public static function extractCandidates(string $text): array
    {
        $text = trim($text);
        $out = [];
        if ($text === '' || mb_strlen($text) > 2048) {
            return $out;
        }
        $selfHosts = self::selfHosts();
        $pushed = [];

        // 1) URLs the text contains (first match wins for the self check;
        //    allow-listed issuer URLs become external references).
        if (preg_match_all('/https?:\/\/[^\s<>"\']{4,}/i', $text, $m)) {
            foreach (array_unique($m[0]) as $url) {
                $parts = @parse_url($url);
                if (!$parts || empty($parts['host'])) {
                    continue;
                }
                $host = strtolower($parts['host']);

                // A token= parameter on our OWN host wins outright.
                if (in_array($host, $selfHosts, true) && preg_match('/[?&]token=([A-Za-z0-9_\-]+)/', $url, $tm)) {
                    if (!in_array('token', $pushed, true)) {
                        $out[] = ['type' => 'token', 'value' => $tm[1], 'reason' => 'token on verify URL', 'kind' => 'url'];
                        $pushed[] = 'token';
                    }
                    continue;
                }

                // Exact trailing-token pattern (bare URL ending in a token
                // on our own host, verify.php?token=…&…  handled above).
                if (!in_array('token', $pushed, true)
                    && self::looksLikeSelfVerifyUrl($host, $url, $selfHosts)) {
                    continue;
                }

                // Exact official hosts become actionable references. Close
                // lookalikes are surfaced as warnings, never as links.
                foreach (self::externalIssuers() as $slug => $issuer) {
                    $hostMatch = self::classifyIssuerHost($host, $issuer['host']);
                    if ($hostMatch === 'exact') {
                        $path = trim($parts['path'] ?? '', '/');
                        $code = basename($path);
                        if ($slug === 'credly' && preg_match('#^badges/([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})(?:/(?:public_url|linked_in_profile))?$#i', $path, $uuid)) {
                            $code = strtolower($uuid[1]);
                        }
                        if (preg_match('#^[A-Za-z0-9._\-]{3,64}$#', $code)
                            && !in_array('ext', $pushed, true)) {
                            $out[] = [
                                'type' => 'external_ref',
                                'value' => $code,
                                'issuer' => $slug,
                                'label' => $issuer['label'],
                                'url' => $url,
                                'reason' => 'issuer verification URL',
                            ];
                            $pushed[] = 'ext';
                        }
                        break;
                    } elseif ($hostMatch === 'suspicious' && !in_array('warning', $pushed, true)) {
                        $out[] = ['type' => 'unsafe_link', 'issuer' => $slug, 'label' => $issuer['label'], 'host' => $host];
                        $pushed[] = 'warning';
                    }
                }
            }
        }

        if (!in_array('ext', $pushed, true)
            && preg_match('/\b([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\b/i', $text, $uuid)) {
            $out[] = ['type' => 'external_ref', 'value' => strtolower($uuid[1]), 'issuer' => 'credly', 'label' => 'Credly', 'reason' => 'Credly badge UUID'];
            $pushed[] = 'ext';
        }

        // 2) Bare 43-char base64url token (possibly with "token=" label).
        if (!in_array('token', $pushed, true)
            && preg_match('/\b[A-Za-z0-9_\-]{43}\b/', $text, $tm)) {
            $out[] = ['type' => 'token', 'value' => $tm[0], 'reason' => 'bare QR token', 'kind' => 'text'];
            $pushed[] = 'token';
        }

        // 3) Certificate-ID candidates: strict CV-shaped strings first,
        //    then any short charset-valid string (the layered DB lookup
        //    decides; malformed → INVALID by the pre-flight check).
        if (!in_array('id', $pushed, true)) {
            if (preg_match('/\bCV[\s\-.\/]?\d{2,4}[\s\-.\/]?\d{4,6}\b/i', $text, $im)) {
                $out[] = ['type' => 'certificate_id', 'value' => $im[0], 'reason' => 'certificate ID in text', 'kind' => 'text'];
                $pushed[] = 'id';
            }
        }

        return $out;
    }

    /** Exact official-host match or a likely spoof (IDN, typo, nested domain). */
    public static function classifyIssuerHost(string $host, string $officialHost): string
    {
        $host = strtolower($host);
        $officialHost = strtolower($officialHost);
        if (preg_match('/[^\x00-\x7F]/', $host)) return 'suspicious';
        $officialRoot = preg_replace('/^www\./', '', $officialHost);
        $hostRoot = preg_replace('/^www\./', '', $host);
        if ($host === $officialHost || $host === $officialRoot) return 'exact';
        if (str_contains($hostRoot, $officialRoot) || str_contains($hostRoot, 'xn--')) return 'suspicious';
        $labels = explode('.', $hostRoot);
        foreach ($labels as $label) {
            if (levenshtein($label, $officialRoot) <= 2) return 'suspicious';
        }
        if (levenshtein($hostRoot, $officialRoot) <= 2) return 'suspicious';
        return 'other';
    }

    public static function suspiciousIssuerUrl(string $url): ?string
    {
        $parts = @parse_url($url);
        if (!$parts || empty($parts['host'])) return null;
        foreach (self::externalIssuers() as $issuer) {
            if (self::classifyIssuerHost(strtolower((string)$parts['host']), $issuer['host']) === 'suspicious') return $issuer['label'];
        }
        return null;
    }

    private static function looksLikeSelfVerifyUrl(string $host, string $url, array $selfHosts): bool
    {
        return in_array($host, $selfHosts, true) && str_contains($url, 'verify.php');
    }

    /**
     * Build the verified allow-listed issuer link for an external code.
     * Only characters [A-Za-z0-9._-] are accepted in codes (a URL-safety
     * check first — never rawurlencode()</>, always validated).
     * @return array{label:string,url:string}|null
     */
    public static function buildIssuerLink(string $issuerSlug, string $code): ?array
    {
        $issuers = self::externalIssuers();
        if (!isset($issuers[$issuerSlug])) {
            return null;
        }
        $code = trim($code);
        if (!preg_match('/^[A-Za-z0-9._\-]{3,64}$/', $code)) {
            return null;
        }
        $issuer = $issuers[$issuerSlug];
        $url = str_replace('{code}', $code, $issuer['template']);
        $https = str_starts_with($url, 'https://');
        return $https ? ['label' => $issuer['label'], 'url' => $url] : null;
    }

    /**
     * "Other link" option: user-supplied URL rendered as an external
     * reference. Guarded like the allow-listed ones (https-only, sane
     * host) but WITHOUT DNS resolution; the link is never fetched by us.
     * @return array{url:string}|null
     */
    public static function validateOtherLink(string $url): ?array
    {
        $url = trim($url);
        if ($url === '' || mb_strlen($url) > 2048) {
            return null;
        }
        $parts = @parse_url($url);
        if (!$parts || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])) {
            return null;
        }
        $host = strtolower($parts['host']);
        if (self::suspiciousIssuerUrl($url) !== null) {
            return null;
        }
        if (!preg_match('/^[a-z0-9.\-]+(\.[a-z]{2,})$/', $host)) {
            return null;
        }
        // The browser will open this — block obvious private/loopback
        // literals with the shared guard (external sources' SSRF helper).
        if (filter_var($host, FILTER_VALIDATE_IP)
            && ExternalSourceService::isIpBlocked($host)) {
            return null;
        }
        if ($host === 'localhost' || str_ends_with($host, '.local')) {
            return null;
        }
        return ['url' => $url];
    }

    /**
     * Scan extracted document text for anything actionable. Reuses
     * extractCandidates() and additionally flags plain "verify at <url>"
     * phrasing to catch printed instructions. Returns mixed candidates
     * (same shape) with the stage reason 'extracted from file'.
     */
    public static function scanExtractedText(string $text): array
    {
        $cands = self::extractCandidates($text);
        foreach ($cands as &$c) {
            if ($c['type'] === 'certificate_id') {
                $c['reason'] = 'ID found in document text';
            }
        }
        unset($c);
        if (preg_match_all('/(?:verify|check)\s+(?:this)?\s*(?:certificate|document|credential)?\s*\b(?:at|on|via)\b[^\r\n]{0,40}?((?:https?:\/\/)[A-Za-z0-9.\-\/?=&%#_.\-]+[A-Za-z0-9\/])/iu', $text, $m)) {
            foreach ($m[1] as $url) {
                $more = self::extractCandidates($url);
                foreach ($more as $c) {
                    $c['reason'] = 'verify-at link found in document text';
                    $cands[] = $c;
                }
            }
        }
        return $cands;
    }
}
