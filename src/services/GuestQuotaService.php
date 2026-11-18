<?php
// src/services/GuestQuotaService.php
// ─────────────────────────────────────────────────────────────────────
// Free-verification quota for visitors who are NOT logged in.
//
// A guest gets GUEST_VERIFY_LIMIT (default 5) verifications per rolling
// GUEST_VERIFY_WINDOW seconds (default 24 h). After that the verify pages
// show a "log in or create a free account" notice INSTEAD of running the
// lookup. Logged-in users (any role) are never counted. The per-IP rate
// limiter in VerificationService is separate and still applies to everyone.
//
// What one "verification" is: a distinct lookup KEY (the same raw-input key
// the rate limiter uses — token, typed ID, file hash …). Repeating a key
// already used in the window is free (page refresh, re-opening the same QR
// link), exactly like VerificationService::checkAndRecordLookup. A lookup
// may carry extra ALIAS keys (e.g. "cert:<certificate id>") that never cost
// a credit but make a later request for the same certificate — the PDF
// report, the same certificate typed differently — count as a repeat.
//
// Two independent counters; the guest is limited when EITHER is full:
//   - per client IP, server-side in guest_verify_quota (migration 017), so
//     clearing cookies alone does not reset it. The IP is stored only as an
//     HMAC (derived key), never raw.
//   - per PHP session ($_SESSION), so a guest who changes IP (mobile data)
//     keeps the same count, and the counter still works if the table is
//     missing.
// Storage is bounded: stale rows are pruned on every call (plus an
// occasional global sweep), and per subject at most limit credit rows plus
// MAX_ALIAS_ROWS alias rows are kept.
//
// Failure policy: if the table is missing (migration 017 not applied) or
// the DB errors, the IP counter FAILS OPEN (error_log, no blocking) so an
// un-migrated install keeps verifying; the session counter still applies.
// ─────────────────────────────────────────────────────────────────────

class GuestQuotaService {

    /** $_SESSION slot: [key_hash => [unix_ts, is_credit(0|1)]]. */
    const SESSION_KEY = 'cv_guest_verify_quota';
    /** Alias (non-credit) rows/entries kept per subject on top of the credits. */
    const MAX_ALIAS_ROWS = 50;
    /** One call in N also prunes every subject's stale rows. */
    const SWEEP_ONE_IN = 200;

    // ── Configuration ───────────────────────────────────────────────────

    /** Free verifications per window; 0 = quota disabled. */
    public static function limit(): int {
        return defined('GUEST_VERIFY_LIMIT') ? max(0, (int)GUEST_VERIFY_LIMIT) : 5;
    }

    /** Rolling window in seconds (never below one minute). */
    public static function window(): int {
        return max(60, defined('GUEST_VERIFY_WINDOW') ? (int)GUEST_VERIFY_WINDOW : 86400);
    }

    /**
     * True when the session belongs to a logged-in user whose session is
     * still within the idle/absolute lifetime (mirrors check_session_expiry,
     * without its redirect side effect). Any role is exempt.
     */
    public static function isAuthenticated(array $session, ?int $now = null): bool {
        if (empty($session['user_id']) || empty($session['role'])) {
            return false;
        }
        $now = $now ?? time();
        $idle = defined('SESSION_IDLE_TIMEOUT') ? (int)SESSION_IDLE_TIMEOUT : 1800;
        $abs  = defined('SESSION_ABSOLUTE_LIFETIME') ? (int)SESSION_ABSOLUTE_LIFETIME : 28800;
        $last = (int)($session['last_activity'] ?? 0);
        $started = (int)($session['login_time'] ?? 0);
        if (($last && ($now - $last) > $idle) || ($started && ($now - $started) > $abs)) {
            return false;
        }
        return true;
    }

    /**
     * HMAC of the client IP under a key derived from APP_ENCRYPTION_KEY
     * (domain-separated, so the encryption key itself is never used as an
     * HMAC key). Plain SHA-256 of an IPv4 address is brute-forceable; the
     * secret makes the stored value useless without the server config.
     */
    public static function subjectHash(string $ip): string {
        $secret = defined('APP_ENCRYPTION_KEY') ? (string)APP_ENCRYPTION_KEY : 'certivault';
        $derived = hash_hmac('sha256', 'certivault/guest-verify-quota/v1', $secret, true);
        return hash_hmac('sha256', 'ip:' . $ip, $derived);
    }

    /** Lookup keys are stored only as SHA-256 (never the raw input). */
    public static function keyHash(string $key): string {
        return hash('sha256', $key);
    }

    /** Alias key for one certificate, shared by every page that shows it. */
    public static function certAlias(string $certificateId): string {
        return 'cert:' . mb_strtolower(trim($certificateId));
    }

    // ── Public API ──────────────────────────────────────────────────────

    /**
     * Read-only gate: may this visitor run a lookup identified by $keys?
     * Nothing is recorded. Call BEFORE any certificate query.
     *
     * @param array    $keys    Raw lookup key(s); empty = just report status.
     * @return array{enabled:bool, exempt:bool, allowed:bool, repeat:bool,
     *               used:int, limit:int, remaining:int, resets_in:?int,
     *               degraded:bool}
     */
    public static function check($db, string $ip, array &$session, array $keys = [], ?int $limit = null, ?int $window = null): array {
        $limit  = $limit ?? self::limit();
        $window = max(1, $window ?? self::window());
        if ($limit <= 0 || self::isAuthenticated($session)) {
            return self::exemptStatus($limit);
        }
        $hashes = self::hashes($keys);
        $now = time();
        self::pruneSession($session, $window, $now);
        $ipState = self::ipState($db, $ip, $hashes, $window);
        $sessState = self::sessionState($session, $hashes, $window, $now);
        return self::status($limit, $ipState, $sessState, false);
    }

    /**
     * Record one lookup that actually reached the verification cascade.
     * The first key is the credit; the rest are free aliases. A lookup
     * whose keys were already seen in the window costs nothing (missing
     * aliases are still remembered). Never records past the limit — the
     * page must have called check() first, this is defence in depth.
     *
     * @return array Same shape as check(): allowed/repeat describe THIS
     *               lookup, used/remaining/resets_in the state AFTER it.
     */
    public static function record($db, string $ip, array &$session, array $keys, ?int $limit = null, ?int $window = null): array {
        $limit  = $limit ?? self::limit();
        $window = max(1, $window ?? self::window());
        if ($limit <= 0 || self::isAuthenticated($session)) {
            return self::exemptStatus($limit);
        }
        $hashes = self::hashes($keys);
        if (!$hashes) {
            return self::check($db, $ip, $session, [], $limit, $window);
        }
        $now = time();
        self::pruneSession($session, $window, $now);
        $ipState = self::ipState($db, $ip, $hashes, $window);
        $sessState = self::sessionState($session, $hashes, $window, $now);
        $before = self::status($limit, $ipState, $sessState, false);
        if (!$before['allowed']) {
            return $before;
        }
        $isRepeat = $before['repeat'];

        // Session side (always available).
        $slot = is_array($session[self::SESSION_KEY] ?? null) ? $session[self::SESSION_KEY] : [];
        foreach ($hashes as $i => $h) {
            if (!isset($slot[$h])) {
                $slot[$h] = [$now, ($i === 0 && !$isRepeat) ? 1 : 0];
            }
        }
        $session[self::SESSION_KEY] = self::capSession($slot);

        // IP side (fails open).
        $subject = self::subjectHash($ip);
        if ($ipState['ok']) {
            try {
                $ins = $db->prepare('INSERT INTO guest_verify_quota (subject_hash, key_hash, is_credit, seen_at)
                                     VALUES (:s, :k, :c, NOW())
                                     ON DUPLICATE KEY UPDATE key_hash = key_hash');
                $aliasRows = $ipState['aliases'];
                foreach ($hashes as $i => $h) {
                    if (in_array($h, $ipState['seen'], true)) {
                        continue;
                    }
                    $credit = ($i === 0 && !$isRepeat) ? 1 : 0;
                    if (!$credit && $aliasRows >= self::MAX_ALIAS_ROWS) {
                        continue; // bounded: aliases are a convenience only
                    }
                    $ins->execute(['s' => $subject, 'k' => $h, 'c' => $credit]);
                    $aliasRows += $credit ? 0 : 1;
                }
            } catch (\PDOException $e) {
                error_log('[CertiVault] Guest verify quota could not record (fail open): ' . $e->getMessage());
                $ipState['ok'] = false;
            }
        }

        $after = self::status(
            $limit,
            $ipState['ok'] ? self::ipState($db, $ip, [], $window) : $ipState,
            self::sessionState($session, [], $window, $now),
            false
        );
        // 'allowed'/'repeat' describe THIS lookup (it was allowed and is now
        // recorded); used/remaining describe the counters after it.
        $after['allowed'] = true;
        $after['repeat'] = $isRepeat;
        return $after;
    }

    // ── Rendering helpers (pure: return escaped HTML) ───────────────────

    /** "about 3 hours" style text for a number of seconds. */
    public static function humanDuration(?int $seconds): string {
        if ($seconds === null) {
            return 'within 24 hours';
        }
        $seconds = max(60, $seconds);
        if ($seconds < 3600) {
            $m = (int)ceil($seconds / 60);
            return 'in about ' . $m . ' minute' . ($m === 1 ? '' : 's');
        }
        $h = (int)ceil($seconds / 3600);
        return 'in about ' . $h . ' hour' . ($h === 1 ? '' : 's');
    }

    /** Prominent "limit reached" card with login / register buttons. */
    public static function renderLimitNotice(array $st): string {
        $limit = (int)($st['limit'] ?? self::limit());
        $e = static fn($v) => htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');
        return '<section class="card guest-quota-limit text-center" role="alert" aria-labelledby="guestQuotaTitle">'
            . '<h2 id="guestQuotaTitle">Free verification limit reached</h2>'
            . '<p class="guest-quota-message">Free verification limit reached — you\'ve used all '
            . $e($limit) . ' free verifications. Log in or create a free account to keep verifying certificates.</p>'
            . '<p class="btn-row guest-quota-actions">'
            . '<a class="btn btn-primary" href="login.php">Log in</a> '
            . '<a class="btn btn-secondary" href="register_student.php">Create a free account</a>'
            . '</p>'
            . '<p class="text-muted small guest-quota-reset">Your free verifications reset '
            . $e(self::humanDuration($st['resets_in'] ?? null))
            . '. Signed-in users can verify without this limit.</p>'
            . '</section>';
    }

    /** Small unobtrusive counter; '' for exempt users or a disabled quota. */
    public static function renderCounter(array $st): string {
        if (empty($st['enabled']) || !empty($st['exempt'])) {
            return '';
        }
        $left = (int)$st['remaining'];
        $limit = (int)$st['limit'];
        return '<p class="guest-quota-counter text-muted small text-center" role="status">'
            . $left . ' of ' . $limit . ' free verification' . ($limit === 1 ? '' : 's') . ' left today — '
            . '<a href="login.php">log in</a> or <a href="register_student.php">register</a> for unlimited verifications.'
            . '</p>';
    }

    /** 429 + Retry-After for a blocked guest (headers only). */
    public static function sendLimitHeaders(array $st): void {
        if (headers_sent()) {
            return;
        }
        http_response_code(429);
        header('Retry-After: ' . max(60, (int)($st['resets_in'] ?? self::window())));
    }

    // ── Internals ───────────────────────────────────────────────────────

    private static function exemptStatus(int $limit): array {
        return [
            'enabled' => $limit > 0, 'exempt' => true, 'allowed' => true, 'repeat' => false,
            'used' => 0, 'limit' => $limit, 'remaining' => $limit, 'resets_in' => null, 'degraded' => false,
        ];
    }

    /** Unique, non-empty key hashes, order kept (first = credit key). */
    private static function hashes(array $keys): array {
        $out = [];
        foreach ($keys as $k) {
            $k = (string)$k;
            if ($k !== '') {
                $h = self::keyHash($k);
                if (!in_array($h, $out, true)) {
                    $out[] = $h;
                }
            }
        }
        return $out;
    }

    private static function windowSql(int $window): string {
        return 'DATE_SUB(NOW(), INTERVAL ' . (int)$window . ' SECOND)';
    }

    /**
     * Prune + read this IP's live state. On any DB error: ok=false, all
     * zeros (fail open).
     *
     * @return array{ok:bool, used:int, aliases:int, seen:string[], resets_in:?int}
     */
    private static function ipState($db, string $ip, array $hashes, int $window): array {
        $subject = self::subjectHash($ip);
        $w = self::windowSql($window);
        try {
            $db->prepare('DELETE FROM guest_verify_quota WHERE subject_hash = :s AND seen_at <= ' . $w)
               ->execute(['s' => $subject]);
            if (random_int(1, self::SWEEP_ONE_IN) === 1) {
                $db->exec('DELETE FROM guest_verify_quota WHERE seen_at <= ' . $w);
            }
            $st = $db->prepare('SELECT key_hash, is_credit,
                                       TIMESTAMPDIFF(SECOND, NOW(), DATE_ADD(seen_at, INTERVAL ' . (int)$window . ' SECOND)) AS ttl
                                FROM guest_verify_quota WHERE subject_hash = :s AND seen_at > ' . $w);
            $st->execute(['s' => $subject]);
            $used = 0; $aliases = 0; $seen = []; $ttls = [];
            foreach ($st->fetchAll(\PDO::FETCH_ASSOC) as $row) {
                if ((int)$row['is_credit'] === 1) {
                    $used++;
                    $ttls[] = max(0, (int)$row['ttl']);
                } else {
                    $aliases++;
                }
                if (in_array($row['key_hash'], $hashes, true)) {
                    $seen[] = $row['key_hash'];
                }
            }
            return ['ok' => true, 'used' => $used, 'aliases' => $aliases, 'seen' => $seen, 'ttls' => $ttls];
        } catch (\PDOException $e) {
            error_log('[CertiVault] Guest verify quota unavailable (migration 017 pending?) — failing open: ' . $e->getMessage());
            return ['ok' => false, 'used' => 0, 'aliases' => 0, 'seen' => [], 'ttls' => []];
        }
    }

    /** @return array{used:int, seen:string[], ttls:int[]} */
    private static function sessionState(array $session, array $hashes, int $window, int $now): array {
        $slot = is_array($session[self::SESSION_KEY] ?? null) ? $session[self::SESSION_KEY] : [];
        $used = 0; $seen = []; $ttls = [];
        foreach ($slot as $h => $entry) {
            $ts = (int)($entry[0] ?? 0);
            if ($now - $ts >= $window) {
                continue;
            }
            if ((int)($entry[1] ?? 0) === 1) {
                $used++;
                $ttls[] = max(0, $ts + $window - $now);
            }
            if (in_array((string)$h, $hashes, true)) {
                $seen[] = (string)$h;
            }
        }
        return ['used' => $used, 'seen' => $seen, 'ttls' => $ttls];
    }

    private static function pruneSession(array &$session, int $window, int $now): void {
        if (!isset($session[self::SESSION_KEY])) {
            return;
        }
        if (!is_array($session[self::SESSION_KEY])) {
            $session[self::SESSION_KEY] = [];
            return;
        }
        foreach ($session[self::SESSION_KEY] as $h => $entry) {
            if (!is_array($entry) || ($now - (int)($entry[0] ?? 0)) >= $window) {
                unset($session[self::SESSION_KEY][$h]);
            }
        }
    }

    /** Keep every credit, plus at most MAX_ALIAS_ROWS newest aliases. */
    private static function capSession(array $slot): array {
        $aliases = array_filter($slot, static fn($e) => (int)($e[1] ?? 0) === 0);
        if (count($aliases) <= self::MAX_ALIAS_ROWS) {
            return $slot;
        }
        uasort($aliases, static fn($a, $b) => ((int)$a[0]) <=> ((int)$b[0]));
        foreach (array_slice(array_keys($aliases), 0, count($aliases) - self::MAX_ALIAS_ROWS) as $drop) {
            unset($slot[$drop]);
        }
        return $slot;
    }

    /** Combine both counters: limited when EITHER is full. */
    private static function status(int $limit, array $ip, array $sess, bool $exempt): array {
        $used = max((int)$ip['used'], (int)$sess['used']);
        $repeat = !empty($ip['seen']) || !empty($sess['seen']);
        // When full, the reset is when the limiting counter(s) drop below
        // the limit: the oldest credit of each full counter expires.
        $resets = null;
        foreach ([$ip, $sess] as $c) {
            if ((int)$c['used'] >= $limit && !empty($c['ttls'])) {
                sort($c['ttls']);
                $t = $c['ttls'][max(0, (int)$c['used'] - $limit)];
                $resets = $resets === null ? $t : max($resets, $t);
            }
        }
        if ($resets === null) {
            $all = array_merge($ip['ttls'] ?? [], $sess['ttls'] ?? []);
            $resets = $all ? min($all) : null;
        }
        return [
            'enabled'   => true,
            'exempt'    => $exempt,
            'allowed'   => $repeat || $used < $limit,
            'repeat'    => $repeat,
            'used'      => min($used, $limit),
            'limit'     => $limit,
            'remaining' => max(0, $limit - $used),
            'resets_in' => $resets,
            'degraded'  => !($ip['ok'] ?? true),
        ];
    }
}
