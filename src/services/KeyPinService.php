<?php
// src/services/KeyPinService.php
// ─────────────────────────────────────────────────────────────────────
// Institution signing-key fingerprint PINNING, stored OUTSIDE the database.
//
// Threat closed: an attacker who can write the database — including the
// institution_keys table — could replace an institution's public key,
// edit a certificate and re-sign it with their own key; every other check
// would pass (the paper's attack S6). Pinning records the SHA-256
// fingerprint of each key in an append-only file the application database
// cannot touch; verification refuses a key whose fingerprint differs.
//
// Model: trust on first use. A key is pinned when it is created (super
// admin approval, rotation, repair script, demo seed) or once for existing
// keys via `php scripts/pin_institution_keys.php`. A pin is NEVER
// overwritten by the application — a conflicting pin attempt is refused
// and logged. Put KEY_PINS_FILE on storage the web/DB layer cannot write,
// and publish `scripts/pin_institution_keys.php --export` out of band.
//
// check() results:
//   'match'    — fingerprint equals the pin            → verify normally
//   'mismatch' — key differs from its pin             → TAMPERED
//   'unpinned' — no pin for this key (yet)            → allowed, unless
//                KEY_PINNING_STRICT is true           → TAMPERED
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/CryptoService.php';

class KeyPinService
{
    private static ?array $cache = null;

    public static function file(): string
    {
        return defined('KEY_PINS_FILE') ? (string)KEY_PINS_FILE
            : __DIR__ . '/../../private_data/pins/' . preg_replace('/[^A-Za-z0-9_-]/', '_', defined('DB_NAME') ? DB_NAME : 'certivault') . '.json';
    }

    public static function strict(): bool
    {
        return defined('KEY_PINNING_STRICT') && KEY_PINNING_STRICT === true;
    }

    /** Test hook: forget the per-request cache (after the file changed). */
    public static function reset(): void
    {
        self::$cache = null;
    }

    private static function pinKey(int $institutionId, int $keyId): string
    {
        return $institutionId . ':' . $keyId;
    }

    /** @return array<string, array{fingerprint:string, pinned_at:string, source:string}> */
    public static function all(): array
    {
        if (self::$cache !== null) {
            return self::$cache;
        }
        $file = self::file();
        if (!is_file($file)) {
            return self::$cache = [];
        }
        $data = json_decode((string)file_get_contents($file), true);
        if (!is_array($data) || !isset($data['pins']) || !is_array($data['pins'])) {
            // A corrupt pin store must never silently disable pinning.
            error_log('[CertiVault] SECURITY: key pin file is unreadable: ' . $file);
            throw new RuntimeException('Key pin store is corrupt.');
        }
        return self::$cache = $data['pins'];
    }

    /**
     * 'match' | 'mismatch' | 'unpinned' for one certificate's signing key.
     * A missing public key counts as a mismatch when a pin exists.
     */
    public static function check(int $institutionId, int $keyId, ?string $publicKey): string
    {
        try {
            $pins = self::all();
        } catch (RuntimeException $e) {
            return 'mismatch'; // fail closed on a corrupt store
        }
        $pin = $pins[self::pinKey($institutionId, $keyId)] ?? null;
        if ($pin === null) {
            return 'unpinned';
        }
        if ($publicKey === null || trim($publicKey) === '') {
            return 'mismatch';
        }
        return hash_equals((string)$pin['fingerprint'], CryptoService::fingerprintPublicKey($publicKey))
            ? 'match' : 'mismatch';
    }

    /** True when verification may proceed with this key. */
    public static function acceptable(int $institutionId, int $keyId, ?string $publicKey): bool
    {
        $r = self::check($institutionId, $keyId, $publicKey);
        return $r === 'match' || ($r === 'unpinned' && !self::strict());
    }

    /**
     * Pin a key (append-only). Returns 'pinned' (new), 'exists' (same
     * fingerprint already pinned) or 'conflict' (a DIFFERENT fingerprint is
     * pinned — refused and logged; never overwritten).
     */
    public static function pin(int $institutionId, int $keyId, string $publicKey, string $source): string
    {
        $fingerprint = CryptoService::fingerprintPublicKey($publicKey);
        $file = self::file();
        $dir = dirname($file);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException('Cannot create key pin directory: ' . $dir);
        }
        $lock = fopen($file . '.lock', 'c');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            throw new RuntimeException('Cannot lock the key pin store.');
        }
        try {
            self::$cache = null;
            $pins = self::all();
            $k = self::pinKey($institutionId, $keyId);
            if (isset($pins[$k])) {
                if (hash_equals((string)$pins[$k]['fingerprint'], $fingerprint)) {
                    return 'exists';
                }
                error_log("[CertiVault] SECURITY: refused to re-pin institution key $k with a different fingerprint.");
                return 'conflict';
            }
            $pins[$k] = ['fingerprint' => $fingerprint, 'pinned_at' => gmdate('c'), 'source' => $source];
            ksort($pins, SORT_NATURAL);
            $json = json_encode(['version' => 1, 'pins' => $pins], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
            if (file_put_contents($tmp, $json . "\n") === false || !rename($tmp, $file)) {
                @unlink($tmp);
                throw new RuntimeException('Cannot write the key pin store.');
            }
            self::$cache = $pins;
            return 'pinned';
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** Pin a freshly created key; never throws (logs instead). */
    public static function pinQuietly(int $institutionId, int $keyId, string $publicKey, string $source): ?string
    {
        try {
            return self::pin($institutionId, $keyId, $publicKey, $source);
        } catch (Throwable $e) {
            error_log('[CertiVault] Key pinning failed for ' . $institutionId . ':' . $keyId . ' — ' . $e->getMessage());
            return null;
        }
    }
}
