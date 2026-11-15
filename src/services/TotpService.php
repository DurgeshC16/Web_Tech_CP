<?php
// src/services/TotpService.php
// ─────────────────────────────────────────────────────────────────────
// TOTP two-factor authentication (RFC 6238 over RFC 4226 HOTP), compatible
// with Google Authenticator, Microsoft Authenticator, Aegis, 1Password …
//   • HMAC-SHA1, 30-second steps, 6 digits, ±1 step clock tolerance
//   • replay protection: a code's time step must be newer than the last
//     accepted one (users.totp_last_step)
//   • secrets stored encrypted (CryptoService::encryptConfig, AES-256-GCM)
//   • 10 single-use recovery codes, stored only as HMAC-SHA-256 hashes
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/CryptoService.php';

class TotpService
{
    public const DIGITS = 6;
    public const PERIOD = 30;
    public const WINDOW = 1;           // accept the previous/next step too
    public const RECOVERY_CODES = 10;
    private const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    // ── RFC 4648 base32 ──────────────────────────────────────────────────
    public static function base32Encode(string $bin): string
    {
        $bits = '';
        foreach (str_split($bin) as $c) {
            $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 5) as $chunk) {
            $out .= self::B32[bindec(str_pad($chunk, 5, '0'))];
        }
        return $out;
    }

    public static function base32Decode(string $b32): string
    {
        $b32 = strtoupper(preg_replace('/[\s=-]/', '', $b32));
        if ($b32 === '' || strspn($b32, self::B32) !== strlen($b32)) {
            throw new InvalidArgumentException('Invalid base32 secret.');
        }
        $bits = '';
        foreach (str_split($b32) as $c) {
            $bits .= str_pad(decbin(strpos(self::B32, $c)), 5, '0', STR_PAD_LEFT);
        }
        $out = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $out .= chr(bindec($byte));
            }
        }
        return $out;
    }

    public static function generateSecret(): string
    {
        return self::base32Encode(random_bytes(20)); // 160-bit, as RFC 4226 recommends
    }

    /** HOTP value for a counter (RFC 4226 §5.3), `$digits` long. */
    public static function hotp(string $secretB32, int $counter, int $digits = self::DIGITS, string $algo = 'sha1'): string
    {
        $mac = hash_hmac($algo, pack('J', $counter), self::base32Decode($secretB32), true);
        $offset = ord($mac[strlen($mac) - 1]) & 0x0F;
        $bin = ((ord($mac[$offset]) & 0x7F) << 24) | ((ord($mac[$offset + 1]) & 0xFF) << 16)
             | ((ord($mac[$offset + 2]) & 0xFF) << 8) | (ord($mac[$offset + 3]) & 0xFF);
        return str_pad((string)($bin % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
    }

    public static function code(string $secretB32, ?int $time = null): string
    {
        return self::hotp($secretB32, intdiv($time ?? time(), self::PERIOD));
    }

    /**
     * Verify a code. Returns the matching time step, or null. A step must be
     * strictly greater than $lastStep (replay protection).
     */
    public static function verifyCode(string $secretB32, string $code, ?int $lastStep = null, ?int $time = null): ?int
    {
        $code = preg_replace('/\s+/', '', $code);
        if (!preg_match('/^\d{' . self::DIGITS . '}$/', $code)) {
            return null;
        }
        $now = intdiv($time ?? time(), self::PERIOD);
        for ($d = -self::WINDOW; $d <= self::WINDOW; $d++) {
            $step = $now + $d;
            if ($lastStep !== null && $step <= $lastStep) {
                continue;
            }
            if (hash_equals(self::hotp($secretB32, $step), $code)) {
                return $step;
            }
        }
        return null;
    }

    public static function otpauthUri(string $secretB32, string $account, string $issuer = 'CertiVault'): string
    {
        return 'otpauth://totp/' . rawurlencode($issuer . ':' . $account)
            . '?secret=' . $secretB32 . '&issuer=' . rawurlencode($issuer)
            . '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::PERIOD;
    }

    // ── Persistence ──────────────────────────────────────────────────────
    public static function enabledFor($db, int $userId): bool
    {
        try {
            $s = $db->prepare('SELECT totp_enabled FROM users WHERE id = :id');
            $s->execute(['id' => $userId]);
            return (int)$s->fetchColumn() === 1;
        } catch (PDOException $e) {
            return false; // migration 015 not applied: 2FA unavailable, never blocks login
        }
    }

    /** Enable 2FA after the user proved possession; returns fresh recovery codes. */
    public static function enable($db, int $userId, string $secretB32, int $acceptedStep): array
    {
        $db->beginTransaction();
        try {
            $db->prepare('UPDATE users SET totp_secret = :s, totp_enabled = 1, totp_last_step = :st WHERE id = :id')
               ->execute(['s' => CryptoService::encryptConfig($secretB32), 'st' => $acceptedStep, 'id' => $userId]);
            $codes = self::replaceRecoveryCodes($db, $userId);
            $db->commit();
            return $codes;
        } catch (Throwable $e) {
            if ($db->inTransaction()) { $db->rollBack(); }
            throw $e;
        }
    }

    public static function disable($db, int $userId): void
    {
        $db->prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = NULL WHERE id = :id')->execute(['id' => $userId]);
        $db->prepare('DELETE FROM user_recovery_codes WHERE user_id = :id')->execute(['id' => $userId]);
    }

    /**
     * Check a login code for a user with 2FA enabled: a TOTP code (replay-
     * safe, records the step) or an unused recovery code (consumed).
     * @return 'totp'|'recovery'|null
     */
    public static function verifyForUser($db, int $userId, string $input): ?string
    {
        $s = $db->prepare('SELECT totp_secret, totp_last_step FROM users WHERE id = :id AND totp_enabled = 1');
        $s->execute(['id' => $userId]);
        $row = $s->fetch();
        if (!$row || empty($row['totp_secret'])) {
            return null;
        }
        $input = trim($input);
        if (preg_match('/^\d{3}\s?\d{3}$/', $input)) {
            $secret = CryptoService::decryptConfig((string)$row['totp_secret']);
            $step = self::verifyCode($secret, $input, $row['totp_last_step'] === null ? null : (int)$row['totp_last_step']);
            if ($step === null) {
                return null;
            }
            // Conditional update closes the race between two parallel logins.
            $u = $db->prepare('UPDATE users SET totp_last_step = :st WHERE id = :id AND (totp_last_step IS NULL OR totp_last_step < :st2)');
            $u->execute(['st' => $step, 'st2' => $step, 'id' => $userId]);
            return $u->rowCount() === 1 ? 'totp' : null;
        }
        $hash = self::recoveryHash($input);
        $u = $db->prepare('UPDATE user_recovery_codes SET used_at = NOW() WHERE user_id = :id AND code_hash = :h AND used_at IS NULL LIMIT 1');
        $u->execute(['id' => $userId, 'h' => $hash]);
        return $u->rowCount() === 1 ? 'recovery' : null;
    }

    public static function remainingRecoveryCodes($db, int $userId): int
    {
        $s = $db->prepare('SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = :id AND used_at IS NULL');
        $s->execute(['id' => $userId]);
        return (int)$s->fetchColumn();
    }

    /** Replace a user's recovery codes; returns the plaintext codes (show once). */
    public static function replaceRecoveryCodes($db, int $userId): array
    {
        $db->prepare('DELETE FROM user_recovery_codes WHERE user_id = :id')->execute(['id' => $userId]);
        $ins = $db->prepare('INSERT INTO user_recovery_codes (user_id, code_hash) VALUES (:id, :h)');
        $codes = [];
        for ($i = 0; $i < self::RECOVERY_CODES; $i++) {
            $raw = strtolower(self::base32Encode(random_bytes(5))); // 8 chars
            $code = substr($raw, 0, 4) . '-' . substr($raw, 4, 4);
            $ins->execute(['id' => $userId, 'h' => self::recoveryHash($code)]);
            $codes[] = $code;
        }
        return $codes;
    }

    private static function recoveryHash(string $code): string
    {
        $norm = strtolower(preg_replace('/[\s-]/', '', $code));
        $pepper = defined('OTP_PEPPER') ? OTP_PEPPER : 'certivault';
        return hash_hmac('sha256', 'recovery:' . $norm, $pepper);
    }
}
