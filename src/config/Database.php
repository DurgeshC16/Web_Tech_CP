<?php
// src/config/Database.php
require_once __DIR__ . '/config.php';

class Database {
    private static $instance = null;
    private $pdo;

    private function __construct() {
        try {
            $this->pdo = self::connect();
        } catch (\PDOException $e) {
            throw new \PDOException($e->getMessage(), (int)$e->getCode());
        }
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance->pdo;
    }

    /**
     * DSN for the configured server. $dbName === '' omits dbname= (server
     * level connection); null uses DB_NAME. DB_PORT is only added when set,
     * so the classic "localhost" setup keeps its exact old DSN.
     */
    public static function dsn(?string $dbName = null): string {
        $dbName = $dbName ?? DB_NAME;
        $dsn = 'mysql:host=' . DB_HOST;
        if (defined('DB_PORT') && (int)DB_PORT > 0) {
            $dsn .= ';port=' . (int)DB_PORT;
        }
        if ($dbName !== '') {
            $dsn .= ';dbname=' . $dbName;
        }
        return $dsn . ';charset=utf8mb4';
    }

    /**
     * PDO options, including TLS when DB_SSL_CA / DB_SSL_CA_PEM is set.
     * TLS always verifies the server certificate against that CA.
     */
    public static function options(array $extra = []): array {
        $options = [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ];
        $ca = self::sslCaFile();
        if ($ca !== null) {
            $options[PDO::MYSQL_ATTR_SSL_CA] = $ca;
            $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = true;
        }
        return $extra + $options;
    }

    /**
     * Path of the CA file to use, or null when TLS is not configured.
     * DB_SSL_CA (a path) wins; otherwise DB_SSL_CA_PEM (the PEM text) is
     * written ONCE to a content-addressed file in the temp directory.
     */
    public static function sslCaFile(): ?string {
        if (defined('DB_SSL_CA') && trim((string)DB_SSL_CA) !== '') {
            return trim((string)DB_SSL_CA);
        }
        if (!defined('DB_SSL_CA_PEM') || trim((string)DB_SSL_CA_PEM) === '') {
            return null;
        }
        $pem = self::normalizePem((string)DB_SSL_CA_PEM);
        $file = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR
            . 'certivault-db-ca-' . substr(hash('sha256', $pem), 0, 16) . '.pem';
        if (!is_file($file) || (string)@file_get_contents($file) !== $pem) {
            $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
            if (@file_put_contents($tmp, $pem) === false || !@rename($tmp, $file)) {
                @unlink($tmp);
                throw new \PDOException('Cannot write the database CA certificate to ' . $file);
            }
            @chmod($file, 0644);
        }
        return $file;
    }

    /**
     * Canonical PEM text for one or more certificates. Hosting dashboards
     * may store a pasted certificate with literal "\n" sequences, CRLF, or
     * line breaks collapsed into spaces; each BEGIN/END block is rebuilt
     * from its base64 body (64-character lines). Text without a
     * certificate block is returned trimmed (OpenSSL then reports it).
     */
    public static function normalizePem(string $pem): string {
        $pem = str_replace(['\\r\\n', '\\n', "\r\n", "\r"], "\n", trim($pem));
        if (!preg_match_all('/-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/s', $pem, $m)) {
            return $pem . "\n";
        }
        $out = '';
        foreach ($m[1] as $body) {
            $b64 = preg_replace('/[^A-Za-z0-9+\/=]/', '', $body);
            $out .= "-----BEGIN CERTIFICATE-----\n" . rtrim(chunk_split($b64, 64, "\n")) . "\n-----END CERTIFICATE-----\n";
        }
        return $out;
    }

    /**
     * Open a NEW connection with the application's session settings
     * (time zone + strict SQL mode). getInstance() uses this; boot scripts
     * call it directly to retry a temporarily unreachable server.
     */
    public static function connect(?string $dbName = null, array $extraOptions = []): PDO {
        try {
            $pdo = new PDO(self::dsn($dbName), DB_USER, DB_PASS, self::options($extraOptions));
        } catch (\PDOException $e) {
            // Re-throw without the original trace (it carries the password
            // as a constructor argument).
            throw new \PDOException($e->getMessage(), (int)$e->getCode());
        }

        // Align the MySQL session time zone with PHP's. Several queries
        // compare MySQL NOW()/CURRENT_TIMESTAMP against PHP time()
        // (OTP resend cooldown, login-lockout remaining, remember-me
        // expiry). On XAMPP the MySQL server often uses the OS zone
        // while PHP uses date.timezone, so those comparisons can skew
        // by the offset (observed: Europe/Berlin vs Asia/Calcutta).
        // date('P') is a fixed "+HH:MM"/"-HH:MM" value (never user
        // input). Numeric offsets work without MySQL tz tables.
        try {
            $pdo->exec("SET time_zone = '" . date('P') . "'");
        } catch (\PDOException $e) {
            // Non-fatal: keep the server default if the offset is
            // rejected, so the app still connects.
        }
        // Strict SQL mode for this session, as on a default MySQL 5.7+/
        // MariaDB 10.2.4+ server. XAMPP ships a non-strict my.ini, which
        // silently truncates or coerces invalid values; strict mode makes
        // local behaviour match production (invalid data -> error). The
        // explicit list also drops MySQL 8's ONLY_FULL_GROUP_BY/ANSI_QUOTES
        // defaults, so MariaDB and MySQL 8 behave alike.
        try {
            $pdo->exec("SET SESSION sql_mode = 'STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ZERO_IN_DATE,NO_ZERO_DATE,NO_ENGINE_SUBSTITUTION'");
        } catch (\PDOException $e) {
            // Non-fatal: keep the server default.
        }
        return $pdo;
    }
}
