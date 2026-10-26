<?php
// src/config/Database.php
require_once __DIR__ . '/config.php';

class Database {
    private static $instance = null;
    private $pdo;

    private function __construct() {
        try {
            $dsn = "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4";
            $options = [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ];
            $this->pdo = new PDO($dsn, DB_USER, DB_PASS, $options);

            // Align the MySQL session time zone with PHP's. Several queries
            // compare MySQL NOW()/CURRENT_TIMESTAMP against PHP time()
            // (OTP resend cooldown, login-lockout remaining, remember-me
            // expiry). On XAMPP the MySQL server often uses the OS zone
            // while PHP uses date.timezone, so those comparisons can skew
            // by the offset (observed: Europe/Berlin vs Asia/Calcutta).
            // date('P') is a fixed "+HH:MM"/"-HH:MM" value (never user
            // input). Numeric offsets work without MySQL tz tables.
            try {
                $this->pdo->exec("SET time_zone = '" . date('P') . "'");
            } catch (\PDOException $e) {
                // Non-fatal: keep the server default if the offset is
                // rejected, so the app still connects.
            }
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
}
