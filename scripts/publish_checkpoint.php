<?php
if (PHP_SAPI !== 'cli') { http_response_code(403); exit("CLI only.\n"); }
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/TransparencyLogService.php';
if (!CERTIFICATE_TRANSPARENCY_ENABLED) { fwrite(STDERR, "Enable CERTIFICATE_TRANSPARENCY_ENABLED in local config first.\n"); exit(1); }

try {
    $keyDir = dirname(TLOG_PRIVATE_KEY_FILE);
    if (!is_dir($keyDir) && !mkdir($keyDir, 0700, true) && !is_dir($keyDir)) throw new RuntimeException('Cannot create platform key directory.');
    $hasPrivate = is_file(TLOG_PRIVATE_KEY_FILE);
    $hasPublic = is_file(TLOG_PUBLIC_KEY_FILE);
    if (!$hasPrivate && !$hasPublic) {
        $pair = CryptoService::generateRSAKeyPair();
        if (file_put_contents(TLOG_PRIVATE_KEY_FILE, $pair['private_key'], LOCK_EX) === false
            || file_put_contents(TLOG_PUBLIC_KEY_FILE, $pair['public_key'], LOCK_EX) === false) throw new RuntimeException('Cannot persist platform signing key pair.');
        @chmod(TLOG_PRIVATE_KEY_FILE, 0600);
        @chmod(TLOG_PUBLIC_KEY_FILE, 0644);
        fwrite(STDERR, "Generated dedicated transparency signing key pair. Back up the private key securely.\n");
    } elseif (!$hasPrivate || !$hasPublic) {
        throw new RuntimeException('Only one platform key file exists; restore the matching pair rather than generating a replacement.');
    }
    $private = file_get_contents(TLOG_PRIVATE_KEY_FILE);
    $public = file_get_contents(TLOG_PUBLIC_KEY_FILE);
    if (!CryptoService::verifyKeyPair($private, $public)) throw new RuntimeException('Platform private/public key files do not match.');

    $db = Database::getInstance();
    $checkpoint = TransparencyLogService::checkpoint($db, $private, $public);
    $dir = __DIR__ . '/../public/checkpoints';
    if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) throw new RuntimeException('Cannot create public/checkpoints.');
    $json = json_encode($checkpoint, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR) . "\n";
    $tmp = $dir . '/latest.' . bin2hex(random_bytes(6)) . '.tmp';
    if (file_put_contents($tmp, $json, LOCK_EX) === false) throw new RuntimeException('Could not write temporary checkpoint JSON.');
    if (!@rename($tmp, $dir . '/latest.json')) {
        // Windows may refuse replacing an existing destination; use a locked
        // replacement as a compatibility fallback after staging the file.
        if (file_put_contents($dir . '/latest.json', $json, LOCK_EX) === false) throw new RuntimeException('Could not publish latest.json.');
        @unlink($tmp);
    }
    echo 'Published checkpoint tree_size=' . $checkpoint['tree_size'] . ' root=' . $checkpoint['root_hash'] . "\n";
    echo 'Public URL: ' . rtrim(BASE_URL, '/') . "/checkpoints/latest.json\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'Checkpoint publishing failed: ' . $e->getMessage() . "\n");
    exit(1);
}
