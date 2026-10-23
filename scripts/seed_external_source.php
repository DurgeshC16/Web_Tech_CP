<?php
// scripts/seed_external_source.php
// -------------------------------------------------------------------------
// OPTIONAL FEATURE (off by default). Seeds a small "public-style" external
// dataset so the external verification source demo works OFFLINE:
// a tiny SQLite database that RemoteDbAdapter can read via a read-only
// PDO connection. No MySQL credentials are needed for this demo source.
//
// Usage:   php scripts/seed_external_source.php
// Idempotent: recreates the SQLite file from scratch each run.
// Then point config.local.php at it (see printed instructions).
// -------------------------------------------------------------------------

if (php_sapi_name() !== 'cli') {
    die('CLI only.');
}
if (!extension_loaded('pdo_sqlite')) {
    fwrite(STDERR, "[!] The pdo_sqlite extension is not enabled (uncomment 'extension=pdo_sqlite' in php.ini).\n");
    exit(1);
}

$root = dirname(__DIR__);
$dir = $root . '/private_data/external_source';
if (!is_dir($dir) && !@mkdir($dir, 0770, true)) {
    fwrite(STDERR, "[!] Could not create $dir\n");
    exit(1);
}
$file = $dir . '/demo_external.sqlite';

// Idempotent: always rebuild from scratch.
@unlink($file);
$pdo = new PDO('sqlite:' . $file, null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);
chmod($file, 0444); // the app only ever needs to READ this file

$pdo->exec('CREATE TABLE external_certificates (
    certificate_id TEXT PRIMARY KEY,
    holder         TEXT NOT NULL,
    title          TEXT NOT NULL,
    issuer         TEXT NOT NULL,
    issue_date     TEXT NOT NULL,
    status         TEXT NOT NULL
)');

// Deliberately NON-CertiVault ID formats so the demo looks like a real
// external registry; one revoked row exercises the status display.
$sample = [
    ['REG-2024-001', 'Priya Raghavan', 'Diploma in Geographic Information Systems', 'State Survey Council', '2024-03-15', 'active'],
    ['REG-2024-002', 'Miguel Andrada', 'Advanced Water Quality Analysis', 'State Survey Council', '2024-06-02', 'active'],
    ['LIC-88231', 'Fatima Zahra Bouadi', 'Licensed Structural Engineer', 'Province Engineering Board', '2023-11-20', 'active'],
    ['SEA/MAR/2023/117', 'Daniel Okafor', 'Seafarer Certificate of Competency', 'Maritime Authority', '2023-08-14', 'revoked'],
    ['reg-2024-009', 'Hsiao-Lin Chen', 'Cartographic Data Management', 'State Survey Council', '2024-10-30', 'active'],
];
$stmt = $pdo->prepare('INSERT INTO external_certificates (certificate_id, holder, title, issuer, issue_date, status) VALUES (?,?,?,?,?,?)');
foreach ($sample as $row) {
    $stmt->execute($row);
}

echo "[+] Seeded external demo source: $file (read-only file)\n";
echo "    Sample lookup IDs: REG-2024-001, reg-2024-009 (case-insensitive),\n";
echo "                       SEA/MAR/2023/117 (revoked example), LIC-88231\n\n";
echo "Enable the feature in src/config/config.local.php:\n\n";
echo "    define('EXT_SOURCE_ENABLED', true);\n";
echo "    define('EXT_DB_DSN', 'sqlite:" . $file . "');\n";
echo "    define('EXT_DB_LABEL', 'Regional Registry (demo)');\n\n";
echo "Then verify an ID NOT present in CertiVault, e.g. REG-2024-001, on verify.php:\n";
echo "CertiVault shows INVALID locally plus a separate external-source card.\n";
