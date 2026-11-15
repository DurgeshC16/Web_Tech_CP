<?php
// scripts/backfill_file_hashes.php
// ─────────────────────────────────────────────────────────────────────
// One-off back-fill for migration 013: fills certificates.file_sha256 for
// rows issued before the column existed, so Smart Verify can match an
// uploaded original file.
//
// A file's hash is only recorded when the stored file still passes the
// canonical integrity check (it reproduces certificates.sha256_hash).
// Altered or missing files are skipped and listed, so a tampered file is
// never enrolled as "the original".
//
// Usage:  php scripts/backfill_file_hashes.php [--dry-run]
// Safe to re-run: only rows with file_sha256 IS NULL are touched.
// ─────────────────────────────────────────────────────────────────────

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit('This script must be run from the command line.');
}

require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/services/CryptoService.php';

$dryRun = in_array('--dry-run', $argv, true);
$db = Database::getInstance();

$hasCol = (int)$db->query("SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'certificates' AND COLUMN_NAME = 'file_sha256'")->fetchColumn();
if ($hasCol === 0) {
    fwrite(STDERR, "certificates.file_sha256 does not exist — apply database/migrations/013_certificate_file_hash.sql first.\n");
    exit(1);
}

$uploads = realpath(__DIR__ . '/../private_data/uploads');
$rows = $db->query('SELECT id, certificate_id, institution_id, student_id, title, issue_date, expiry_date,
                           file_path, sha256_hash
                    FROM certificates WHERE file_sha256 IS NULL ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);

$update = $db->prepare('UPDATE certificates SET file_sha256 = :h WHERE id = :id AND file_sha256 IS NULL');
$filled = 0;
$skipped = [];

foreach ($rows as $row) {
    $path = $uploads !== false ? $uploads . DIRECTORY_SEPARATOR . basename((string)$row['file_path']) : '';
    if ($path === '' || !is_file($path)) {
        $skipped[] = [$row['certificate_id'], 'file missing'];
        continue;
    }
    $canonical = CryptoService::computeCertificateHash($row, $path);
    if (empty($row['sha256_hash']) || !hash_equals((string)$row['sha256_hash'], $canonical)) {
        $skipped[] = [$row['certificate_id'], 'integrity check failed (file or fields altered)'];
        continue;
    }
    if (!$dryRun) {
        $update->execute(['h' => hash_file('sha256', $path), 'id' => $row['id']]);
    }
    $filled++;
}

printf("%s %d of %d certificate(s).\n", $dryRun ? 'Would back-fill' : 'Back-filled', $filled, count($rows));
foreach ($skipped as [$cid, $why]) {
    echo "  skipped $cid: $why\n";
}
exit(0);
