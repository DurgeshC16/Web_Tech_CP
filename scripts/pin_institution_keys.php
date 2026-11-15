<?php
// scripts/pin_institution_keys.php
// ─────────────────────────────────────────────────────────────────────
// Operator tool for signing-key fingerprint pins (see KeyPinService).
//
//   php scripts/pin_institution_keys.php            pin every key that has
//                                                    no pin yet (TOFU bootstrap
//                                                    for existing installs)
//   php scripts/pin_institution_keys.php --verify   compare every key in the
//                                                    DB with its pin; exit 1 on
//                                                    any mismatch or missing pin
//   php scripts/pin_institution_keys.php --export   print the pin set as JSON,
//                                                    to publish out of band
//
// Run the bootstrap ONCE on a database you trust (pins are never
// overwritten afterwards). Keep the pin file (KEY_PINS_FILE) on storage the
// web/database layer cannot write, and back it up.
// ─────────────────────────────────────────────────────────────────────

if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    exit('This script must be run from the command line.');
}

require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/services/KeyPinService.php';

$mode = $argv[1] ?? '';
$db = Database::getInstance();
$keys = $db->query('SELECT k.institution_id, k.key_id, k.public_key, k.status, i.name
                    FROM institution_keys k JOIN institutions i ON i.id = k.institution_id
                    ORDER BY k.institution_id, k.key_id')->fetchAll(PDO::FETCH_ASSOC);

if ($mode === '--export') {
    echo json_encode(['database' => DB_NAME, 'exported_at' => gmdate('c'), 'pins' => KeyPinService::all()],
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    exit(0);
}

if ($mode === '--verify') {
    $bad = 0;
    foreach ($keys as $k) {
        $r = KeyPinService::check((int)$k['institution_id'], (int)$k['key_id'], $k['public_key']);
        printf("%-8s institution %d (%s) key v%d [%s]\n", strtoupper($r), $k['institution_id'], $k['name'], $k['key_id'], $k['status']);
        if ($r !== 'match') {
            $bad++;
        }
    }
    echo $bad === 0 ? "All keys match their pins.\n" : "$bad key(s) unpinned or MISMATCHED.\n";
    exit($bad === 0 ? 0 : 1);
}

if ($mode !== '') {
    fwrite(STDERR, "Usage: php scripts/pin_institution_keys.php [--verify|--export]\n");
    exit(2);
}

$counts = ['pinned' => 0, 'exists' => 0, 'conflict' => 0];
foreach ($keys as $k) {
    $r = KeyPinService::pin((int)$k['institution_id'], (int)$k['key_id'], $k['public_key'], 'bootstrap');
    $counts[$r]++;
    if ($r === 'conflict') {
        fwrite(STDERR, "CONFLICT institution {$k['institution_id']} key v{$k['key_id']}: database key differs from its pin!\n");
    }
}
printf("Pin file: %s\nnew pins: %d, already pinned: %d, conflicts: %d\n",
    KeyPinService::file(), $counts['pinned'], $counts['exists'], $counts['conflict']);
exit($counts['conflict'] === 0 ? 0 : 1);
