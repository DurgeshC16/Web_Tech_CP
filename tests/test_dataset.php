<?php
// tests/test_dataset.php
// scripts/generate_dataset.php — the dummy certificate dataset generator.
// Runs the real CLI script (as a child process) against the TEST database
// with a small population and checks: dry-run writes nothing, counts and
// accounts, every certificate verifies with its expected verdict through
// VerificationService, version chains / revocations carry the same DB
// effects as the app pages, the CSV outputs (bulk CSV parses cleanly with
// BulkIssueService), determinism, refusal to run twice, and that --reset
// removes ONLY dataset rows and files.

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/utils/validators.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/BulkIssueService.php';
require_once __DIR__ . '/../src/services/KeyPinService.php';

const T_DOMAIN = '@dataset.example.com';
const T_PEOPLE = 6;

$db = test_db();
$dbName = getenv('CV_TEST_DB') ?: 'certivault_test';
$script = realpath(__DIR__ . '/../scripts/generate_dataset.php');
$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cv_dataset_' . getmypid();
@mkdir($tmp, 0777, true);
$uploads = __DIR__ . '/../private_data/uploads/';
$qrDir = __DIR__ . '/../public/qrcodes/';

/** Run the generator; returns [exit code, combined output]. */
function t_gen(array $args, array $extraEnv = []): array
{
    global $script, $dbName;
    $env = array_merge(getenv(), $extraEnv);
    $env['CV_KEY_PINS_FILE'] = getenv('CV_KEY_PINS_FILE'); // same pin store as this process
    $env['CV_CERTIFICATE_TRANSPARENCY_ENABLED'] = '0';
    $cmd = array_merge([PHP_BINARY, $script, '--db=' . $dbName], $args);
    // Output goes to temp files, not pipes: on Windows, reading two pipes
    // one after the other can block forever (a full stderr pipe stalls the
    // child, or an inherited write handle never reports EOF) and hang the
    // whole suite. Files cannot deadlock.
    $o = tempnam(sys_get_temp_dir(), 'cvds');
    $e = tempnam(sys_get_temp_dir(), 'cvds');
    $p = proc_open($cmd, [0 => ['file', 'NUL', 'r'], 1 => ['file', $o, 'w'], 2 => ['file', $e, 'w']], $pipes, null, $env);
    if (!is_resource($p)) {
        @unlink($o);
        @unlink($e);
        return [-1, 'proc_open failed'];
    }
    $code = proc_close($p);
    $out = (string)file_get_contents($o) . (string)file_get_contents($e);
    @unlink($o);
    @unlink($e);
    return [$code, $out];
}

function t_counts($db): array
{
    $n = fn($sql) => (int)$db->query($sql)->fetchColumn();
    $ds = "RIGHT(u.email, " . strlen(T_DOMAIN) . ") = '" . T_DOMAIN . "'";
    return [
        'users_all' => $n('SELECT COUNT(*) FROM users'),
        'users_other' => $n("SELECT COUNT(*) FROM users u WHERE NOT ($ds)"),
        'inst_other' => $n("SELECT COUNT(*) FROM institutions i JOIN users u ON u.id = i.user_id WHERE NOT ($ds)"),
        'students_other' => $n("SELECT COUNT(*) FROM students s JOIN users u ON u.id = s.user_id WHERE NOT ($ds)"),
        'certs_all' => $n('SELECT COUNT(*) FROM certificates'),
        'ds_users' => $n("SELECT COUNT(*) FROM users u WHERE $ds"),
        'ds_students' => $n("SELECT COUNT(*) FROM students s JOIN users u ON u.id = s.user_id WHERE $ds"),
        'ds_inst' => $n("SELECT COUNT(*) FROM institutions i JOIN users u ON u.id = i.user_id WHERE $ds"),
        'ds_certs' => $n("SELECT COUNT(*) FROM certificates c JOIN students s ON s.id = c.student_id JOIN users u ON u.id = s.user_id WHERE $ds"),
    ];
}

/** Read a CSV written by the generator (strips the UTF-8 BOM). */
function t_csv(string $path): array
{
    $fh = fopen($path, 'r');
    $head = fgetcsv($fh, 0, ',', '"', '');
    $head[0] = preg_replace('/^\xEF\xBB\xBF/', '', (string)$head[0]);
    $rows = [];
    while (($r = fgetcsv($fh, 0, ',', '"', '')) !== false) {
        if ($r !== [null]) { $rows[] = array_combine($head, $r); }
    }
    fclose($fh);
    return [$head, $rows];
}

// A test database created before migration 007 still has the 20-char
// certificate_id; the dataset uses custom IDs, so bring the two columns
// up to the canonical schema (database/schema.sql: VARCHAR(64)).
foreach ([['certificates', 'certificate_id', 'VARCHAR(64) NOT NULL'], ['verification_logs', 'certificate_id_found', 'VARCHAR(64) NULL']] as [$tbl, $col, $def]) {
    $w = (int)$db->query("SELECT CHARACTER_MAXIMUM_LENGTH FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '$tbl' AND COLUMN_NAME = '$col'")->fetchColumn();
    if ($w > 0 && $w < 64) { $db->exec("ALTER TABLE $tbl MODIFY COLUMN $col $def"); }
}

// Leftovers from an interrupted earlier run would skew every count.
t_gen(['--reset']);

// Canary rows that --reset must never touch: a similar-looking domain and
// a certificate-holding student of a non-dataset institution.
$tag = bin2hex(random_bytes(4));
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "student", 1)')->execute(['e' => "canary-$tag@notdataset.example.com"]);
$canaryUid = (int)$db->lastInsertId();
$db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "Canary Person")')->execute(['u' => $canaryUid]);
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "student", 1)')->execute(['e' => "canary-$tag@example.com"]);
$canaryUid2 = (int)$db->lastInsertId();

$before = t_counts($db);
// Concurrent suites may add/remove their own fixtures in the shared test
// DB, so "untouched" is checked by id: everything non-dataset that
// existed before must still exist afterwards.
$keepUsers = array_map('intval', $db->query("SELECT id FROM users WHERE RIGHT(email, " . strlen(T_DOMAIN) . ") <> '" . T_DOMAIN . "'")->fetchAll(PDO::FETCH_COLUMN));
$keepCerts = array_map('intval', $db->query('SELECT id FROM certificates')->fetchAll(PDO::FETCH_COLUMN));
function t_still_there($db, string $table, array $ids): bool
{
    if (!$ids) { return true; }
    return (int)$db->query("SELECT COUNT(*) FROM $table WHERE id IN (" . implode(',', $ids) . ')')->fetchColumn() === count($ids);
}
$filesBefore = count(glob($uploads . '*') ?: []);

try {
    // ── Dry run writes nothing ────────────────────────────────────────
    [$code, $out] = t_gen(['--dry-run', '--people=' . T_PEOPLE, '--seed=7', '--out=' . $tmp . '/dry']);
    t_check('dry-run exits 0 and says so', $code === 0 && str_contains($out, 'DRY RUN'));
    t_check('dry-run created no dataset rows', t_counts($db)['ds_users'] === 0);
    t_check('dry-run wrote no files', !is_dir($tmp . '/dry') && count(glob($uploads . '*') ?: []) === $filesBefore);

    // Public demo password + signing-capable institutions: never in production.
    [$code, $out] = t_gen(['--people=' . T_PEOPLE, '--seed=7', '--out=' . $tmp . '/prod'], ['CV_ENV' => 'production']);
    t_check('generation refuses when CV_ENV=production', $code === 1 && str_contains($out, 'production')
        && t_counts($db)['ds_users'] === 0 && !is_dir($tmp . '/prod'));

    // ── Real generation ───────────────────────────────────────────────
    [$code, $out] = t_gen(['--people=' . T_PEOPLE, '--seed=7', '--out=' . $tmp . '/real']);
    t_check('generation exits 0', $code === 0);
    if ($code !== 0) {
        echo $out;
        throw new RuntimeException('generator failed — remaining checks skipped');
    }
    t_check('summary reports every certificate re-verified', (bool)preg_match('/Re-verified\s*:\s*(\d+)\/\1 match/', $out));
    $after = t_counts($db);
    t_check('6 dataset students created', $after['ds_students'] === T_PEOPLE);
    t_check('5 dataset institutions created', $after['ds_inst'] === 5);
    t_check('accounts = people + institution admins', $after['ds_users'] === T_PEOPLE + 5);
    t_check('non-dataset rows untouched by generation', t_still_there($db, 'users', $keepUsers) && t_still_there($db, 'certificates', $keepCerts));

    // Institutions: approved, one active key, pinned outside the DB.
    $insts = $db->query("SELECT i.id, i.name, i.status, u.is_verified, u.role, k.key_id, k.public_key, k.encrypted_private_key
        FROM institutions i JOIN users u ON u.id = i.user_id LEFT JOIN institution_keys k ON k.institution_id = i.id AND k.status = 'active'
        WHERE RIGHT(u.email, " . strlen(T_DOMAIN) . ") = '" . T_DOMAIN . "'")->fetchAll();
    KeyPinService::reset();
    t_check('institutions approved with verified admin accounts', count(array_filter($insts, fn($i) => $i['status'] === 'approved' && (int)$i['is_verified'] === 1 && $i['role'] === 'admin')) === 5);
    t_check('each institution has an active key whose private half round-trips',
        count(array_filter($insts, fn($i) => $i['key_id'] !== null && CryptoService::verifyKeyPair(CryptoService::decryptPrivateKey($i['encrypted_private_key']), $i['public_key']))) === 5);
    t_check('each institution key is pinned (match)', count(array_filter($insts, fn($i) => KeyPinService::check((int)$i['id'], (int)$i['key_id'], $i['public_key']) === 'match')) === 5);

    // Accounts: activated, documented strong password, reserved domain.
    $users = $db->query("SELECT email, password_hash, is_verified FROM users WHERE RIGHT(email, " . strlen(T_DOMAIN) . ") = '" . T_DOMAIN . "'")->fetchAll();
    t_check('demo password passes v_password_strong', v_password_strong('Demo@12345') === true);
    t_check('every dataset account is activated and accepts the demo password',
        count(array_filter($users, fn($u) => (int)$u['is_verified'] === 1 && password_verify('Demo@12345', $u['password_hash']))) === count($users));
    t_check('every dataset email passes v_email', count(array_filter($users, fn($u) => v_email($u['email']) === true)) === count($users));
    $students = $db->query("SELECT s.full_name, s.enrollment_number FROM students s JOIN users u ON u.id = s.user_id WHERE RIGHT(u.email, " . strlen(T_DOMAIN) . ") = '" . T_DOMAIN . "'")->fetchAll();
    t_check('names pass v_person_name and enrolment numbers are set',
        count(array_filter($students, fn($s) => v_person_name($s['full_name']) === true && $s['enrollment_number'] !== '')) === T_PEOPLE);

    // ── CSV outputs ───────────────────────────────────────────────────
    [$head, $certRows] = t_csv($tmp . '/real/certificates_dataset.csv');
    foreach (['certificate_id', 'holder_name', 'holder_email', 'enrollment_number', 'institution', 'title', 'issue_date', 'expiry_date', 'status', 'expected_verdict', 'verify_url', 'sha256'] as $col) {
        if (!in_array($col, $head, true)) { t_check("certificates CSV has column $col", false); }
    }
    t_check('certificates CSV has the required columns', count(array_intersect(['certificate_id', 'holder_name', 'holder_email', 'enrollment_number', 'institution', 'title', 'issue_date', 'expiry_date', 'status', 'expected_verdict', 'verify_url', 'sha256'], $head)) === 12);
    t_check('one CSV row per dataset certificate', count($certRows) === $after['ds_certs'] && count($certRows) >= T_PEOPLE);
    t_check('CSV contains no private key material', !preg_grep('/PRIVATE KEY|ENC1|CFG1/', file($tmp . '/real/certificates_dataset.csv')) && !preg_grep('/PRIVATE KEY/', file($tmp . '/real/institutions.csv')));

    // ── Every certificate verifies with its expected verdict ──────────
    $verdicts = [];
    $wrong = [];
    $tokenOk = 0;
    $filesOk = 0;
    foreach ($certRows as $r) {
        $row = VerificationService::findByCertificateId($db, $r['certificate_id']);
        $got = $row ? VerificationService::verify($db, $row)['verdict'] : 'NOT FOUND';
        $verdicts[$got] = ($verdicts[$got] ?? 0) + 1;
        if ($got !== $r['expected_verdict']) { $wrong[] = $r['certificate_id'] . " $got≠{$r['expected_verdict']}"; }
        if ($row && $r['verify_url'] === 'verify.php?token=' . $row['qr_token'] && $r['sha256'] === $row['sha256_hash']) { $tokenOk++; }
        if ($row && is_file($uploads . $row['file_path']) && strncmp((string)file_get_contents($uploads . $row['file_path'], false, null, 0, 4), '%PDF', 4) === 0
            && is_file($qrDir . $row['qr_token'] . '.png') && hash_file('sha256', $uploads . $row['file_path']) === $row['file_sha256']) { $filesOk++; }
    }
    t_check('every certificate gives its expected verdict' . ($wrong ? ' (' . implode(', ', $wrong) . ')' : ''), !$wrong);
    foreach (['VALID', 'REVOKED', 'SUPERSEDED', 'EXPIRED'] as $v) {
        t_check("at least one $v certificate", ($verdicts[$v] ?? 0) >= 1);
    }
    t_check('verify_url + sha256 columns match the database', $tokenOk === count($certRows));
    t_check('every certificate has its signed PDF + QR image on disk', $filesOk === count($certRows));

    // Revocation / supersede carry the same DB effects as the app pages.
    $rev = $db->query("SELECT c.revocation_reason, c.revoked_at, c.revoked_by, i.user_id FROM certificates c JOIN institutions i ON i.id = c.institution_id
        JOIN users u ON u.id = i.user_id WHERE c.status = 'revoked' AND RIGHT(u.email, " . strlen(T_DOMAIN) . ") = '" . T_DOMAIN . "'")->fetchAll();
    t_check('revocations record reason, time and the institution admin', $rev && count(array_filter($rev, fn($r) => strlen((string)$r['revocation_reason']) >= 10 && $r['revoked_at'] !== null && (int)$r['revoked_by'] === (int)$r['user_id'])) === count($rev));
    $sup = $db->query("SELECT o.id, o.superseded_by_id, n.id AS new_id, n.previous_version_id, n.version, n.status AS new_status
        FROM certificates o JOIN certificates n ON n.id = o.superseded_by_id JOIN institutions i ON i.id = o.institution_id
        JOIN users u ON u.id = i.user_id WHERE o.status = 'superseded' AND RIGHT(u.email, " . strlen(T_DOMAIN) . ") = '" . T_DOMAIN . "'")->fetchAll();
    t_check('superseded v1 links to v2 and v2 links back (version 2)',
        $sup && count(array_filter($sup, fn($s) => (int)$s['previous_version_id'] === (int)$s['id'] && (int)$s['version'] === 2 && $s['new_status'] === 'active')) === count($sup));

    // people.csv / institutions.csv
    [, $people] = t_csv($tmp . '/real/people.csv');
    t_check('people.csv has one row per person', count($people) === T_PEOPLE);
    t_check('people.csv certificate counts add up', array_sum(array_column($people, 'certificate_count')) === count($certRows));
    [, $instCsv] = t_csv($tmp . '/real/institutions.csv');
    t_check('institutions.csv lists 5 institutions with key fingerprints', count($instCsv) === 5 && count(array_filter($instCsv, fn($i) => preg_match('/^[0-9A-F]{2}(:[0-9A-F]{2}){31}$/', $i['public_key_fingerprint_sha256']))) === 5);

    // bulk_issue_100.csv parses with the real bulk-issue parser, no errors.
    $bulk = $tmp . '/real/bulk_issue_100.csv';
    [$bulkRows, $fatal] = BulkIssueService::parseCsv($db, $bulk, 'bulk_issue_100.csv', filesize($bulk));
    t_check('bulk CSV accepted by BulkIssueService::parseCsv', $fatal === null);
    t_check('bulk CSV: one valid row per person', count($bulkRows) === T_PEOPLE && !array_filter($bulkRows, fn($r) => $r['errors']));
    t_check('bulk CSV header is exactly the template header', str_starts_with(preg_replace('/^\xEF\xBB\xBF/', '', (string)file_get_contents($bulk)),
        implode(',', array_merge(BulkIssueService::REQUIRED, BulkIssueService::OPTIONAL)) . "\n"));

    // ── Determinism: the plan-only CSVs match the real run ────────────
    [$code] = t_gen(['--csv-only', '--people=' . T_PEOPLE, '--seed=7', '--out=' . $tmp . '/plan']);
    t_check('csv-only exits 0', $code === 0);
    t_check('same seed → identical people.csv and bulk CSV',
        file_get_contents($tmp . '/plan/people.csv') === file_get_contents($tmp . '/real/people.csv')
        && file_get_contents($tmp . '/plan/bulk_issue_100.csv') === file_get_contents($bulk));
    [$code] = t_gen(['--csv-only', '--people=' . T_PEOPLE, '--seed=8', '--out=' . $tmp . '/plan8']);
    t_check('a different seed gives a different dataset', file_get_contents($tmp . '/plan8/people.csv') !== file_get_contents($tmp . '/real/people.csv'));

    // ── Re-running refuses instead of duplicating ────────────────────
    [$code, $out] = t_gen(['--people=' . T_PEOPLE, '--seed=7', '--out=' . $tmp . '/again']);
    t_check('second run refuses (exit 2) with a clear message', $code === 2 && str_contains($out, 'already exists') && str_contains($out, '--reset'));
    $again = t_counts($db);
    t_check('second run changed nothing', $again['ds_users'] === $after['ds_users'] && $again['ds_certs'] === $after['ds_certs']);

    [$code, $out] = t_gen(['--rest']);
    t_check('unknown option is rejected (no accidental run)', $code === 64);

    // ── Reset removes only the dataset ───────────────────────────────
    $dsFiles = $db->query("SELECT c.file_path, c.qr_token FROM certificates c JOIN students s ON s.id = c.student_id JOIN users u ON u.id = s.user_id
        WHERE RIGHT(u.email, " . strlen(T_DOMAIN) . ") = '" . T_DOMAIN . "'")->fetchAll();
    [$code, $out] = t_gen(['--reset']);
    $reset = t_counts($db);
    t_check('reset exits 0', $code === 0 && str_contains($out, 'Reset: removed'));
    t_check('reset removed every dataset row', $reset['ds_users'] === 0 && $reset['ds_inst'] === 0 && $reset['ds_students'] === 0 && $reset['ds_certs'] === 0);
    t_check('reset kept every non-dataset user and certificate', t_still_there($db, 'users', $keepUsers) && t_still_there($db, 'certificates', $keepCerts));
    $canary = $db->prepare('SELECT COUNT(*) FROM users WHERE id IN (:a, :b)');
    $canary->execute(['a' => $canaryUid, 'b' => $canaryUid2]);
    t_check('look-alike domain accounts untouched', (int)$canary->fetchColumn() === 2);
    t_check('reset deleted the dataset PDFs and QR images',
        $dsFiles && !array_filter($dsFiles, fn($f) => is_file($uploads . $f['file_path']) || is_file($qrDir . $f['qr_token'] . '.png')));
    [$code, $out] = t_gen(['--reset']);
    t_check('reset again is a harmless no-op', $code === 0 && str_contains($out, 'removed 0 dataset account'));
} catch (Throwable $e) {
    t_check('suite aborted: ' . $e->getMessage(), false);
} finally {
    t_gen(['--reset']);
    $db->prepare('DELETE FROM users WHERE id IN (:a, :b)')->execute(['a' => $canaryUid, 'b' => $canaryUid2]);
    foreach (glob($tmp . '/*/*') ?: [] as $f) { @unlink($f); }
    foreach (glob($tmp . '/*') ?: [] as $d) { @rmdir($d); }
    @rmdir($tmp);
}

exit(t_summary('test_dataset') ? 0 : 1);
