<?php
// scripts/generate_dataset.php
// -------------------------------------------------------------------------
// Generates a realistic, reproducible DUMMY dataset: ~100 fictional people
// holding ~150-200 certificates from 5 fictional institutions.
//
// Everything goes through the application's REAL code paths, so every
// certificate verifies cryptographically exactly like a hand-issued one:
//   institutions  same provisioning as super_admin.php approval: RSA key
//                 pair → encrypted at rest → round-trip check → key v1 →
//                 fingerprint pinned outside the DB (KeyPinService)
//   certificates  IssuanceService::issue() (the pipeline shared by single
//                 and bulk issuance) with a generated PDF from
//                 CertificatePdfService (QR embedded) → canonical SHA-256 →
//                 RSA signature → transparency-log leaf (when enabled)
//   revocations   same DB effects as revoke_certificate.php (reason,
//                 revoked_at, revoked_by + REVOKE log event)
//   corrections   same DB effects as supersede_certificate.php (v2 linked
//                 to v1, v1 → superseded + SUPERSEDE log event)
// Afterwards every generated certificate is re-verified with
// VerificationService and must give its expected verdict.
//
// All dataset accounts use the reserved domain @dataset.example.com
// (RFC 2606: example.com can never belong to a real person). That domain
// is the marker --reset uses — nothing else is ever removed.
//
// Usage:
//   php scripts/generate_dataset.php [--people=100] [--seed=2026]
//       [--dry-run] [--csv-only] [--reset] [--out=DIR] [--db=NAME]
//       [--base-url=URL]
//
//   --people=N    number of people (1-500, default 100)
//   --seed=N      deterministic seed (default 2026): same seed + same N →
//                 same names, emails, courses, dates and certificate IDs
//   --dry-run     print the plan and pre-flight checks; write nothing
//   --csv-only    only write the CSV files from the plan (no database);
//                 verify_url / sha256 columns stay empty
//   --reset       remove ONLY a previously generated dataset (rows + PDF
//                 and QR files), then stop. Run again to regenerate.
//   --out=DIR     where the CSV files go (default docs/samples/dataset)
//   --db=NAME     target database (default: DB_NAME from config, or the
//                 CV_DB_NAME environment variable)
//   --base-url=U  base URL baked into the QR codes (same as CV_BASE_URL;
//                 default for CLI is http://localhost:8081)
//
// Re-running while a dataset exists refuses (exit code 2) instead of
// duplicating anything.
// -------------------------------------------------------------------------

if (php_sapi_name() !== 'cli') {
    // Writes accounts with a known demo password — never reachable over HTTP.
    http_response_code(403);
    exit('This script must be run from the command line.');
}

// ── Options (parsed BEFORE config loads: --db / --base-url feed it) ──
const DS_ALLOWED_OPTS = ['people', 'seed', 'dry-run', 'csv-only', 'reset', 'out', 'db', 'base-url', 'help'];
foreach (array_slice($argv, 1) as $arg) {
    // getopt() silently ignores unknown options; a typo such as --rest
    // must not turn into a full generation run.
    $name = preg_replace('/^--([a-z-]+).*$/', '$1', $arg);
    if (!str_starts_with($arg, '--') || !in_array($name, DS_ALLOWED_OPTS, true)) {
        fwrite(STDERR, "Unknown argument: $arg (see the header of scripts/generate_dataset.php)\n");
        exit(64);
    }
}
$opts = getopt('', ['people:', 'seed:', 'dry-run', 'csv-only', 'reset', 'out:', 'db:', 'base-url:', 'help']);
if (isset($opts['help'])) {
    $src = file_get_contents(__FILE__);
    preg_match('/\/\/ Usage:.*?(?=\/\/ -{10})/s', $src, $m);
    echo preg_replace('/^\/\/ ?/m', '', $m[0] ?? 'See the file header.');
    exit(0);
}
$PEOPLE = isset($opts['people']) ? (int)$opts['people'] : 100;
$SEED = isset($opts['seed']) ? (int)$opts['seed'] : 2026;
$DRY = isset($opts['dry-run']);
$CSV_ONLY = isset($opts['csv-only']);
$RESET = isset($opts['reset']);
if ($PEOPLE < 1 || $PEOPLE > 500 || (isset($opts['people']) && !ctype_digit((string)$opts['people']))) {
    fwrite(STDERR, "--people must be a whole number between 1 and 500.\n");
    exit(64);
}
if (isset($opts['seed']) && !preg_match('/^-?\d{1,9}$/', (string)$opts['seed'])) {
    fwrite(STDERR, "--seed must be an integer.\n");
    exit(64);
}
if ((int)$DRY + (int)$CSV_ONLY + (int)$RESET > 1) {
    fwrite(STDERR, "Use only one of --dry-run, --csv-only, --reset.\n");
    exit(64);
}

if (getenv('CV_ENV') === 'production' && !$DRY && !$CSV_ONLY && !$RESET) {
    // The dataset creates approved, signing-capable institution accounts
    // with a password published in the repo. On a production deployment
    // that is a ready-made way to forge "valid" certificates, so refuse.
    // (--reset stays allowed so an accidental dataset can be removed.)
    fwrite(STDERR, "Refusing to generate the demo dataset while CV_ENV=production (its accounts share a public password).\n");
    exit(1);
}

$dbOverride = $opts['db'] ?? (getenv('CV_DB_NAME') ?: null);
if ($dbOverride !== null) {
    if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', (string)$dbOverride)) {
        fwrite(STDERR, "--db must be a plain database name.\n");
        exit(64);
    }
    // Defined before config.php so config.local.php (which also uses
    // defined() guards) cannot silently point us at a different database.
    // KEY_PINS_FILE is derived from DB_NAME, so pins follow the database.
    define('DB_NAME', (string)$dbOverride);
}
if (isset($opts['base-url'])) {
    if (!preg_match('#^https?://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~/\-]*)?$#', (string)$opts['base-url'])) {
        fwrite(STDERR, "--base-url must look like http://host[:port][/path]\n");
        exit(64);
    }
    putenv('CV_BASE_URL=' . rtrim((string)$opts['base-url'], '/'));
}

if (!getenv('OPENSSL_CONF')) {
    // CLI on Windows often lacks the OpenSSL config path that Apache has;
    // without it openssl_pkey_new() (key generation) fails.
    foreach (['C:\\xampp\\php\\extras\\ssl\\openssl.cnf', 'C:\\xampp\\php\\extras\\openssl\\openssl.cnf', 'C:\\xampp\\apache\\conf\\openssl.cnf'] as $cnf) {
        if (is_file($cnf)) { putenv('OPENSSL_CONF=' . $cnf); break; }
    }
}

require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/utils/validators.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/KeyPinService.php';
require_once __DIR__ . '/../src/services/TransparencyLogService.php';
require_once __DIR__ . '/../src/services/IssuanceService.php';
require_once __DIR__ . '/../src/services/CertificatePdfService.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/BulkIssueService.php';

const DS_DOMAIN = 'dataset.example.com';     // RFC 2606 reserved — the dataset marker
const DS_PASSWORD = 'Demo@12345';            // documented demo password (passes v_password_strong)
const DS_PIN_SOURCE = 'generate_dataset';
const DS_FIRST_DAY = '2019-01-01';
const DS_LAST_DAY = '2026-10-31';            // clamped to today when run earlier

$ROOT = dirname(__DIR__);
$OUT = rtrim(str_replace('\\', '/', $opts['out'] ?? ($ROOT . '/docs/samples/dataset')), '/');
$TODAY = date('Y-m-d');

// ─────────────────────────────────────────────────────────────────────
// Fictional catalogue. Names are invented; any resemblance to a real
// institution is coincidental. 'home' institutions enrol students;
// the online academy only issues short courses.
// course: code, title, kind, years (programme length), valid (years of
// validity → expiry date; null = never expires), enr (enrolment code)
// ─────────────────────────────────────────────────────────────────────
function ds_institutions(): array
{
    return [
        'NBIT' => ['name' => 'Northbridge Institute of Technology', 'admin' => 'registrar.northbridge', 'home' => 32, 'courses' => [
            ['code' => 'BTCSE', 'title' => 'Bachelor of Technology in Computer Science and Engineering', 'kind' => 'degree', 'years' => 4, 'valid' => null, 'enr' => 'CS'],
            ['code' => 'BTECE', 'title' => 'Bachelor of Technology in Electronics and Communication Engineering', 'kind' => 'degree', 'years' => 4, 'valid' => null, 'enr' => 'EC'],
            ['code' => 'MTDS', 'title' => 'Master of Technology in Data Science', 'kind' => 'degree', 'years' => 2, 'valid' => null, 'enr' => 'DS'],
            ['code' => 'MCA', 'title' => 'Master of Computer Applications', 'kind' => 'degree', 'years' => 2, 'valid' => null, 'enr' => 'CA'],
            ['code' => 'CCF', 'title' => 'Certificate in Cloud Computing Fundamentals', 'kind' => 'certification', 'years' => 0, 'valid' => 3],
            ['code' => 'WSC', 'title' => 'Workshop on Secure Coding Practices', 'kind' => 'workshop', 'years' => 0, 'valid' => null],
            ['code' => 'INT', 'title' => 'Internship Completion - Embedded Systems Lab', 'kind' => 'internship', 'years' => 0, 'valid' => null],
        ]],
        'WSD' => ['name' => 'Westlake School of Design', 'admin' => 'registrar.westlake', 'home' => 20, 'courses' => [
            ['code' => 'BDCD', 'title' => 'Bachelor of Design in Communication Design', 'kind' => 'degree', 'years' => 4, 'valid' => null, 'enr' => 'CD'],
            ['code' => 'BDPD', 'title' => 'Bachelor of Design in Product Design', 'kind' => 'degree', 'years' => 4, 'valid' => null, 'enr' => 'PD'],
            ['code' => 'MDID', 'title' => 'Master of Design in Interaction Design', 'kind' => 'degree', 'years' => 2, 'valid' => null, 'enr' => 'ID'],
            ['code' => 'DUX', 'title' => 'Diploma in UI/UX Design', 'kind' => 'diploma', 'years' => 1, 'valid' => null, 'enr' => 'UX'],
            ['code' => 'TYP', 'title' => 'Workshop on Typography Fundamentals', 'kind' => 'workshop', 'years' => 0, 'valid' => null],
            ['code' => 'CMG', 'title' => 'Certificate in Motion Graphics', 'kind' => 'certification', 'years' => 0, 'valid' => null],
            ['code' => 'DTB', 'title' => 'Design Thinking Bootcamp', 'kind' => 'workshop', 'years' => 0, 'valid' => null],
        ]],
        'RCCM' => ['name' => 'Riverside College of Commerce and Management', 'admin' => 'registrar.riverside', 'home' => 26, 'courses' => [
            ['code' => 'MBAF', 'title' => 'Master of Business Administration (Finance)', 'kind' => 'degree', 'years' => 2, 'valid' => null, 'enr' => 'MB'],
            ['code' => 'BBA', 'title' => 'Bachelor of Business Administration', 'kind' => 'degree', 'years' => 3, 'valid' => null, 'enr' => 'BB'],
            ['code' => 'BCOMH', 'title' => 'Bachelor of Commerce (Honours)', 'kind' => 'degree', 'years' => 3, 'valid' => null, 'enr' => 'BC'],
            ['code' => 'PGDBA', 'title' => 'Post Graduate Diploma in Business Analytics', 'kind' => 'diploma', 'years' => 1, 'valid' => null, 'enr' => 'BA'],
            ['code' => 'CDM', 'title' => 'Certificate in Digital Marketing', 'kind' => 'certification', 'years' => 0, 'valid' => 2],
            ['code' => 'FMV', 'title' => 'Financial Modelling and Valuation Workshop', 'kind' => 'workshop', 'years' => 0, 'valid' => null],
            ['code' => 'CBC', 'title' => 'Certificate in Business Communication', 'kind' => 'certification', 'years' => 0, 'valid' => null],
        ]],
        'LIHS' => ['name' => 'Lakeview Institute of Health Sciences', 'admin' => 'registrar.lakeview', 'home' => 22, 'courses' => [
            ['code' => 'BSN', 'title' => 'Bachelor of Science in Nursing', 'kind' => 'degree', 'years' => 4, 'valid' => null, 'enr' => 'NS'],
            ['code' => 'BPT', 'title' => 'Bachelor of Physiotherapy', 'kind' => 'degree', 'years' => 4, 'valid' => null, 'enr' => 'PT'],
            ['code' => 'DMLT', 'title' => 'Diploma in Medical Laboratory Technology', 'kind' => 'diploma', 'years' => 2, 'valid' => null, 'enr' => 'ML'],
            ['code' => 'BLS', 'title' => 'Basic Life Support (BLS) Provider Certification', 'kind' => 'certification', 'years' => 0, 'valid' => 2],
            ['code' => 'ACLS', 'title' => 'Advanced Cardiac Life Support (ACLS) Provider Certification', 'kind' => 'certification', 'years' => 0, 'valid' => 2],
            ['code' => 'CMC', 'title' => 'Certificate in Medical Coding', 'kind' => 'certification', 'years' => 0, 'valid' => 3],
            ['code' => 'IPC', 'title' => 'Infection Prevention and Control Workshop', 'kind' => 'workshop', 'years' => 0, 'valid' => null],
        ]],
        'OSOA' => ['name' => 'Open Skills Online Academy', 'admin' => 'credentials.openskills', 'home' => 0, 'courses' => [
            ['code' => 'PYDS', 'title' => 'Python for Data Science', 'kind' => 'mooc', 'years' => 0, 'valid' => null],
            ['code' => 'MLF', 'title' => 'Machine Learning Foundations', 'kind' => 'mooc', 'years' => 0, 'valid' => null],
            ['code' => 'FSWD', 'title' => 'Full Stack Web Development', 'kind' => 'mooc', 'years' => 0, 'valid' => null],
            ['code' => 'ICS', 'title' => 'Introduction to Cybersecurity', 'kind' => 'mooc', 'years' => 0, 'valid' => null],
            ['code' => 'PME', 'title' => 'Project Management Essentials', 'kind' => 'certification', 'years' => 0, 'valid' => 3],
            ['code' => 'CPE', 'title' => 'Cloud Practitioner Essentials', 'kind' => 'certification', 'years' => 0, 'valid' => 3],
            ['code' => 'ASM', 'title' => 'Professional Certificate in Agile Scrum', 'kind' => 'certification', 'years' => 0, 'valid' => 2],
            ['code' => 'DVD', 'title' => 'Data Visualization and Dashboards', 'kind' => 'mooc', 'years' => 0, 'valid' => null],
        ]],
    ];
}

/** Name pools (weight = share of people). Only characters v_person_name accepts. */
function ds_name_pools(): array
{
    return [
        // Indian names, grouped by region/community so first and last
        // names combine plausibly.
        ['w' => 20, 'first' => ['Aarav', 'Vivaan', 'Aditya', 'Ishaan', 'Arjun', 'Rohan', 'Kabir', 'Ananya', 'Diya', 'Ishita', 'Priya',
            'Saanvi', 'Neha', 'Riya', 'Aditi', 'Pooja', 'Rahul', 'Vikram', 'Siddharth', 'Nikhil', 'Harsh', 'Tanvi', 'Shreya', 'Anjali', 'Yash'],
            'last' => ['Sharma', 'Verma', 'Gupta', 'Mehta', 'Agarwal', 'Chopra', 'Malhotra', 'Kapoor', 'Saxena', 'Trivedi', 'Pandey', 'Mishra', 'Patel', 'Joshi']],
        ['w' => 12, 'first' => ['Aniket', 'Mrunal', 'Tejas', 'Swati', 'Rutuja', 'Omkar', 'Sakshi', 'Gauri', 'Pranav', 'Shreyas', 'Sayali'],
            'last' => ['Kulkarni', 'Deshpande', 'Patil', 'Jadhav', 'Pawar', 'Chavan', 'Gokhale', 'Joshi', 'Deshmukh']],
        ['w' => 9, 'first' => ['Karthik', 'Lakshmi', 'Divya', 'Kavya', 'Meera', 'Sai', 'Arvind', 'Deepa', 'Vignesh', 'Srinivas'],
            'last' => ['Iyer', 'Nair', 'Reddy', 'Rao', 'Pillai', 'Menon', 'Naidu', 'Bhat', 'Krishnan']],
        ['w' => 5, 'first' => ['Arnav', 'Debolina', 'Sourav', 'Riddhi', 'Anirban', 'Payel'], 'last' => ['Banerjee', 'Chatterjee', 'Mukherjee', 'Das', 'Bose', 'Ghosh']],
        ['w' => 4, 'first' => ['Farhan', 'Zoya', 'Ayesha', 'Imran', 'Sameer', 'Sana'], 'last' => ['Khan', 'Shaikh', 'Qureshi', 'Ansari']],
        ['w' => 3, 'first' => ['Gurpreet', 'Harpreet', 'Manpreet', 'Jasleen', 'Arjan'], 'last' => ['Singh', 'Kaur', 'Gill', 'Sethi', 'Sandhu']],
        ['w' => 2, 'first' => ['Rhea', 'Neil', 'Sharon', 'Alan', 'Joanna'], 'last' => ['Fernandes', "D'Souza", 'Pereira', 'Rodrigues']],
        ['w' => 8, 'first' => ['Olivia', 'Liam', 'Noah', 'Ava', 'James', 'Emily', 'Ethan', 'Grace', 'Jack', 'Hannah'],
            'last' => ['Smith', 'Johnson', 'Brown', 'Taylor', 'Wilson', 'Davies', 'Evans', 'Thompson', 'Walker', "O'Brien"]],
        ['w' => 4, 'first' => ['Lukas', 'Felix', 'Jonas', 'Emma', 'Anna', 'Björn', 'Søren', 'Freya'],
            'last' => ['Müller', 'Schmidt', 'Weber', 'Andersson', 'Jensen', 'Larsen']],
        ['w' => 3, 'first' => ['Léa', 'Hugo', 'Chloé', 'Noémie', 'Zoë', 'Théo'], 'last' => ['Dubois', 'Lefèvre', 'Moreau', 'Laurent']],
        ['w' => 2, 'first' => ['Matteo', 'Giulia', 'Lorenzo', 'Chiara'], 'last' => ['Rossi', 'Bianchi', 'Romano', 'Ricci']],
        ['w' => 7, 'first' => ['José', 'María', 'Sofía', 'Mateo', 'Lucía', 'Diego', 'Valentina', 'Carlos', 'Camila', 'Andrés'],
            'last' => ['García', 'Martínez', 'Rodríguez', 'López', 'Hernández', 'Gómez', 'Fernández', 'Ruiz', 'Torres']],
        ['w' => 4, 'first' => ['Wei', 'Mei', 'Jia Hui', 'Hao', 'Xin'], 'last' => ['Chen', 'Wang', 'Li', 'Zhang', 'Liu']],
        ['w' => 3, 'first' => ['Hiroshi', 'Yuki', 'Haruto', 'Sakura', 'Aiko'], 'last' => ['Tanaka', 'Sato', 'Suzuki', 'Watanabe']],
        ['w' => 2, 'first' => ['Min-jun', 'Ji-woo', 'Seo-yeon', 'Ha-eun'], 'last' => ['Kim', 'Park', 'Lee', 'Choi']],
        ['w' => 2, 'first' => ['Linh', 'Minh', 'Anh', 'Duc'], 'last' => ['Nguyen', 'Tran', 'Pham', 'Le']],
        ['w' => 4, 'first' => ['Chidi', 'Amara', 'Kwame', 'Ama', 'Nia', 'Kofi'], 'last' => ['Okafor', 'Mensah', 'Adeyemi', 'Osei', 'Kamau']],
        ['w' => 3, 'first' => ['Tariq', 'Layla', 'Omar', 'Fatima', 'Yusuf', 'Noor'], 'last' => ['Haddad', 'Mansour', 'Khalil', 'Nasser']],
    ];
}

// ── Deterministic helpers (all randomness comes from mt_rand) ─────────
function ds_pick(array $a) { return $a[mt_rand(0, count($a) - 1)]; }

/** Weighted pick: $weights = [key => weight]. */
function ds_weighted(array $weights)
{
    $r = mt_rand(1, array_sum($weights));
    foreach ($weights as $k => $w) {
        if (($r -= $w) <= 0) { return $k; }
    }
    return array_key_last($weights);
}

function ds_shuffle(array $a): array
{
    for ($i = count($a) - 1; $i > 0; $i--) {
        $j = mt_rand(0, $i);
        [$a[$i], $a[$j]] = [$a[$j], $a[$i]];
    }
    return $a;
}

function ds_rand_date(string $from, string $to): string
{
    $a = strtotime($from);
    $b = strtotime($to);
    if ($b < $a) { $b = $a; }
    return date('Y-m-d', $a + 86400 * mt_rand(0, (int)(($b - $a) / 86400)));
}

function ds_add_years(string $date, int $years): string
{
    return date('Y-m-d', strtotime("$date +$years years"));
}

/** ASCII e-mail local part from a display name ("Søren D'Souza" → "soren.dsouza"). */
function ds_slug(string $s): string
{
    $map = ['à' => 'a', 'á' => 'a', 'â' => 'a', 'ä' => 'a', 'å' => 'a', 'ç' => 'c', 'è' => 'e', 'é' => 'e', 'ê' => 'e', 'ë' => 'e',
        'ì' => 'i', 'í' => 'i', 'î' => 'i', 'ï' => 'i', 'ñ' => 'n', 'ò' => 'o', 'ó' => 'o', 'ô' => 'o', 'ö' => 'o', 'ø' => 'o',
        'ù' => 'u', 'ú' => 'u', 'û' => 'u', 'ü' => 'u', 'ý' => 'y', 'ÿ' => 'y'];
    $s = strtr(mb_strtolower($s, 'UTF-8'), $map);
    return preg_replace('/[^a-z0-9]+/', '', $s);
}

/** Introduce one realistic typo (two adjacent letters swapped in the longest word). */
function ds_typo(string $title): string
{
    $words = explode(' ', $title);
    $longest = 0;
    foreach ($words as $i => $w) {
        if (strlen($w) > strlen($words[$longest])) { $longest = $i; }
    }
    $w = $words[$longest];
    if (strlen($w) >= 5) {
        $p = (int)(strlen($w) / 2);
        $words[$longest] = substr($w, 0, $p - 1) . $w[$p] . $w[$p - 1] . substr($w, $p + 1);
    }
    $typo = implode(' ', $words);
    return $typo !== $title ? $typo : $title . ' Programme';
}

/** VALID / REVOKED / SUPERSEDED / EXPIRED as of $today (mirrors VerificationService). */
function ds_expected_verdict(string $state, ?string $expiry, string $today): string
{
    if ($state === 'revoked') { return 'REVOKED'; }
    if ($state === 'superseded') { return 'SUPERSEDED'; }
    if ($expiry !== null && $expiry !== '' && strtotime($expiry) < strtotime($today)) { return 'EXPIRED'; }
    return 'VALID';
}

// ─────────────────────────────────────────────────────────────────────
// The plan: a pure function of (people, seed, cutoff day). No DB access.
// ─────────────────────────────────────────────────────────────────────
function ds_plan(int $people, int $seed, string $today): array
{
    mt_srand($seed);
    $insts = ds_institutions();
    $pools = ds_name_pools();
    $cutoff = min($today, DS_LAST_DAY);
    $homeWeights = [];
    foreach ($insts as $code => $i) {
        if ($i['home'] > 0) { $homeWeights[$code] = $i['home']; }
    }
    $poolWeights = array_map(fn($p) => $p['w'], $pools);

    $persons = [];
    $certs = [];
    $usedNames = [];
    $usedEmails = [];
    $enrSeq = [];
    for ($p = 1; $p <= $people; $p++) {
        // Unique, plausible full name (fall back to a middle initial).
        $name = '';
        for ($try = 0; $try < 40; $try++) {
            $pool = $pools[ds_weighted($poolWeights)];
            $first = ds_pick($pool['first']);
            $last = ds_pick($pool['last']);
            $name = "$first $last";
            if (!isset($usedNames[$name])) { break; }
            if ($try >= 20) {
                // Pools exhausted for this draw: a middle initial keeps it unique.
                $name = $first . ' ' . chr(65 + mt_rand(0, 25)) . '. ' . $last;
                if (!isset($usedNames[$name])) { break; }
            }
        }
        $usedNames[$name] = true;
        $local = ds_slug($first) . '.' . ds_slug($last);
        $email = $local . '@' . DS_DOMAIN;
        for ($n = 2; isset($usedEmails[$email]); $n++) {
            $email = $local . $n . '@' . DS_DOMAIN;
        }
        $usedEmails[$email] = true;

        $home = ds_weighted($homeWeights);
        $programmes = array_values(array_filter($insts[$home]['courses'], fn($c) => in_array($c['kind'], ['degree', 'diploma'], true)));
        $prog = ds_pick($programmes);
        $graduated = mt_rand(1, 100) <= 80;
        if ($graduated) {
            $gradYear = mt_rand(2019, (int)substr($cutoff, 0, 4));
            $gradDate = min($cutoff, ds_rand_date("$gradYear-06-01", "$gradYear-08-31"));
            $admission = $gradYear - max(1, $prog['years']);
        } else {
            // Currently enrolled: no degree yet, only short courses.
            $admission = mt_rand(max(2019, (int)substr($cutoff, 0, 4) - 3), (int)substr($cutoff, 0, 4) - 1);
            $gradDate = null;
        }
        $key = $home . $prog['enr'] . $admission;
        $enrSeq[$key] = ($enrSeq[$key] ?? 0) + 1;
        $enrollment = sprintf('%s%02d%s%03d', $home, $admission % 100, $prog['enr'], $enrSeq[$key]);

        $person = ['pid' => sprintf('P%03d', $p), 'name' => $name, 'email' => $email, 'enrollment' => $enrollment,
            'home' => $home, 'programme' => $prog['title'], 'graduated' => $graduated, 'certs' => []];
        $want = (int)ds_weighted([1 => 40, 2 => 45, 3 => 15]);
        $given = [];
        if ($graduated) {
            $certs[] = ['person' => $p - 1, 'inst' => $home, 'course' => $prog, 'issue' => $gradDate];
            $given[$home . $prog['code']] = true;
        }
        $from = max(DS_FIRST_DAY, "$admission-08-01");
        for ($guard = 0; count($given) < $want && $guard < 30; $guard++) {
            $src = ds_weighted(['home' => 50, 'online' => 35, 'other' => 15]);
            $inst = $src === 'home' ? $home : ($src === 'online' ? 'OSOA' : ds_pick(array_values(array_diff(array_keys($homeWeights), [$home]))));
            $short = array_values(array_filter($insts[$inst]['courses'], fn($c) => !in_array($c['kind'], ['degree', 'diploma'], true)));
            $course = ds_pick($short);
            if (isset($given[$inst . $course['code']])) { continue; }
            $given[$inst . $course['code']] = true;
            $issueFrom = $from <= $cutoff ? $from : date('Y-m-d', strtotime("$cutoff -60 days"));
            $certs[] = ['person' => $p - 1, 'inst' => $inst, 'course' => $course, 'issue' => ds_rand_date($issueFrom, $cutoff)];
        }
        $persons[] = $person;
    }

    // Expiry from the course validity; state defaults to active.
    foreach ($certs as &$c) {
        $c['expiry'] = $c['course']['valid'] ? date('Y-m-d', strtotime(ds_add_years($c['issue'], $c['course']['valid']) . ' -1 day')) : null;
        $c['title'] = $c['course']['title'];
        $c['state'] = 'active';
    }
    unset($c);

    // A realistic minority of corrections and revocations (at least one
    // each so even a tiny dataset exercises every verdict).
    $total = count($certs);
    $nSup = max(1, (int)round($total * 0.03));
    $nRev = max(1, (int)round($total * 0.04));
    $order = ds_shuffle(range(0, $total - 1));
    usort($order, fn($a, $b) => (int)!in_array($certs[$a]['course']['kind'], ['degree', 'diploma'], true)
        <=> (int)!in_array($certs[$b]['course']['kind'], ['degree', 'diploma'], true)); // corrections mostly on degrees
    foreach (array_slice($order, 0, min($nSup, $total)) as $i) {
        $certs[$i]['state'] = 'superseded';
    }
    $reasons = [
        'Issued in error: duplicate of an earlier certificate for the same course.',
        'Course requirements were not completed; certificate was issued prematurely.',
        'Revoked following an academic integrity investigation (committee ref. AIC-%d).',
        'Learner withdrew before the final assessment; certificate withdrawn.',
        'Assessment results were annulled after an examination board review.',
    ];
    $revocable = array_values(array_filter(ds_shuffle(range(0, $total - 1)), fn($i) => $certs[$i]['state'] === 'active'));
    foreach (array_slice($revocable, 0, $nRev) as $i) {
        $certs[$i]['state'] = 'revoked';
        $certs[$i]['reason'] = sprintf(ds_pick($reasons), mt_rand(100, 999));
        $at = date('Y-m-d', strtotime($certs[$i]['issue'] . ' +' . mt_rand(15, 400) . ' days'));
        $certs[$i]['revoked_at'] = min($at, $today) . sprintf(' %02d:%02d:00', mt_rand(9, 17), mt_rand(0, 59));
    }

    // Guarantee at least one naturally EXPIRED certificate.
    $hasExpired = false;
    foreach ($certs as $c) {
        if ($c['state'] === 'active' && ds_expected_verdict('active', $c['expiry'], $today) === 'EXPIRED') { $hasExpired = true; break; }
    }
    if (!$hasExpired && $total > 1) {
        $cands = array_values(array_filter(range(0, $total - 1), fn($i) => $certs[$i]['state'] === 'active'));
        usort($cands, fn($a, $b) => (int)($certs[$a]['course']['valid'] === null) <=> (int)($certs[$b]['course']['valid'] === null)
            ?: (int)in_array($certs[$a]['course']['kind'], ['degree', 'diploma'], true) <=> (int)in_array($certs[$b]['course']['kind'], ['degree', 'diploma'], true)
            ?: $a <=> $b);
        if ($cands) {
            $i = $cands[0];
            $valid = $certs[$i]['course']['valid'] ?: 1;
            $latest = date('Y-m-d', strtotime("$today -$valid years -45 days"));
            $certs[$i]['issue'] = ds_rand_date(min(DS_FIRST_DAY, $latest), $latest);
            $certs[$i]['expiry'] = date('Y-m-d', strtotime(ds_add_years($certs[$i]['issue'], $valid) . ' -1 day'));
        }
    }

    // Certificate IDs: <INST>/<YEAR>/<COURSE>/<NNNN>, numbered per
    // institution + year in issue-date order (custom IDs are a supported
    // app feature; the CV-YYYY-NNNNNN namespace stays for auto IDs).
    $idx = range(0, $total - 1);
    usort($idx, fn($a, $b) => strcmp($certs[$a]['issue'], $certs[$b]['issue']) ?: $a <=> $b);
    $seq = [];
    foreach ($idx as $i) {
        $y = substr($certs[$i]['issue'], 0, 4);
        $k = $certs[$i]['inst'] . $y;
        $seq[$k] = ($seq[$k] ?? 0) + 1;
        $certs[$i]['id'] = sprintf('%s/%s/%s/%04d', $certs[$i]['inst'], $y, $certs[$i]['course']['code'], $seq[$k]);
    }

    // Corrections: the original (v1) carried a typo in the title; v2 is the
    // corrected re-issue with the same award dates.
    $final = [];
    foreach ($idx as $i) {
        $c = $certs[$i];
        $c['version'] = 1;
        $c['previous'] = null;
        if ($c['state'] === 'superseded') {
            $correct = $c['title'];
            $c['title'] = ds_typo($correct);
            $final[] = $c;
            $v2 = $c;
            $v2['id'] = $c['id'] . '-V2';
            $v2['title'] = $correct;
            $v2['state'] = 'active';
            $v2['version'] = 2;
            $v2['previous'] = $c['id'];
            $final[] = $v2;
        } else {
            $final[] = $c;
        }
    }
    foreach ($final as $c) {
        $persons[$c['person']]['certs'][] = $c['id'];
    }

    // bulk_issue_100.csv: one new certificate per person in the exact
    // public/bulk_issue.php format (certificate_id blank = automatic ID,
    // so the file can be uploaded any number of times).
    $events = [
        ['Guest Lecture Series 2026 - Certificate of Participation', null],
        ['Annual Technical Symposium 2026 - Participation', null],
        ['Workshop on Generative AI Tools for Professionals', null],
        ['Inter-College Coding Contest 2026 - Certificate of Merit', null],
        ['Community Outreach Volunteer Programme 2026', null],
        ['Research Methodology Short Course', null],
        ['First Aid and Emergency Response Training', 2],
        ['Professional Ethics and Workplace Safety Module', 3],
    ];
    $bulk = [];
    $bulkFrom = min('2026-01-15', $cutoff);
    foreach ($persons as $person) {
        [$title, $valid] = ds_pick($events);
        $issue = ds_rand_date($bulkFrom, $cutoff);
        $bulk[] = [$person['email'], $person['name'], $title, $issue, $valid ? ds_add_years($issue, $valid) : '', ''];
    }

    return ['institutions' => $insts, 'people' => $persons, 'certs' => $final, 'bulk' => $bulk];
}

// ─────────────────────────────────────────────────────────────────────
// CSV output (same writer settings as BulkIssueService::sendCsv; UTF-8 BOM
// so spreadsheet apps show accented names correctly).
// ─────────────────────────────────────────────────────────────────────
function ds_write_csv(string $path, array $header, array $rows, bool $neutralise = true): void
{
    $fh = fopen($path, 'w');
    if ($fh === false) {
        throw new RuntimeException("Cannot write $path");
    }
    fwrite($fh, "\xEF\xBB\xBF");
    fputcsv($fh, $header, ',', '"', '');
    foreach ($rows as $r) {
        fputcsv($fh, $neutralise ? array_map([BulkIssueService::class, 'csvCell'], $r) : $r, ',', '"', '');
    }
    fclose($fh);
}

const DS_CERT_HEADER = ['certificate_id', 'version', 'previous_certificate_id', 'holder_name', 'holder_email', 'enrollment_number',
    'institution', 'title', 'credential_type', 'issue_date', 'expiry_date', 'status', 'expected_verdict', 'verdict_as_of',
    'revocation_reason', 'verify_url', 'sha256', 'file_sha256'];

/**
 * Write all CSV files. $db = null → plan only (no tokens/hashes).
 * @return array<string,int> file => data rows
 */
function ds_write_outputs(array $plan, string $out, string $today, $db = null): array
{
    if (!is_dir($out) && !mkdir($out, 0775, true) && !is_dir($out)) {
        throw new RuntimeException("Cannot create output directory $out");
    }
    $live = [];
    $keys = [];
    if ($db !== null) {
        $ids = array_column($plan['certs'], 'id');
        $in = implode(',', array_fill(0, count($ids), '?'));
        $st = $db->prepare("SELECT certificate_id, status, qr_token, sha256_hash, file_sha256, revocation_reason, expiry_date FROM certificates WHERE certificate_id IN ($in)");
        $st->execute($ids);
        foreach ($st->fetchAll() as $r) { $live[$r['certificate_id']] = $r; }
        $ks = $db->prepare('SELECT i.name, k.key_id, k.public_key FROM institutions i JOIN users u ON u.id = i.user_id
                            JOIN institution_keys k ON k.institution_id = i.id AND k.status = "active"
                            WHERE RIGHT(u.email, ' . (strlen(DS_DOMAIN) + 1) . ') = :d');
        $ks->execute(['d' => '@' . DS_DOMAIN]);
        foreach ($ks->fetchAll() as $r) { $keys[$r['name']] = $r; }
    }

    $rows = [];
    foreach ($plan['certs'] as $c) {
        $p = $plan['people'][$c['person']];
        $l = $live[$c['id']] ?? null;
        $status = $l ? (string)VerificationService::effectiveStatus(['status' => $l['status'], 'expiry_date' => $l['expiry_date']])
            : ($c['state'] === 'active' && ds_expected_verdict('active', $c['expiry'], $today) === 'EXPIRED' ? 'expired' : $c['state']);
        $rows[] = [$c['id'], $c['version'], $c['previous'] ?? '', $p['name'], $p['email'], $p['enrollment'],
            $plan['institutions'][$c['inst']]['name'], $c['title'], $c['course']['kind'], $c['issue'], $c['expiry'] ?? '',
            $status, ds_expected_verdict($c['state'], $c['expiry'], $today), $today, $c['reason'] ?? '',
            $l ? 'verify.php?token=' . $l['qr_token'] : '', $l['sha256_hash'] ?? '', $l['file_sha256'] ?? ''];
    }
    ds_write_csv("$out/certificates_dataset.csv", DS_CERT_HEADER, $rows);

    $people = [];
    foreach ($plan['people'] as $p) {
        $people[] = [$p['pid'], $p['name'], $p['email'], $p['enrollment'], $plan['institutions'][$p['home']]['name'],
            $p['programme'], $p['graduated'] ? 'graduated' : 'enrolled', count($p['certs']), implode('; ', $p['certs'])];
    }
    ds_write_csv("$out/people.csv", ['person_id', 'full_name', 'email', 'enrollment_number', 'home_institution', 'programme',
        'programme_status', 'certificate_count', 'certificate_ids'], $people);

    $inst = [];
    foreach ($plan['institutions'] as $code => $i) {
        $n = count(array_filter($plan['certs'], fn($c) => $c['inst'] === $code));
        $k = $keys[$i['name']] ?? null;
        $inst[] = [$code, $i['name'], $i['admin'] . '@' . DS_DOMAIN, $n, $k ? (int)$k['key_id'] : '',
            $k ? CryptoService::fingerprintPublicKey($k['public_key']) : ''];
    }
    ds_write_csv("$out/institutions.csv", ['code', 'institution', 'admin_email', 'certificates', 'active_key_id', 'public_key_fingerprint_sha256'], $inst);

    // Exact bulk_issue.php header; values are plain (no formula prefixes
    // possible), written unmodified so the upload round-trips.
    ds_write_csv("$out/bulk_issue_100.csv", array_merge(BulkIssueService::REQUIRED, BulkIssueService::OPTIONAL), $plan['bulk'], false);

    return ['certificates_dataset.csv' => count($rows), 'people.csv' => count($people), 'institutions.csv' => count($inst), 'bulk_issue_100.csv' => count($plan['bulk'])];
}

// ─────────────────────────────────────────────────────────────────────
// Database helpers
// ─────────────────────────────────────────────────────────────────────
function ds_suffix_sql(string $col): string
{
    return "RIGHT($col, " . (strlen(DS_DOMAIN) + 1) . ') = :dsdomain';
}

/** @return array{users:int, institutions:int, students:int, certificates:int} */
function ds_existing($db): array
{
    $q = function (string $sql) use ($db): int {
        $s = $db->prepare($sql);
        $s->execute(['dsdomain' => '@' . DS_DOMAIN]);
        return (int)$s->fetchColumn();
    };
    return [
        'users' => $q('SELECT COUNT(*) FROM users WHERE ' . ds_suffix_sql('email')),
        'institutions' => $q('SELECT COUNT(*) FROM institutions i JOIN users u ON u.id = i.user_id WHERE ' . ds_suffix_sql('u.email')),
        'students' => $q('SELECT COUNT(*) FROM students s JOIN users u ON u.id = s.user_id WHERE ' . ds_suffix_sql('u.email')),
        'certificates' => $q('SELECT COUNT(*) FROM certificates c JOIN students s ON s.id = c.student_id JOIN users u ON u.id = s.user_id WHERE ' . ds_suffix_sql('u.email')),
    ];
}

/**
 * Remove ONLY the dataset: accounts on @dataset.example.com (never a
 * super admin), the institutions/students they own, every certificate
 * those institutions issued or those students hold, their verification
 * log rows, and the matching PDF + QR files. Transparency-log entries and
 * key pins are append-only by design and are kept.
 */
function ds_reset($db, array $knownInstitutionNames): array
{
    $p = ['dsdomain' => '@' . DS_DOMAIN];
    $st = $db->prepare('SELECT id, role FROM users WHERE ' . ds_suffix_sql('email') . ' AND role <> "super_admin"');
    $st->execute($p);
    $users = $st->fetchAll();
    if (!$users) {
        return ['users' => 0, 'certificates' => 0, 'files' => 0, 'skipped' => []];
    }
    $uids = array_map('intval', array_column($users, 'id'));
    $inU = implode(',', $uids); // integers only

    // Safety net: an admin on the dataset domain whose institution is not
    // one of ours (renamed / created by hand) is left alone.
    $skipped = [];
    foreach ($db->query("SELECT i.id, i.name, i.user_id FROM institutions i WHERE i.user_id IN ($inU)")->fetchAll() as $r) {
        if (!in_array($r['name'], $knownInstitutionNames, true)) {
            $skipped[] = $r['name'];
            $uids = array_values(array_diff($uids, [(int)$r['user_id']]));
        }
    }
    if (!$uids) {
        return ['users' => 0, 'certificates' => 0, 'files' => 0, 'skipped' => $skipped];
    }
    $inU = implode(',', $uids);
    $instIds = array_map('intval', $db->query("SELECT id FROM institutions WHERE user_id IN ($inU)")->fetchAll(PDO::FETCH_COLUMN));
    $stuIds = array_map('intval', $db->query("SELECT id FROM students WHERE user_id IN ($inU)")->fetchAll(PDO::FETCH_COLUMN));
    $conds = [];
    if ($instIds) { $conds[] = 'institution_id IN (' . implode(',', $instIds) . ')'; }
    if ($stuIds) { $conds[] = 'student_id IN (' . implode(',', $stuIds) . ')'; }
    $certs = $conds ? $db->query('SELECT id, certificate_id, file_path, qr_token FROM certificates WHERE ' . implode(' OR ', $conds))->fetchAll() : [];
    $certIds = array_map('intval', array_column($certs, 'id'));

    if ($certIds) {
        // Never touch a non-dataset row: refuse if one links into the set.
        $inC = implode(',', $certIds);
        $foreign = (int)$db->query("SELECT COUNT(*) FROM certificates WHERE id NOT IN ($inC) AND (previous_version_id IN ($inC) OR superseded_by_id IN ($inC))")->fetchColumn();
        if ($foreign > 0) {
            throw new RuntimeException("$foreign non-dataset certificate(s) are version-linked to dataset certificates; refusing to reset.");
        }
    }
    if ($instIds) {
        $att = (int)$db->query('SELECT COUNT(*) FROM external_credentials WHERE attesting_institution_id IN (' . implode(',', $instIds) . ')'
            . ($stuIds ? ' AND student_id NOT IN (' . implode(',', $stuIds) . ')' : ''))->fetchColumn();
        if ($att > 0) {
            throw new RuntimeException("$att non-dataset external credential(s) were attested by a dataset institution; refusing to reset.");
        }
    }

    $db->beginTransaction();
    try {
        if ($certIds) {
            $inC = implode(',', $certIds);
            $db->exec("UPDATE certificates SET previous_version_id = NULL, superseded_by_id = NULL WHERE id IN ($inC)");
            $db->exec("DELETE FROM certificates WHERE id IN ($inC)");
            $del = $db->prepare('DELETE FROM verification_logs WHERE certificate_id_found = :cid');
            foreach ($certs as $c) { $del->execute(['cid' => $c['certificate_id']]); }
        }
        $db->prepare('DELETE FROM login_attempts WHERE ' . ds_suffix_sql('email'))->execute($p);
        // institutions → institution_keys, students → external_credentials,
        // users → otp_codes / remember_tokens / recovery codes all cascade.
        if ($instIds) { $db->exec('DELETE FROM institutions WHERE id IN (' . implode(',', $instIds) . ')'); }
        if ($stuIds) { $db->exec('DELETE FROM students WHERE id IN (' . implode(',', $stuIds) . ')'); }
        $db->exec("DELETE FROM users WHERE id IN ($inU)");
        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) { $db->rollBack(); }
        throw $e;
    }

    // Files only after the commit, and only plain basenames we stored.
    $files = 0;
    $uploads = __DIR__ . '/../private_data/uploads/';
    $qrs = __DIR__ . '/../public/qrcodes/';
    foreach ($certs as $c) {
        foreach ([$uploads . basename((string)$c['file_path']), $qrs . basename((string)$c['qr_token']) . '.png'] as $f) {
            if (basename($f) !== '' && basename($f) !== '.png' && is_file($f) && @unlink($f)) { $files++; }
        }
    }
    return ['users' => count($uids), 'certificates' => count($certIds), 'files' => $files, 'skipped' => $skipped];
}

/** Create + approve one institution exactly like super_admin.php does. */
function ds_create_institution($db, array $inst, string $passwordHash): array
{
    $email = $inst['admin'] . '@' . DS_DOMAIN;
    $db->prepare("INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, :h, 'admin', 1)")
       ->execute(['e' => $email, 'h' => $passwordHash]);
    $uid = (int)$db->lastInsertId();
    $db->prepare("INSERT INTO institutions (user_id, name, status) VALUES (:u, :n, 'pending')")->execute(['u' => $uid, 'n' => $inst['name']]);
    $iid = (int)$db->lastInsertId();

    // Approval (super_admin.php): generate → encrypt → round-trip check →
    // approve + key v1 in one transaction → pin outside the database.
    $db->beginTransaction();
    try {
        $keys = CryptoService::generateRSAKeyPair();
        $enc = CryptoService::encryptPrivateKey($keys['private_key']);
        if (!CryptoService::verifyKeyPair(CryptoService::decryptPrivateKey($enc), $keys['public_key'])) {
            throw new RuntimeException('Generated key pair failed the round-trip verification.');
        }
        $db->prepare('UPDATE institutions SET status = "approved" WHERE id = :id')->execute(['id' => $iid]);
        $db->prepare('INSERT INTO institution_keys (institution_id,key_id,public_key,encrypted_private_key,status,valid_from) VALUES (:iid,1,:pub,:priv,"active",NOW())')
           ->execute(['iid' => $iid, 'pub' => $keys['public_key'], 'priv' => $enc]);
        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) { $db->rollBack(); }
        throw $e;
    }
    $pin = KeyPinService::pinQuietly($iid, 1, $keys['public_key'], DS_PIN_SOURCE);
    if (KeyPinService::check($iid, 1, $keys['public_key']) !== 'match') {
        // A stale pin for this id (e.g. a restored database) would make
        // every certificate of this institution verify as TAMPERED.
        throw new RuntimeException("Key pin for institution $iid could not be recorded (result: " . var_export($pin, true) . ').');
    }
    return ['id' => $iid, 'user_id' => $uid, 'name' => $inst['name'], 'email' => $email];
}

/** Issue one planned certificate through IssuanceService with a generated PDF. */
function ds_issue($db, array $instRow, int $studentId, string $studentName, array $c): int
{
    $render = function ($certId, $qrToken, $verifyUrl, $qrPath, $destination) use ($instRow, $studentName, $c) {
        if (CertificatePdfService::available()) {
            $pdf = CertificatePdfService::render([
                'institution' => $instRow['name'], 'student' => $studentName, 'title' => $c['title'],
                'certificate_id' => $certId, 'issue_date' => $c['issue'], 'expiry_date' => $c['expiry'], 'verify_url' => $verifyUrl,
            ], $qrPath);
        } else {
            // Without dompdf: a minimal but unique PDF (still hashed/signed).
            $pdf = "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
                . "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 842 595]>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
                . "CertiVault dummy dataset certificate $certId / {$c['title']} / $studentName\n";
        }
        if (file_put_contents($destination, $pdf) === false) {
            throw new Exception('The certificate PDF could not be saved.');
        }
    };
    $issued = IssuanceService::issue($db, $instRow['id'], $studentId,
        ['title' => $c['title'], 'issue_date' => $c['issue'], 'expiry_date' => $c['expiry'] ?? '', 'custom_id' => $c['id']], 'pdf', $render);
    $st = $db->prepare('SELECT id FROM certificates WHERE certificate_id = :c');
    $st->execute(['c' => $issued['certificate_id']]);
    return (int)$st->fetchColumn();
}

/** Same DB effects as revoke_certificate.php. */
function ds_revoke($db, array $instRow, string $certId, string $reason, string $at): void
{
    $db->beginTransaction();
    try {
        $st = $db->prepare('UPDATE certificates SET status = "revoked", revocation_reason = :reason, revoked_at = :at, revoked_by = :by
                            WHERE certificate_id = :cid AND institution_id = :iid AND status IN ("active","expired")');
        $st->execute(['reason' => $reason, 'at' => $at, 'by' => $instRow['user_id'], 'cid' => $certId, 'iid' => $instRow['id']]);
        if ($st->rowCount() !== 1) {
            throw new RuntimeException("Certificate $certId could not be revoked.");
        }
        TransparencyLogService::append($db, $certId, 'REVOKE');
        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) { $db->rollBack(); }
        throw $e;
    }
}

/** Same DB effects as supersede_certificate.php (v2 already issued). */
function ds_supersede($db, array $instRow, int $oldId, string $oldCertId, int $newId): void
{
    $db->beginTransaction();
    try {
        $db->prepare('UPDATE certificates SET version = 2, previous_version_id = :old WHERE id = :new AND institution_id = :iid')
           ->execute(['old' => $oldId, 'new' => $newId, 'iid' => $instRow['id']]);
        $st = $db->prepare('UPDATE certificates SET status = "superseded", superseded_by_id = :new WHERE id = :old AND institution_id = :iid AND status IN ("active","expired")');
        $st->execute(['new' => $newId, 'old' => $oldId, 'iid' => $instRow['id']]);
        if ($st->rowCount() !== 1) {
            throw new RuntimeException("Certificate $oldCertId could not be superseded.");
        }
        TransparencyLogService::append($db, $oldCertId, 'SUPERSEDE');
        $db->commit();
    } catch (Throwable $e) {
        if ($db->inTransaction()) { $db->rollBack(); }
        throw $e;
    }
}

function ds_summary_counts(array $plan, string $today): array
{
    $v = ['VALID' => 0, 'EXPIRED' => 0, 'REVOKED' => 0, 'SUPERSEDED' => 0];
    foreach ($plan['certs'] as $c) { $v[ds_expected_verdict($c['state'], $c['expiry'], $today)]++; }
    return $v;
}

// ─────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────
$plan = ds_plan($PEOPLE, $SEED, $TODAY);
$verdicts = ds_summary_counts($plan, $TODAY);
$instNames = array_column($plan['institutions'], 'name');
$printPlan = function () use ($plan, $verdicts, $PEOPLE, $SEED) {
    printf("Plan (seed %d): %d institutions, %d people, %d certificates — VALID %d · EXPIRED %d · REVOKED %d · SUPERSEDED %d\n",
        $SEED, count($plan['institutions']), $PEOPLE, count($plan['certs']), $verdicts['VALID'], $verdicts['EXPIRED'], $verdicts['REVOKED'], $verdicts['SUPERSEDED']);
};

if ($CSV_ONLY) {
    $printPlan();
    foreach (ds_write_outputs($plan, $OUT, $TODAY) as $f => $n) { echo "[+] $OUT/$f ($n rows)\n"; }
    echo "CSV-only mode: verify_url / sha256 are empty until the dataset is generated into a database.\n";
    exit(0);
}

try {
    $db = Database::getInstance();
} catch (Throwable $e) {
    fwrite(STDERR, 'Cannot connect to database "' . DB_NAME . '": ' . $e->getMessage() . "\n");
    exit(1);
}
echo 'Database: ' . DB_NAME . "\n";

if ($RESET) {
    try {
        $r = ds_reset($db, $instNames);
    } catch (Throwable $e) {
        fwrite(STDERR, 'Reset refused/failed: ' . $e->getMessage() . "\n");
        exit(1);
    }
    printf("[-] Reset: removed %d dataset account(s), %d certificate(s), %d file(s). Transparency-log entries and key pins are append-only and were kept.\n",
        $r['users'], $r['certificates'], $r['files']);
    foreach ($r['skipped'] as $s) { echo "[!] Left untouched (not a dataset institution name): $s\n"; }
    exit(0);
}

$existing = ds_existing($db);
if ($existing['users'] > 0 && !$DRY) {
    printf("[=] A dataset already exists in \"%s\" (%d accounts, %d certificates). Nothing was changed.\n    Run with --reset first to remove it, then run again to regenerate.\n",
        DB_NAME, $existing['users'], $existing['certificates']);
    exit(2);
}

// Pre-flight: every planned certificate ID must be free (same rule as issuance).
$collisions = [];
foreach ($plan['certs'] as $c) {
    if (($m = v_certificate_id_flexible($c['id'], $db)) !== true) { $collisions[] = $c['id'] . ': ' . $m; }
}
$planErrors = [];
foreach ($plan['people'] as $p) {
    if (($m = v_person_name($p['name'])) !== true) { $planErrors[] = $p['name'] . ': ' . $m; }
}
if (($m = v_password_strong(DS_PASSWORD)) !== true) { $planErrors[] = 'demo password: ' . $m; }
// Custom IDs need the widened column from migration 007 (VARCHAR(64)).
$idWidth = (int)$db->query("SELECT CHARACTER_MAXIMUM_LENGTH FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'certificates' AND COLUMN_NAME = 'certificate_id'")->fetchColumn();
$longestId = max(array_map('strlen', array_column($plan['certs'], 'id')));
if ($idWidth > 0 && $idWidth < $longestId) {
    $planErrors[] = "certificates.certificate_id is VARCHAR($idWidth) but IDs up to $longestId characters are needed — apply database/migrations/007_flexible_certificate_id.sql first.";
}

if ($DRY) {
    echo "DRY RUN — nothing will be written.\n";
    $printPlan();
    echo 'PDF generator (dompdf): ' . (CertificatePdfService::available() ? 'available' : 'NOT available — placeholder PDFs would be used') . "\n";
    echo 'QR / verify base URL : ' . BASE_URL . "\n";
    echo 'Key pin file         : ' . KeyPinService::file() . "\n";
    echo 'Transparency log     : ' . (CERTIFICATE_TRANSPARENCY_ENABLED ? 'enabled' : 'disabled') . "\n";
    echo 'Existing dataset     : ' . ($existing['users'] > 0
        ? "{$existing['users']} accounts, {$existing['certificates']} certificates — a real run would refuse (use --reset first)"
        : 'none') . "\n";
    echo 'ID collisions        : ' . count($collisions) . ($existing['users'] > 0 ? ' (expected while the dataset exists)' : '') . "\n";
    foreach (array_merge($collisions, $planErrors) as $e) { echo "  [!] $e\n"; }
    echo "\nSample of planned certificates:\n";
    foreach (array_slice($plan['certs'], 0, 8) as $c) {
        printf("  %-24s %-28s %-10s %s\n", $c['id'], $plan['people'][$c['person']]['name'], $c['issue'], ds_expected_verdict($c['state'], $c['expiry'], $TODAY));
    }
    exit((($collisions && $existing['users'] === 0) || $planErrors) ? 1 : 0);
}

if ($collisions || $planErrors) {
    fwrite(STDERR, "Pre-flight failed:\n  " . implode("\n  ", array_merge($collisions, $planErrors)) . "\n");
    exit(1);
}

@set_time_limit(0);
$started = microtime(true);
$printPlan();
echo 'QR / verify base URL: ' . BASE_URL . "\n";
try {
    // Institutions
    $instRows = [];
    $adminHash = password_hash(DS_PASSWORD, PASSWORD_BCRYPT);
    foreach ($plan['institutions'] as $code => $inst) {
        $instRows[$code] = ds_create_institution($db, $inst, $adminHash);
        echo "[+] Institution approved, key generated + pinned: {$inst['name']} <{$instRows[$code]['email']}>\n";
    }

    // People: activated student accounts (each with its own bcrypt hash).
    $studentIds = [];
    $insU = $db->prepare("INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, :h, 'student', 1)");
    $insS = $db->prepare('INSERT INTO students (user_id, full_name, enrollment_number) VALUES (:u, :n, :en)');
    foreach ($plan['people'] as $i => $p) {
        $insU->execute(['e' => $p['email'], 'h' => password_hash(DS_PASSWORD, PASSWORD_BCRYPT)]);
        $insS->execute(['u' => (int)$db->lastInsertId(), 'n' => $p['name'], 'en' => $p['enrollment']]);
        $studentIds[$i] = (int)$db->lastInsertId();
    }
    echo '[+] ' . count($studentIds) . " activated student accounts\n";

    // Certificates in issue-date order; corrections and revocations after.
    $dbIds = [];
    $n = 0;
    foreach ($plan['certs'] as $c) {
        $p = $plan['people'][$c['person']];
        $dbIds[$c['id']] = ds_issue($db, $instRows[$c['inst']], $studentIds[$c['person']], $p['name'], $c);
        if ($c['previous'] !== null) {
            ds_supersede($db, $instRows[$c['inst']], $dbIds[$c['previous']], $c['previous'], $dbIds[$c['id']]);
        }
        if ($c['state'] === 'revoked') {
            ds_revoke($db, $instRows[$c['inst']], $c['id'], $c['reason'], $c['revoked_at']);
        }
        if (++$n % 25 === 0) { echo "    … $n certificates issued\n"; }
    }
    echo "[+] $n certificates issued (signed PDFs with QR codes)\n";
} catch (Throwable $e) {
    fwrite(STDERR, "\n[x] Generation failed: " . $e->getMessage() . "\n    Removing the partial dataset…\n");
    try {
        $r = ds_reset($db, $instNames);
        fwrite(STDERR, "    Removed {$r['users']} account(s), {$r['certificates']} certificate(s).\n");
    } catch (Throwable $e2) {
        fwrite(STDERR, '    Cleanup failed too (' . $e2->getMessage() . "); run with --reset.\n");
    }
    exit(1);
}

// Verify every generated certificate with the real verification cascade.
$mismatch = [];
$bySample = [];
foreach ($plan['certs'] as $c) {
    $row = VerificationService::findByCertificateId($db, $c['id']);
    $expected = ds_expected_verdict($c['state'], $c['expiry'], $TODAY);
    $got = $row ? VerificationService::verify($db, $row)['verdict'] : 'NOT FOUND';
    if ($got !== $expected) { $mismatch[] = "{$c['id']}: expected $expected, got $got"; }
    $bySample[$expected][] = [$c['id'], $got, $row['qr_token'] ?? ''];
}

foreach (ds_write_outputs($plan, $OUT, $TODAY, $db) as $f => $rows) { echo "[+] $OUT/$f ($rows rows)\n"; }

echo "\n================ Dataset Summary ================\n";
printf("Database          : %s   (%.1fs)\n", DB_NAME, microtime(true) - $started);
printf("Certificates      : %d  (VALID %d, EXPIRED %d, REVOKED %d, SUPERSEDED %d)\n", count($plan['certs']), $verdicts['VALID'], $verdicts['EXPIRED'], $verdicts['REVOKED'], $verdicts['SUPERSEDED']);
printf("Re-verified       : %d/%d match the expected verdict\n", count($plan['certs']) - count($mismatch), count($plan['certs']));
echo 'Password (all)    : ' . DS_PASSWORD . "\n";
echo 'Institution login : ' . $instRows['NBIT']['email'] . "  (one per institution, see institutions.csv)\n";
echo 'Student login     : ' . $plan['people'][0]['email'] . "  (" . $plan['people'][0]['name'] . ")\n";
echo "Sample (one per verdict):\n";
foreach ($bySample as $expected => $list) {
    [$id, $got, $tok] = $list[0];
    printf("  %-24s %-10s %s/verify.php?token=%s\n", $id, $got, BASE_URL, $tok);
}
echo "=================================================\n";
foreach ($mismatch as $m) { fwrite(STDERR, "[x] $m\n"); }
exit($mismatch ? 1 : 0);
