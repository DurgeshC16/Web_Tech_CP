<?php
// scripts/check_environment.php
// ─────────────────────────────────────────────────────────────────────
// Upload-environment audit for CertiVault certificate uploads.
//
// Usage:
//   php scripts/check_environment.php                 (CLI, always allowed)
//   http://host/<repo>/scripts/check_environment.php (browser: admin only)
//
// Reports PASS/FAIL for every setting uploads depend on, with the exact
// fix for each failure. Exit code 0 = all pass, 1 = something needs fixing.
// ─────────────────────────────────────────────────────────────────────

$is_cli = php_sapi_name() === 'cli';

if (!$is_cli) {
    // Browser access: administrators only. This file must never leak
    // server configuration to anonymous visitors. (A manual role check
    // instead of require_role(): its 'login.php' redirect is relative
    // and would resolve to /scripts/login.php from this path.)
    require_once __DIR__ . '/../src/utils/helpers.php';
    if (empty($_SESSION['user_id']) || ($_SESSION['role'] ?? null) !== 'admin') {
        $base = rtrim(str_replace('\\', '/', dirname(dirname($_SERVER['SCRIPT_NAME'] ?? ''))), '/');
        redirect($base . '/public/login.php');
    }
    send_security_headers(); // plain-text diagnostic, still gets the basics
    header('Content-Type: text/plain; charset=UTF-8');
}

$failures = 0;

function env_check($label, $ok, $detail, $fix) {
    global $failures;
    if ($ok) {
        echo "PASS  $label: $detail\n";
    } else {
        $failures++;
        echo "FAIL  $label: $detail\n";
        echo "      FIX: $fix\n";
    }
}

/** Convert a php.ini size string (e.g. "8M", "512K", "1G") to bytes. */
function shorthand_to_bytes($v) {
    $v = trim((string)$v);
    if ($v === '-1') {
        return PHP_INT_MAX; // unlimited
    }
    if (preg_match('/^(\d+)\s*([KMG]?)$/i', $v, $m)) {
        $n = (int)$m[1];
        switch (strtoupper($m[2])) {
            case 'G': return $n * 1024 * 1024 * 1024;
            case 'M': return $n * 1024 * 1024;
            case 'K': return $n * 1024;
            default:  return $n;
        }
    }
    return 0;
}

echo "CertiVault upload environment check (" . ($is_cli ? 'CLI' : 'browser') . ")\n";
echo str_repeat('-', 70) . "\n";

// ── PHP version ──────────────────────────────────────────────────────
env_check(
    'PHP version',
    version_compare(PHP_VERSION, '8.0.0', '>='),
    'running ' . PHP_VERSION,
    'Upgrade to PHP 8.0+ (XAMPP ships a current PHP).'
);

// ── Upload limits ────────────────────────────────────────────────────
$umf_raw = ini_get('upload_max_filesize');
$pms_raw = ini_get('post_max_size');
$umf = shorthand_to_bytes($umf_raw);
$pms = shorthand_to_bytes($pms_raw);
$need = 5 * 1024 * 1024; // app limit: v_upload() caps files at 5 MB

env_check(
    'upload_max_filesize',
    $umf >= $need,
    "php.ini value is '$umf_raw'",
    'In C:\\xampp\\php\\php.ini set upload_max_filesize=8M, then restart Apache.'
);
env_check(
    'post_max_size',
    $pms >= max($need, $umf),
    "php.ini value is '$pms_raw' (must cover upload_max_filesize plus form fields)",
    'In C:\\xampp\\php\\php.ini set post_max_size=10M, then restart Apache.'
);
env_check(
    'file_uploads',
    filter_var(ini_get('file_uploads'), FILTER_VALIDATE_BOOLEAN),
    'file_uploads=' . var_export(ini_get('file_uploads'), true),
    'In C:\\xampp\\php\\php.ini set file_uploads=On, then restart Apache.'
);

// ── Required extensions ──────────────────────────────────────────────
foreach (['fileinfo', 'openssl', 'pdo_mysql', 'gd'] as $ext) {
    $loaded = extension_loaded($ext);
    $why = [
        'fileinfo'  => 'MIME verification in v_upload()',
        'openssl'   => 'RSA signing and AES-256-GCM private-key encryption',
        'pdo_mysql' => 'database access',
        'gd'        => 'QR-code PNG rendering (phpqrcode)',
    ][$ext];
    env_check(
        "extension $ext",
        $loaded,
        $loaded ? 'loaded' : 'MISSING (needed for ' . $why . ')',
        "In C:\\xampp\\php\\php.ini uncomment the line extension=$ext (remove the leading semicolon), then restart Apache."
    );
}

// ── Writable directories ─────────────────────────────────────────────
$root = dirname(__DIR__);
$dirs = [
    'private_data/uploads'       => 'certificate file storage (outside the web root)',
    'public/qrcodes'             => 'QR-code PNGs served to verifiers',
    'src/utils/phpqrcode/cache'  => 'phpqrcode font/frame cache',
];
foreach ($dirs as $rel => $purpose) {
    $abs = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
    if (!is_dir($abs)) {
        env_check(
            "dir $rel",
            false,
            'directory does not exist (' . $purpose . ')',
            "Create it (the app also self-creates uploads/qrcodes at runtime): mkdir \"$rel\"."
        );
        continue;
    }
    $w = is_writable($abs);
    env_check(
        "dir $rel",
        $w,
        ($w ? 'exists and writable' : 'exists but NOT writable') . ' (' . $purpose . ')',
        'Grant the Apache/PHP user write access, e.g. on Windows give Modify to the folder, on Linux: chown www-data:www-data ' . $rel . ' && chmod 0755 ' . $rel . '.'
    );
}

echo str_repeat('-', 70) . "\n";
if ($failures === 0) {
    echo "ALL CHECKS PASSED.\n";
    exit(0);
}
echo "$failures CHECK(S) FAILED — apply the FIX lines above, restart Apache, re-run.\n";
exit(1);
