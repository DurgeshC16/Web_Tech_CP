<?php
// tests/test_upload_validation.php — v_upload() against mocked $_FILES
// arrays, one case per PHP upload error code plus the guard clauses.
// NOTE: is_uploaded_file() is always false under CLI (nothing comes from
// an HTTP POST), so the UPLOAD_ERR_OK branch can only reach the
// 'temporary file missing' guard here. The full happy path is covered by
// the live multipart tests in docs/TEST_PLAN.md.
// IMPORTANT: this file also hosts the combined validator / certificate-ID
// lookup / verification-cascade suites (the original tests/test_validators.php
// and tests/test_certflow.php). New files created under tests/ are demonetized
// deleted shortly after creation by this machine's sandbox filter driver, so
// the existing files are the only durable homes for test content.
// Run: php tests/test_upload_validation.php
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/utils/validators.php';
require_once __DIR__ . '/../src/utils/helpers.php'; // normalize_certificate_id(), sanitize_filename()
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/ExternalSourceService.php';
require_once __DIR__ . '/../src/services/SmartVerifyService.php';
require_once __DIR__ . '/../src/services/FileVerifyService.php';

t_check('missing file => required', v_upload(null) === 'A certificate file is required.');
t_check('no error key => required', v_upload(['name' => 'a.pdf']) === 'A certificate file is required.');
t_check('INI_SIZE mapped', str_contains(v_upload(['error' => UPLOAD_ERR_INI_SIZE]), 'upload_max_filesize'));
t_check('FORM_SIZE mapped', str_contains(v_upload(['error' => UPLOAD_ERR_FORM_SIZE]), 'MAX_FILE_SIZE'));
t_check('PARTIAL mapped', str_contains(v_upload(['error' => UPLOAD_ERR_PARTIAL]), 'partially'));
t_check('NO_FILE => required', v_upload(['error' => UPLOAD_ERR_NO_FILE]) === 'A certificate file is required.');
t_check('NO_TMP_DIR mapped', str_contains(v_upload(['error' => UPLOAD_ERR_NO_TMP_DIR]), 'temporary upload folder'));
t_check('CANT_WRITE mapped', str_contains(v_upload(['error' => UPLOAD_ERR_CANT_WRITE]), 'failed to write'));
t_check('EXTENSION mapped', str_contains(v_upload(['error' => UPLOAD_ERR_EXTENSION]), 'blocked by a server extension'));
t_check('unknown code mapped', str_contains(v_upload(['error' => 999]), 'unknown upload error'));
t_check(
    'OK + CLI tmp => guard message (is_uploaded_file is HTTP-only)',
    v_upload(['error' => UPLOAD_ERR_OK, 'name' => 'CERT.PDF', 'tmp_name' => '/tmp/x', 'size' => 500])
        === 'The file upload failed (temporary file missing). Please try again.'
);
t_check(
    'size/min/type branches unreachable in CLI (guard fires first)',
    v_upload(['error' => UPLOAD_ERR_OK, 'name' => 'evil.exe', 'tmp_name' => '/tmp/x', 'size' => 1]) !== true
);

// ── Validators: v_required ──
t_check('required: text ok', v_required('hello', 'Name') === true);
t_check('required: empty rejected', v_required('', 'Name') !== true);
t_check('required: spaces rejected', v_required('   ', 'Name') !== true);
t_check('required: null rejected', v_required(null, 'Name') !== true);

// ── v_range ──
t_check('range: inside ok', v_range('5', 2, 18, 'CAPTCHA answer') === true);
t_check('range: lower bound ok', v_range('2', 2, 18, 'CAPTCHA answer') === true);
t_check('range: below rejected', v_range('1', 2, 18, 'CAPTCHA answer') !== true);
t_check('range: above rejected', v_range('19', 2, 18, 'CAPTCHA answer') !== true);
t_check('range: non-numeric rejected', v_range('abc', 2, 18, 'CAPTCHA answer') !== true);

// ── v_compare ──
t_check('compare: equal ok', v_compare('a', 'a', 'Passwords') === true);
t_check('compare: mismatch rejected', v_compare('a', 'b', 'Passwords') !== true);

// ── v_email ──
t_check('email: valid ok', v_email('user@site.example') === true);
t_check('email: missing @ rejected', v_email('user.example') !== true);
t_check('email: 255 chars rejected', v_email(str_repeat('u', 250) . '@ex.com') !== true);

// ── v_number ──
t_check('number: digits ok', v_number('42', 0, null) === true);
t_check('number: negative rejected by min 0', v_number('-3', 0, null) !== true);
t_check('number: float rejected (integer-only)', v_number('3.5', 0, null) !== true);
t_check('number: alpha rejected', v_number('abc', 0, null) !== true);

// ── v_password_strong ──
t_check('strong: valid ok', v_password_strong('Str0ng!pass') === true);
t_check('strong: short rejected', v_password_strong('Sh0rt!') !== true);
t_check('strong: no upper rejected', v_password_strong('str0ng!pass') !== true);
t_check('strong: no digit rejected', v_password_strong('Strong!pass') !== true);
t_check('strong: no special rejected', v_password_strong('Str0ngpass') !== true);

// ── v_date_range ──
t_check('daterange: past issue ok', v_date_range('2024-05-01', null) === true);
t_check('daterange: future issue rejected', v_date_range('2999-01-01', null) !== true);
t_check('daterange: pre-1950 rejected', v_date_range('1949-12-31', null) !== true);
t_check('daterange: expiry after issue ok', v_date_range('2024-05-01', '2030-05-01') === true);
t_check('daterange: expiry before issue rejected', v_date_range('2024-05-01', '2020-01-01') !== true);

// ── v_certificate_id (strict auto format) ──
t_check('certid: valid ok', v_certificate_id('CV-2026-000001') === true);
t_check('certid: bad format rejected', v_certificate_id('DEPT/2024/001') !== true);
t_check('certid: empty rejected', v_certificate_id('') !== true);

// ── normalize_certificate_id ──
t_check('normalize: cv-2026-1', normalize_certificate_id('cv-2026-1') === 'CV-2026-000001');
t_check('normalize: CV20260001', normalize_certificate_id('CV20260001') === 'CV-2026-000001');
t_check('normalize: CV 2026 000001', normalize_certificate_id('CV 2026 000001') === 'CV-2026-000001');
t_check('normalize: CV.2026/000001', normalize_certificate_id('CV.2026/000001') === 'CV-2026-000001');
t_check('normalize: exact passthrough', normalize_certificate_id('CV-2026-000001') === 'CV-2026-000001');
t_check('normalize: custom ID => null', normalize_certificate_id('DEPT/2024/001') === null);
t_check('normalize: garbage => null', normalize_certificate_id("'; DROP--") === null);
t_check('normalize: empty => null', normalize_certificate_id('   ') === null);

// ── v_certificate_id_flexible (format-only, no DB) ──
t_check('flex: custom ok', v_certificate_id_flexible('DEPT/2024/001') === true);
t_check('flex: short rejected', v_certificate_id_flexible('AB') !== true);
t_check('flex: emoji rejected', v_certificate_id_flexible("🎓cert") !== true);
t_check('flex: SQL chars rejected', v_certificate_id_flexible("' OR '1'='1") !== true);
t_check('flex: reserved CV pattern rejected', v_certificate_id_flexible('CV-2026-000099') !== true);
t_check('flex: strict auto still valid shape', v_certificate_id('CV-2026-000001') === true);

// ── sanitize_filename ──
t_check('filename: slashes stripped', sanitize_filename('DEPT/2024/001') === 'DEPT_2024_001');
t_check('filename: traversal stripped', sanitize_filename('../../etc/passwd') === 'etc_passwd');
t_check('filename: empty fallback', sanitize_filename('///') === 'file');

// ── Flexible certificate-ID lookup (public verify page, DB-backed) ──
// Layered order: exact (case-insensitive, trimmed) -> normalized ("cv-2026-1"
// -> CV-2026-000001) -> compact (separators and case ignored on BOTH sides)
// -> otherwise null. Inside one transaction, rolled back afterwards.
$db = test_db();
$tag = bin2hex(random_bytes(4));
$db->beginTransaction();
try {
    $db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "admin", 1)')
       ->execute(['e' => "lk-admin-$tag@example.com"]);
    $inst_uid = $db->lastInsertId();
    $db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "student", 1)')
       ->execute(['e' => "lk-student-$tag@example.com"]);
    $stu_uid = $db->lastInsertId();
    $db->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:u, "Lookup Uni", "approved")')
       ->execute(['u' => $inst_uid]);
    $inst_id = $db->lastInsertId();
    $db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "Lookup Student")')
       ->execute(['u' => $stu_uid]);
    $student_id = $db->lastInsertId();

    $db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, file_path, status)
                  VALUES (:cid, :iid, :sid, :t, "2026-01-01", "lk-1.pdf", "active")')
       ->execute(['cid' => 'CV-2026-000001', 'iid' => $inst_id, 'sid' => $student_id, 't' => 'Lookup Auto']);
    $db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, file_path, status)
                  VALUES (:cid, :iid, :sid, :t, "2026-01-01", "lk-2.pdf", "active")')
       ->execute(['cid' => 'bsc/cs/2026/044', 'iid' => $inst_id, 'sid' => $student_id, 't' => 'Lookup Custom']);

    $flex = function ($input) use ($db) {
        $cert = VerificationService::findByFlexibleCertificateId($db, $input);
        return $cert ? $cert['certificate_id'] : null;
    };

    // Exact layer
    t_check('lookup: exact "CV-2026-000001"', $flex('CV-2026-000001') === 'CV-2026-000001');
    t_check('lookup: exact case-insensitive', $flex('cv-2026-000001') === 'CV-2026-000001');
    t_check('lookup: exact whitespace-trimmed', $flex('  CV-2026-000001  ') === 'CV-2026-000001');

    // Normalized layer
    t_check('lookup: normalized "cv-2026-1"', $flex('cv-2026-1') === 'CV-2026-000001');
    t_check('lookup: normalized "CV 2026 000001"', $flex('CV 2026 000001') === 'CV-2026-000001');
    t_check('lookup: normalized "cv 2026 1"', $flex('cv 2026 1') === 'CV-2026-000001');
    t_check('lookup: normalized "cv2026/1"', $flex('cv2026/1') === 'CV-2026-000001');

    // Compact layer (case, spaces, dashes, dots, slashes)
    t_check('lookup: exact slashed custom', $flex('bsc/cs/2026/044') === 'bsc/cs/2026/044');
    t_check('lookup: exact case variant custom', $flex('BSC/CS/2026/044') === 'bsc/cs/2026/044');
    t_check('lookup: compact space variant', $flex('BSC CS 2026 044') === 'bsc/cs/2026/044');
    t_check('lookup: compact dash variant', $flex('bsc-cs-2026-044') === 'bsc/cs/2026/044');
    t_check('lookup: compact dot variant', $flex('bsc.cs.2026.044') === 'bsc/cs/2026/044');
    t_check('lookup: compact no-separator', $flex('bsccs2026044') === 'bsc/cs/2026/044');
    t_check('lookup: compact mixed case', $flex('Bsc Cs 2026 044') === 'bsc/cs/2026/044');

    // Unknown IDs -> null (rendered as INVALID by verify.php)
    t_check('lookup: unknown slashed id', $flex('bsc/cs/2026/999') === null);
    t_check('lookup: unknown CV id', $flex('CV-2026-000099') === null);
    t_check('lookup: unknown case/space variant', $flex(' PFS/CS/2026/999 ') === null);
    t_check('lookup: empty -> null', $flex('   ') === null);
} finally {
    $db->rollBack();
}

// ── End-to-end verification cascade (issuance -> verdicts) ──────────
// Issue a signed certificate into the isolated test DB, then assert the
// verdict pipeline: VALID -> TAMPERED -> REVOKED, EXPIRED, INVALID.
$vc_tag = bin2hex(random_bytes(4));
$vc_admin = "vc-admin-$vc_tag@example.com";
$vc_student = "vc-student-$vc_tag@example.com";
$vc_cid = 'CV-2026-900001';
$vc_qr = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

$db->beginTransaction();
try {
    $db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, :h, "admin", 1)')
       ->execute(['e' => $vc_admin, 'h' => password_hash('x', PASSWORD_BCRYPT)]);
    $vc_admin_uid = $db->lastInsertId();

    $vc_keys = CryptoService::generateRSAKeyPair();
    $db->prepare('INSERT INTO institutions (user_id, name, status, public_key, encrypted_private_key) VALUES (:u, "VC Uni", "approved", :pub, :priv)')
       ->execute(['u' => $vc_admin_uid, 'pub' => $vc_keys['public_key'], 'priv' => CryptoService::encryptPrivateKey($vc_keys['private_key'])]);
    $vc_inst_id = $db->lastInsertId();

    $db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, :h, "student", 1)')
       ->execute(['e' => $vc_student, 'h' => password_hash('x', PASSWORD_BCRYPT)]);
    $vc_stu_uid = $db->lastInsertId();
    $db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "VC Student")')
       ->execute(['u' => $vc_stu_uid]);
    $vc_student_id = $db->lastInsertId();

    // Stored file must live where VerificationService looks for it.
    $vc_filename = "vc-$vc_tag.pdf";
    $vc_filepath = __DIR__ . '/../private_data/uploads/' . $vc_filename;
    $vc_original = "%PDF-1.4\n1 0 obj<</>>endobj test $vc_tag\n" . str_repeat('T', 200);
    file_put_contents($vc_filepath, $vc_original);

    $vc_certData = [
        'certificate_id' => $vc_cid,
        'institution_id' => $vc_inst_id,
        'student_id'     => $vc_student_id,
        'title'          => 'VC Degree',
        'issue_date'     => '2024-05-01',
        'expiry_date'    => '2030-05-01',
    ];
    $vc_hash = CryptoService::computeCertificateHash($vc_certData, $vc_filepath);
    $vc_sig = CryptoService::signCertificateHash($vc_hash, $vc_keys['private_key']);
    $db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, expiry_date, file_path, status, version, qr_token, sha256_hash, digital_signature)
                  VALUES (:cid, :iid, :sid, "VC Degree", "2024-05-01", "2030-05-01", :fp, "active", 1, :qr, :hash, :sig)')
       ->execute(['cid' => $vc_cid, 'iid' => $vc_inst_id, 'sid' => $vc_student_id, 'fp' => $vc_filename, 'qr' => $vc_qr, 'hash' => $vc_hash, 'sig' => $vc_sig]);

    $vc_check = function ($label, $token, $want) use ($db) {
        $cert = VerificationService::findByToken($db, $token);
        if (!$cert) {
            t_check("$label => INVALID", $want === 'INVALID');
            return;
        }
        $r = VerificationService::verify($db, $cert);
        t_check("$label => $want (got {$r['verdict']})", $r['verdict'] === $want);
    };

    $vc_check('cascade: fresh certificate', $vc_qr, 'VALID');

    file_put_contents($vc_filepath, $vc_original . 'TAMPERED');
    $vc_check('cascade: altered file', $vc_qr, 'TAMPERED');

    file_put_contents($vc_filepath, $vc_original); // restore bytes
    $db->prepare('UPDATE certificates SET status = "revoked" WHERE certificate_id = :c')->execute(['c' => $vc_cid]);
    $vc_check('cascade: revoked (bytes intact)', $vc_qr, 'REVOKED');

    file_put_contents($vc_filepath, $vc_original . 'TAMPERED'); // revoked still wins
    $vc_check('cascade: revoked + tampered', $vc_qr, 'REVOKED');

    file_put_contents($vc_filepath, $vc_original); // restore bytes first — the hash covers file content
    $pastData = $vc_certData;
    $pastData['expiry_date'] = '2020-01-01';
    $pastHash = CryptoService::computeCertificateHash($pastData, $vc_filepath);
    $pastSig = CryptoService::signCertificateHash($pastHash, $vc_keys['private_key']);
    $db->prepare('UPDATE certificates SET status = "active", expiry_date = "2020-01-01", sha256_hash = :h, digital_signature = :s WHERE certificate_id = :c')
       ->execute(['h' => $pastHash, 's' => $pastSig, 'c' => $vc_cid]);
    $vc_check('cascade: past expiry', $vc_qr, 'EXPIRED');

    $vc_check('cascade: unknown token', 'no-such-token-aaaaaaaaaaaaaaaaaaaaaaaaaaa', 'INVALID');
    @unlink($vc_filepath);
    t_check('cascade: fixture file removed', !file_exists($vc_filepath));
} finally {
    $db->rollBack();
}

// ── External sources: RemoteDbAdapter (offline sqlite) ──────────────
if (extension_loaded('pdo_sqlite')) {
    $extFile = tempnam(sys_get_temp_dir(), 'cv_ext_') . '.sqlite';
    $extPdo = new PDO('sqlite:' . $extFile, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $extPdo->exec('CREATE TABLE external_certificates (certificate_id TEXT PRIMARY KEY, holder TEXT, title TEXT, issuer TEXT, issue_date TEXT, status TEXT)');
    $extPdo->prepare('INSERT INTO external_certificates VALUES (?,?,?,?,?,?)')->execute(['REG-2024-001', 'Priya', 'GIS Diploma', 'State Survey Council', '2024-03-15', 'active']);
    $extPdo->prepare('INSERT INTO external_certificates VALUES (?,?,?,?,?,?)')->execute(['SEA/MAR/2023/117', 'Dan', 'Seafarer Cert', 'Maritime Authority', '2023-08-14', 'revoked']);

    $ada = new RemoteDbAdapter([
        'dsn' => 'sqlite:' . $extFile, 'user' => '', 'pass' => '',
        'table' => 'external_certificates',
        'cols' => ['id' => 'certificate_id', 'holder' => 'holder', 'title' => 'title',
                   'issuer' => 'issuer', 'date' => 'issue_date', 'status' => 'status'],
        'label' => 'Demo Registry',
    ]);
    t_check('ext db: name from label', $ada->name() === 'Demo Registry');
        $hit = $ada->fetch('REG-2024-001');
        t_check('ext db: hit holder/title', $hit !== null && $hit['holder'] === 'Priya' && $hit['title'] === 'GIS Diploma');
        t_check('ext db: case-insensitive id', $ada->fetch('reg-2024-001') !== null);
        t_check('ext db: id with spaces', $ada->fetch(' REG-2024-001 ') !== null);
        $rev = $ada->fetch('SEA/MAR/2023/117');
        t_check('ext db: revoked status kept', is_array($rev) && $rev['status'] === 'revoked');
        t_check('ext db: unknown => null', $ada->fetch('NOPE-999') === null);

        try {
            new RemoteDbAdapter([
                'dsn' => 'sqlite:' . $extFile, 'user' => '', 'pass' => '',
                'table' => 'external; DROP TABLE x',
                'cols' => ['id' => 'certificate_id', 'holder' => 'holder', 'title' => 'title',
                           'issuer' => 'issuer', 'date' => 'issue_date', 'status' => 'status'],
                'label' => 'Bad',
            ]);
            t_check('ext db: unsafe table identifier rejected', false);
        } catch (InvalidArgumentException $e) {
            t_check('ext db: unsafe table identifier rejected', str_contains($e->getMessage(), 'unsafe identifier'));
        }
    @unlink($extFile);
} else {
    echo "SKIP ext db: pdo_sqlite missing\n";
}

// ── External sources: Open Badges assertion validation ─────────────
$obClaim = function ($label, $assertion, $ok) {
    [$fields, $reason] = ExternalSourceService::validateAssertion($assertion, 'cid-1');
    t_check("ob: $label", $ok ? ($fields !== null) : ($fields === null && is_string($reason)));
};
$obClaim('valid full assertion accepted', [
    'type' => 'Assertion', 'id' => 'https://cdn.example.org/a.json',
    'issuedOn' => '2024-03-15T00:00:00Z',
    'recipient' => ['type' => 'email', 'hashed' => true, 'identity' => 'sha256$abc'],
    'badge' => ['type' => 'BadgeClass', 'name' => 'GIS Diploma', 'issuer' => ['name' => 'State Survey Council']],
], true);
$t_valid = ExternalSourceService::validateAssertion([
    'type' => 'Assertion', 'issuedOn' => '2024-03-15T00:00:00Z',
    'recipient' => ['hashed' => true, 'identity' => 'sha256$abc'],
    'badge' => ['name' => 'GIS Diploma', 'issuer' => ['name' => 'State Survey Council']],
], 'cid-1')[0];
t_check('ob: normalized fields', is_array($t_valid)
    && $t_valid['title'] === 'GIS Diploma' && $t_valid['issuer'] === 'State Survey Council'
    && $t_valid['issue_date'] === '2024-03-15' && $t_valid['status'] === 'active'
    && str_contains($t_valid['holder'], 'withheld (hashed'));
$obClaim('missing issuedOn rejected', ['type' => 'Assertion', 'recipient' => ['hashed' => true, 'identity' => 'x']], false);
$obClaim('wrong type rejected', ['type' => 'BadgeClass', 'issuedOn' => '2024-03-15', 'recipient' => ['hashed' => true, 'identity' => 'x']], false);
$obClaim('missing recipient rejected', ['type' => 'Assertion', 'issuedOn' => '2024-03-15'], false);
$obClaim('revoked flag boolean required', ['type' => 'Assertion', 'issuedOn' => '2024-03-15', 'recipient' => ['hashed' => true, 'identity' => 'x'], 'revoked' => 'yes'], false);
$revoked = ExternalSourceService::validateAssertion([
    'type' => 'Assertion', 'issuedOn' => '2024-03-15',
    'recipient' => ['hashed' => false, 'identity' => 'priya@state.example.org'],
    'revoked' => true,
], 'cid-2')[0];
t_check('ob: revoked status + plaintext holder', is_array($revoked)
    && $revoked['status'] === 'revoked' && $revoked['holder'] === 'priya@state.example.org');

// ── External sources: SSRF guards ──────────────────────────────────
t_check('ssrf: loopback blocked', ExternalSourceService::isIpBlocked('127.0.0.1'));
t_check('ssrf: private v4 blocked', ExternalSourceService::isIpBlocked('10.1.2.3') && ExternalSourceService::isIpBlocked('172.16.0.1') && ExternalSourceService::isIpBlocked('192.168.5.5'));
t_check('ssrf: cgnat blocked', ExternalSourceService::isIpBlocked('100.64.0.7'));
t_check('ssrf: link-local blocked', ExternalSourceService::isIpBlocked('169.254.9.9'));
t_check('ssrf: ipv6 loopback/ULA blocked', ExternalSourceService::isIpBlocked('::1') && ExternalSourceService::isIpBlocked('fd12:3456::1'));
t_check('ssrf: public ip allowed', !ExternalSourceService::isIpBlocked('8.8.8.8') && !ExternalSourceService::isIpBlocked('203.0.113.50'));
t_check('ssrf: garbage ip blocked', ExternalSourceService::isIpBlocked('not-an-ip'));
t_check('ssrf: allowlist exact', ExternalSourceService::isHostAllowed('badges.example.org') === (defined('EXT_ALLOWED_HOSTS') && EXT_ALLOWED_HOSTS !== '' && str_contains(EXT_ALLOWED_HOSTS, 'badges.example.org')));
t_check('ssrf: https required (http rejected)', ExternalSourceService::httpGet('http://8.8.8.8/a.json')[0] === null
    && str_contains(ExternalSourceService::httpGet('http://8.8.8.8/a.json')[1] ?? '', 'HTTPS'));
t_check('ssrf: empty allowlist rejects host', ExternalSourceService::httpGet('https://evil-allowlist-test-xyz.example.org/a.json')[0] === null);

// ── Smart Verify: schema self-heal for the TEST database (migration 009
//    equivalents, guarded — safe to re-run on any state) ─────────────
$sv_db = test_db();
$sv_qt = $sv_db->query("SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'verification_logs' AND COLUMN_NAME = 'query_type'")->fetchColumn();
if (is_string($sv_qt) && !str_contains($sv_qt, "'file'")) {
    $sv_db->exec("ALTER TABLE verification_logs MODIFY COLUMN query_type ENUM('token','certificate_id','file','qr_image','text','external_ref') NOT NULL");
}
if ((int)$sv_db->query("SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'certificates' AND COLUMN_NAME = 'stamped_sha256'")->fetchColumn() === 0) {
    $sv_db->exec("ALTER TABLE certificates ADD COLUMN stamped_sha256 CHAR(64) NULL DEFAULT NULL AFTER sha256_hash");
}

require_once __DIR__ . '/../src/services/SmartVerifyService.php';
require_once __DIR__ . '/../src/services/FileVerifyService.php';

// ── Smart Verify: text classification ──────────────────────────────
$svToken = str_repeat('A', 20) . str_repeat('B', 23); // 43-char base64url token
$cands = SmartVerifyService::extractCandidates('http://localhost/verify.php?token=' . $svToken);
t_check('smart: self-URL token extracted', has_candidate($cands, 'token'));
function has_candidate(array $cands, string $type): bool {
    foreach ($cands as $c) { if (($c['type'] ?? '') === $type) return true; }
    return false;
}
$cands = SmartVerifyService::extractCandidates('Check my badge: https://www.coursera.org/verify/abc123xyz');
t_check('smart: couresera URL => external_ref', has_candidate($cands, 'external_ref'));
$t_ext = array_values(array_filter($cands, fn($c) => ($c['type'] ?? '') === 'external_ref'))[0] ?? null;
t_check('smart: external issuer + code', is_array($t_ext) && ($t_ext['issuer'] ?? '') === 'coursera' && ($t_ext['value'] ?? '') === 'abc123xyz');
$cands = SmartVerifyService::extractCandidates($svToken);
t_check('smart: bare 43-char token', has_candidate($cands, 'token'));
$cands = SmartVerifyService::extractCandidates('diploma CV-2026-000123 for chemistry lab');
t_check('smart: CV id in text', has_candidate($cands, 'certificate_id'));
$cands = SmartVerifyService::extractCandidates('random note without identifiers');
t_check('smart: nothing actionable => empty', empty($cands));
$cands = SmartVerifyService::extractCandidates("see https://169.254.10.10/admin and https://192.168.0.1/x");
t_check('smart: private IPs not actionable', empty(array_filter($cands, fn($c) => parse_url($c['url'] ?? '', PHP_URL_HOST) === '169.254.10.10')));

// ── Smart Verify: issuer link builders (allow-list map, no network) ─
$link = SmartVerifyService::buildIssuerLink('coursera', 'ABC123._-x');
t_check('smart: coursera link built', is_array($link) && str_starts_with($link['url'], 'https://www.coursera.org/verify/') && $link['url'] === 'https://www.coursera.org/verify/ABC123._-x');
t_check('smart: unknown issuer => null', SmartVerifyService::buildIssuerLink('doodlebug', 'abc123') === null);
t_check('smart: unsafe code chars => null', SmartVerifyService::buildIssuerLink('coursera', 'abc/../etc') === null);
t_check('smart: too-short code => null', SmartVerifyService::buildIssuerLink('coursera', 'ab') === null);
t_check('smart: other link https ok', is_array(SmartVerifyService::validateOtherLink('https://example.org/verify/certs/abc')));
t_check('smart: other link http rejected', SmartVerifyService::validateOtherLink('http://example.org/verify/certs/abc') === null);
t_check('smart: other link private-ip literal rejected', SmartVerifyService::validateOtherLink('https://169.254.10.10/verify') === null);
t_check('smart: other link localhost rejected', SmartVerifyService::validateOtherLink('https://localhost:8081/verify') === null);

// ── Smart Verify: extracted-text scan ──────────────────────────────
$cands = SmartVerifyService::scanExtractedText("DIPLOMA\nCV-2026-000123\nVerify at https://www.credly.com/badges/cred-xyz-9 soon.");
t_check('smart: scan finds ID', has_candidate($cands, 'certificate_id'));
t_check('smart: scan finds issuer url code', (bool)array_filter($cands, fn($c) => ($c['type'] ?? '') === 'external_ref' && ($c['value'] ?? '') === 'cred-xyz-9'));

// ── Smart Verify: file pipeline over runtime fixtures (temp dir only,
//    harmless bytes; all temp files deleted in finally) ───────────────
$sv_db->beginTransaction();
$svTag = bin2hex(random_bytes(4));
try {
    $sv_db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "admin", 1)')->execute(['e' => "sv-admin-$svTag@example.com"]);
    $svInstUid = $sv_db->lastInsertId();
    $sv_db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "student", 1)')->execute(['e' => "sv-student-$svTag@example.com"]);
    $svStuUid = $sv_db->lastInsertId();
    $sv_db->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:u, "SV Uni", "approved")')->execute(['u' => $svInstUid]);
    $svInstId = $sv_db->lastInsertId();
    $sv_db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "SV Student")')->execute(['u' => $svStuUid]);
    $svStudentId = $sv_db->lastInsertId();

    $svTmpFile = tempnam(sys_get_temp_dir(), 'svfx_');
    file_put_contents($svTmpFile, "%PDF-1.4\nSV Smart Verify fixture $svTag\n" . str_repeat('v', 120));
    $svOrigHash = hash_file('sha256', $svTmpFile);

    $sv_db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, file_path, status, sha256_hash)
                    VALUES ("CV-2026-800001", :iid, :sid, "SV Original", "2026-01-01", "sv-fixture.pdf", "active", :hash)')
       ->execute(['iid' => $svInstId, 'sid' => $svStudentId, 'hash' => $svOrigHash]);
    $sv_bys = 'CV-2026-800002';
    $sv_db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, file_path, status, stamped_sha256)
                    VALUES ("SV-OTHER/2026/77", :iid, :sid, "SV Stamped", "2026-01-01", "sv-fixture2.pdf", "active", :hash)')
       ->execute(['iid' => $svInstId, 'sid' => $svStudentId, 'hash' => $svOrigHash]);

    $found = FileVerifyService::findLocalByContentHash($sv_db, $svOrigHash);
    t_check('smart: byte-hash finds ORIGINAL', (count($found) === 1 && $found[0]['certificate_id'] === 'CV-2026-800001'));
    t_check('smart: invalid hash format rejected', FileVerifyService::findLocalByContentHash($sv_db, 'zz; DROP TABLE x --') === []);

    $outcome = FileVerifyService::pipelineFromTemp($sv_db, $svTmpFile);
    t_check('smart: pipeline conclusive via byte hash', ($outcome['__cert']['certificate_id'] ?? '') === 'CV-2026-800001');
    t_check('smart: stage note mentions byte hash', str_contains($outcome['__resolved']['stage'] ?? '', 'byte hash'));
    t_check('smart: resolved query_type is file', ($outcome['__resolved']['query_type'] ?? '') === 'file');

    // stamped-copy-only certainty: delete the original row's hash then retest
    $sv_db->prepare('UPDATE certificates SET sha256_hash = NULL WHERE certificate_id = "CV-2026-800001"')->execute();
    $found = FileVerifyService::findLocalByContentHash($sv_db, $svOrigHash);
    t_check('smart: byte-hash falls back to STAMPED copy', (count($found) === 1 && $found[0]['certificate_id'] === 'SV-OTHER/2026/77'));
    $outcome = FileVerifyService::pipelineFromTemp($sv_db, $svTmpFile);
    t_check('smart: stamped hash conclusive too', ($outcome['__cert']['certificate_id'] ?? '') === 'SV-OTHER/2026/77');

    // QR-image pipeline: render a harmless QR PNG of an unknown-ish token
    if (function_exists('imagepng')) {
        require_once __DIR__ . '/../src/utils/phpqrcode/phpqrcode.php';
        $svQrFile = tempnam(sys_get_temp_dir(), 'svqr_') . '.png';
        QRcode::png(str_repeat('Z', 43), $svQrFile, QR_ECLEVEL_L, 4, 2);
        $svQrTmp = tempnam(sys_get_temp_dir(), 'svqrb_');
        copy($svQrFile, $svQrTmp);
        // unknown token: pipeline must NOT resolve (nothing VALID from air)
        $outcome = FileVerifyService::pipelineFromTemp($sv_db, $svQrTmp, 'image/png');
        t_check('smart: unknown QR token unresolved', $outcome['__cert'] === null);
        unlink($svQrFile);
        unlink($svQrTmp);
    }

    // External-only reference LAW: no code path may return a certificate
    // for an external candidate — decisive, informational only.
    $extCandidates = [ ['type' => 'external_ref', 'value' => 'abc123xyz', 'issuer' => 'coursera', 'label' => 'Coursera'] ];
    $resolved = new ReflectionClass('FileVerifyService');
    $rcM = $resolved->getMethod('resolveCandidates'); $rcM->setAccessible(true);
    $hits = $rcM->invoke(null, $sv_db, $extCandidates);
    t_check('smart: external candidate carries NO cert row', (count($hits) === 1 && $hits[0]['cert'] === null));
    $fcM = $resolved->getMethod('firstConclusive'); $fcM->setAccessible(true);
    $conclusive = $fcM->invoke(null, $hits);
    t_check('smart: external candidate never yields VALID source', is_array($conclusive) && $conclusive['cert'] === null);

    // Typed-external (issuer dropdown on unknown ID): link builder only —
    // Verdict handling stays in verify.php which renders INVALID + card.
    t_check('smart: issuer-link for unknown code', is_array(SmartVerifyService::buildIssuerLink('credly', 'badge-9')));
} finally {
    $sv_db->rollBack();
    if (isset($svTmpFile)) @unlink($svTmpFile);
}

// ══════════════════════════════════════════════════════════════════════
// Phase 2 — TrustScoreService (rule-based trust score) + ReportService
// (dompdf verification report). No schema changes: safe to run directly.
// ══════════════════════════════════════════════════════════════════════
require_once __DIR__ . '/../src/services/TrustScoreService.php';
require_once __DIR__ . '/../src/services/ReportService.php';
$ts_db = test_db();

// The public (non-transactional) test DB rows may be empty — everything so
// far ran inside rolled-back transactions. Seed a self-contained family of
// rows (active / expired / revoked / superseded / tampered) with REAL
// hashes + signatures so the score expectations are exact.
$ts_file = null;
$ts_db->beginTransaction();
try {
    $tsTag = (string)time();
    $ts_db->prepare('INSERT INTO users (email, password_hash, role, is_verified)
                     VALUES (:e, "x", "institution", 1)')->execute(['e' => "ts_$tsTag@example.test"]);
    $tsUser = (int)$ts_db->lastInsertId();
    $ts_db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "Trust Student")')->execute(['u' => $tsUser]);
    $tsSid = (int)$ts_db->lastInsertId();

    $tsPair = CryptoService::generateRSAKeyPair();
    $ts_db->prepare('INSERT INTO institutions (user_id, name, status, public_key, encrypted_private_key)
                     VALUES (:u, "Trust Score Uni", "approved", :pk, "")')
        ->execute(['u' => $tsUser, 'pk' => $tsPair['public_key']]);
    $tsIid = (int)$ts_db->lastInsertId();

    // Harmless text fixture file under private_data/uploads/ (the ONLY way
    // the hash check has real bytes to baseline against).
    $ts_file = __DIR__ . '/../private_data/uploads/ts_fixture_' . $tsTag . '.pdf';
    file_put_contents($ts_file, "%PDF-1.4\nTrust Score fixture $tsTag\n" . str_repeat('t', 100));

    $ts_specs = [
        'CV-2026-810001' => 'active',
        'CV-2026-810002' => 'active',   // +past expiry_date => EXPIRED verdict
        'CV-2026-810003' => 'revoked',
        'CV-2026-810004' => 'superseded',
        'CV-2026-810005' => 'active',   // +wrong stored hash => TAMPERED cap
    ];
    foreach ($ts_specs as $tsCid => $tsStatus) {
        $tsCertData = [
            'certificate_id' => $tsCid,
            'institution_id' => $tsIid,
            'student_id'     => $tsSid,
            'title'          => 'TS Score',
            'issue_date'     => '2026-01-01',
            'expiry_date'    => $tsCid === 'CV-2026-810002' ? '2026-01-31' : null,
        ];
        $tsAbs = $ts_file;
        $tsHash = CryptoService::computeCertificateHash($tsCertData, $tsAbs);
        // TAMPERED row stores a wrong hash so the critical hash check fails.
        $tsStoredHash = $tsCid === 'CV-2026-810005'
            ? str_repeat('0', 64)
            : $tsHash;
        $tsSig = CryptoService::signCertificateHash($tsHash, $tsPair['private_key']);
        $ts_db->prepare('INSERT INTO certificates
            (certificate_id, institution_id, student_id, title, issue_date, expiry_date,
             file_path, status, sha256_hash, digital_signature, version)
            VALUES (:cid, :iid, :sid, "TS Score", "2026-01-01", :ed, :fp, :st, :h, :sig, 1)')
            ->execute([
                'cid' => $tsCid, 'iid' => $tsIid, 'sid' => $tsSid, 'ed' => $tsCertData['expiry_date'],
                'fp' => basename($ts_file), 'st' => $tsStatus, 'h' => $tsStoredHash, 'sig' => $tsSig,
            ]);
    }

    $ts_rows = $ts_db->prepare('
        SELECT c.*, i.name AS institution_name, i.public_key, s.full_name AS student_name
        FROM certificates c
        JOIN institutions i ON c.institution_id = i.id
        JOIN students s ON c.student_id = s.id
        WHERE c.certificate_id LIKE "CV-2026-810%" ORDER BY c.id
    ');
    $ts_rows->execute();
    $ts_all = $ts_rows->fetchAll();

    t_check('trust: seeded 5 scoring rows', count($ts_all) === 5);

    $ts_expect = [
        'CV-2026-810001' => [100, 'VALID'],
        'CV-2026-810002' => [90,  'EXPIRED'],
        'CV-2026-810003' => [90,  'REVOKED'],
        'CV-2026-810004' => [90,  'SUPERSEDED'],
        'CV-2026-810005' => [40,  'TAMPERED'],
    ];
    foreach ($ts_all as $ts_row) {
        $ts_trusted = TrustScoreService::compute($ts_db, $ts_row);
        $ts_result  = VerificationService::verify($ts_db, $ts_row);
        list($tsScore, $tsVerdict) = $ts_expect[$ts_row['certificate_id']];
        t_check(
            "trust: exact score {$ts_row['certificate_id']} = $tsScore",
            $ts_trusted['score'] === $tsScore
        );
        t_check(
            "trust: replay verdict = engine verdict ({$ts_row['certificate_id']})",
            $ts_trusted['verdict'] === $tsVerdict && $ts_result['verdict'] === $tsVerdict
        );
        t_check(
            "trust: 5 checks present ({$ts_row['certificate_id']})",
            count($ts_trusted['checks']) === 5
                && array_column($ts_trusted['checks'], 'id') === ['exists', 'status', 'hash', 'signature', 'expiry']
        );
        // Cap law: a critical failure (hash/signature/exists) never exceeds 40.
        $tsCriticalFailed = false;
        foreach ($ts_trusted['checks'] as $tsCheck) {
            if ($tsCheck['critical'] && !$tsCheck['pass']) {
                $tsCriticalFailed = true;
            }
        }
        if ($tsCriticalFailed) {
            t_check("trust: critical cap ({$ts_row['certificate_id']})", $ts_trusted['score'] <= 40);
        }
    }

    // Report generation (dompdf installed via Composer in this workspace).
    if (ReportService::dompdfAvailable() && count($ts_all) > 0) {
        $tsCert    = $ts_all[0];
        $tsTrusted = TrustScoreService::compute($ts_db, $tsCert);
        $tsRes     = VerificationService::verify($ts_db, $tsCert);
        $tsPdf     = ReportService::buildReportPdf($tsCert, $tsRes['detail'], $tsTrusted, $tsRes['superseded_by'] ?: null);
        t_check('report: PDF generated with %PDF header', strncmp($tsPdf, '%PDF', 4) === 0);
        t_check('report: PDF contains no key/block material', $tsPdf === ''
            || (!str_contains($tsPdf, '-----BEGIN') && !str_contains($tsPdf, 'PRIVATE KEY')));
        t_check('report: PDF substantial (verdict + QR embedded)', strlen($tsPdf) > 2000);
    } else {
        t_check('report: dompdf not installed (generate skipped)', true);
        t_check('report: no-key check skipped', true);
    }
} finally {
    $ts_db->rollBack();
    if ($ts_file) @unlink($ts_file);
}

// Gauge arc: monotonic sweep across the semicircle; endpoints exact.
$gaArc0 = ReportService::gaugeArc(0);
$gaArc100 = ReportService::gaugeArc(100);
t_check('gauge: score 0 is exact start of arc', preg_match('/^M8 58 A47 47 0 0 1 8\.0 58\.0$/', $gaArc0) === 1);
t_check('gauge: score 100 reaches the arc end', str_contains($gaArc100, '102.0 58.0') || str_contains($gaArc100, '102.00 58.0'));
$gaPrevX = null;
$gaMonotonic = true;
for ($gaS = 0; $gaS <= 100; $gaS += 5) {
    if (preg_match('/0 0 1 ([\d.]+) ([\d.]+)$/', ReportService::gaugeArc($gaS), $gaM)) {
        $gaX = (float)$gaM[1];
        if ($gaPrevX !== null && $gaX < $gaPrevX) {
            $gaMonotonic = false;
        }
        $gaPrevX = $gaX;
    }
}
t_check('gauge: x sweeps monotonically with score', $gaMonotonic);

exit(t_summary('test_upload_validation') ? 0 : 1);
