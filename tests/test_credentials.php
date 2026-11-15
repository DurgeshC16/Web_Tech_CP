<?php
// tests/test_credentials.php
// Portable signed credentials (CredentialService + public/credential.php):
// independent verification, tamper detection, the attacker-key case that
// makes the key-directory comparison necessary, no secret leakage, OpenSSL
// CLI interoperability, and the HTTP endpoint.

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/VerificationService.php';
require_once __DIR__ . '/../src/services/CredentialService.php';
require_once __DIR__ . '/../src/utils/helpers.php';

$db = test_db();
$db->exec(file_get_contents(__DIR__ . '/../database/migrations/014_verify_rate_limiter.sql'));
$tag = bin2hex(random_bytes(4));
$file = __DIR__ . '/../private_data/uploads/cred-fixture-' . $tag . '.pdf';

// ── Fixture (committed: the HTTP part needs it visible to php -S) ─────
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "admin", 1)')->execute(['e' => "cred-admin-$tag@example.com"]);
$adminUid = (int)$db->lastInsertId();
$db->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:u, :n, "approved")')->execute(['u' => $adminUid, 'n' => "Credential Uni $tag"]);
$instId = (int)$db->lastInsertId();
$keys = CryptoService::generateRSAKeyPair();
test_insert_institution_key($db, $instId, $keys['public_key'], CryptoService::encryptPrivateKey($keys['private_key']));
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "student", 1)')->execute(['e' => "cred-stu-$tag@example.com"]);
$stuUid = (int)$db->lastInsertId();
$db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "Crédential Stüdent")')->execute(['u' => $stuUid]);
$stuId = (int)$db->lastInsertId();
file_put_contents($file, "%PDF-1.4 credential fixture $tag\n" . str_repeat('C', 300));
$cid = 'CRED-' . strtoupper($tag);
$token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
$fields = ['certificate_id' => $cid, 'institution_id' => $instId, 'student_id' => $stuId,
           'title' => 'Données & Systèmes — Advanced', 'issue_date' => '2025-03-01', 'expiry_date' => '2099-12-31'];
$h = CryptoService::computeCertificateHash($fields, $file);
$db->prepare('INSERT INTO certificates (certificate_id, institution_id, key_id, student_id, title, issue_date, expiry_date, file_path, status, qr_token, sha256_hash, file_sha256, digital_signature)
              VALUES (:c, :i, 1, :s, :t, "2025-03-01", "2099-12-31", :f, "active", :q, :h, :fh, :sig)')
   ->execute(['c' => $cid, 'i' => $instId, 's' => $stuId, 't' => $fields['title'], 'f' => basename($file), 'q' => $token,
              'h' => $h, 'fh' => hash_file('sha256', $file), 'sig' => CryptoService::signCertificateHash($h, $keys['private_key'])]);

try {
    $cert = VerificationService::findByCertificateId($db, $cid);
    $cred = CredentialService::build($db, $cert);

    // ── Shape + independent verification ──────────────────────────────
    t_check('credential built', is_array($cred) && $cred['format'] === CredentialService::FORMAT);
    t_check('status at export = VALID', $cred['status_at_export']['verdict'] === 'VALID');
    t_check('canonical string reproduces the stored digest', hash('sha256', CredentialService::canonicalString($cred)) === $h);
    t_check('offline verification: valid (UTF-8 title)', CredentialService::verifyOffline($cred)['valid'] === true);

    $json = json_encode($cred);
    foreach (['PRIVATE KEY', 'GCM1.', $token, basename($file), 'encrypted_private_key', 'file_path'] as $secret) {
        t_check('export contains no secret/internal value: ' . substr($secret, 0, 14), !str_contains($json, $secret));
    }

    // ── Tampering ─────────────────────────────────────────────────────
    $t = $cred; $t['certificate']['title'] = 'Forged Title';
    $r = CredentialService::verifyOffline($t);
    t_check('edited title: digest fails', $r['digest'] === false && $r['valid'] === false);
    $t = $cred; $t['certificate']['expiry_date'] = '2199-12-31';
    t_check('extended expiry: digest fails', CredentialService::verifyOffline($t)['valid'] === false);
    $t = $cred; $t['certificate']['file_sha256'] = hash('sha256', 'other file');
    t_check('different file hash: digest fails', CredentialService::verifyOffline($t)['valid'] === false);
    $t = $cred; $t['proof']['signature_base64'] = base64_encode(random_bytes(256));
    $r = CredentialService::verifyOffline($t);
    t_check('random signature: signature fails', $r['digest'] === true && $r['signature'] === false);
    $t = $cred; $t['proof']['key_fingerprint_sha256'] = str_repeat('AB:', 31) . 'AB';
    t_check('fingerprint not matching the embedded key: fails', CredentialService::verifyOffline($t)['fingerprint'] === false);

    // Attacker re-signs with their OWN key and embeds it: the file is
    // internally consistent, so only a comparison with the PUBLISHED key
    // can reveal it — exactly what offline_verify.php does.
    $evil = CryptoService::generateRSAKeyPair();
    $t = $cred; $t['certificate']['title'] = 'Forged Title';
    $t['proof']['digest_sha256'] = hash('sha256', CredentialService::canonicalString($t));
    $t['proof']['signature_base64'] = CryptoService::signCertificateHash($t['proof']['digest_sha256'], $evil['private_key']);
    $t['proof']['public_key_pem'] = trim($evil['public_key']);
    $t['proof']['key_fingerprint_sha256'] = CryptoService::fingerprintPublicKey($evil['public_key']);
    t_check('attacker-key credential is self-consistent (why key trust matters)', CredentialService::verifyOffline($t)['valid'] === true);
    t_check('…but its key differs from the institution\'s published key',
        $t['proof']['key_fingerprint_sha256'] !== CryptoService::fingerprintPublicKey($keys['public_key']));

    // ── OpenSSL command-line interoperability (paper claim) ───────────
    $openssl = null;
    foreach (['C:\\xampp\\apache\\bin\\openssl.exe', '/usr/bin/openssl'] as $cand) {
        if (is_file($cand)) { $openssl = $cand; break; }
    }
    if ($openssl === null && trim((string)shell_exec('openssl version 2>&1')) !== '') {
        $openssl = 'openssl';
    }
    if ($openssl) {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cv_cred_' . $tag;
        @mkdir($dir);
        file_put_contents("$dir/digest.txt", $cred['proof']['digest_sha256']);
        file_put_contents("$dir/sig.bin", base64_decode($cred['proof']['signature_base64']));
        file_put_contents("$dir/issuer.pem", $cred['proof']['public_key_pem'] . "\n");
        $out = shell_exec(escapeshellarg($openssl) . ' dgst -sha256 -verify ' . escapeshellarg("$dir/issuer.pem")
            . ' -signature ' . escapeshellarg("$dir/sig.bin") . ' ' . escapeshellarg("$dir/digest.txt") . ' 2>&1');
        t_check('OpenSSL CLI verifies the credential signature', is_string($out) && str_contains($out, 'Verified OK'));
        array_map('unlink', glob("$dir/*")); @rmdir($dir);
    } else {
        t_check('OpenSSL CLI not available (skipped)', true);
    }

    // ── Missing file: no export ───────────────────────────────────────
    $noFile = $cert; $noFile['file_path'] = 'does-not-exist.pdf';
    t_check('missing stored file: build() returns null', CredentialService::build($db, $noFile) === null);

    // ── HTTP endpoint via php -S ──────────────────────────────────────
    if (function_exists('curl_init')) {
        $port = (int)(getenv('CV_TEST_CRED_PORT') ?: 8171);
        $env = getenv();
        $env['CV_DB_NAME'] = getenv('CV_TEST_DB') ?: 'certivault_test';
        $env['CV_ENV'] = 'development';
        $log = sys_get_temp_dir() . '/cv_cred_http.log';
        $proc = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', realpath(__DIR__ . '/../public')],
            [0 => ['pipe', 'r'], 1 => ['file', $log, 'a'], 2 => ['file', $log, 'a']], $pipes, null, $env);
        $get = function (string $path) use ($port) {
            $ch = curl_init("http://127.0.0.1:$port/$path");
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_TIMEOUT => 20]);
            $raw = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $hs = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            curl_close($ch);
            return $raw === false ? [0, '', ''] : [$code, substr($raw, 0, $hs), substr($raw, $hs)];
        };
        for ($i = 0; $i < 50 && $get('offline_verify.php')[0] !== 200; $i++) { usleep(200000); }
        $db->exec("DELETE FROM verify_rate WHERE ip = '127.0.0.1'");

        [$code, $hdr, $body] = $get('credential.php?token=' . $token);
        $j = json_decode($body, true);
        t_check('HTTP token -> 200 JSON credential', $code === 200 && is_array($j) && ($j['certificate']['certificate_id'] ?? '') === $cid);
        t_check('HTTP served as a download', stripos($hdr, 'Content-Disposition: attachment') !== false);
        t_check('HTTP credential verifies offline', is_array($j) && CredentialService::verifyOffline($j)['valid'] === true);
        [$code] = $get('credential.php?certificate_id=' . rawurlencode(strtolower($cid)));
        t_check('HTTP lower-case certificate_id -> 200', $code === 200);
        [$code, , $body] = $get('credential.php?certificate_id=NOPE-' . $tag);
        t_check('HTTP unknown id -> 404 not_found', $code === 404 && str_contains($body, 'not_found'));
        [$code] = $get('credential.php');
        t_check('HTTP no identifier -> 400', $code === 400);
        [$code, , $body] = $get('offline_verify.php');
        t_check('offline verifier page served with its external script', $code === 200 && str_contains($body, 'assets/js/credential-verify.js'));
        [$code, , $body] = $get('well-known-keys.php');
        $dirJson = json_decode($body, true);
        $entry = array_values(array_filter($dirJson['keys'] ?? [], fn($k) => (int)$k['institution_id'] === $instId))[0] ?? null;
        t_check('key directory always on and lists institution_id + fingerprint',
            $code === 200 && $entry !== null && $entry['fingerprint_sha256'] === CryptoService::fingerprintPublicKey($keys['public_key']));
        $logged = $db->prepare("SELECT COUNT(*) FROM verification_logs WHERE verifier_ip = '127.0.0.1' AND detail LIKE 'credential export%' AND certificate_id_found = :c");
        $logged->execute(['c' => $cid]);
        t_check('exports are audit-logged', (int)$logged->fetchColumn() >= 2);

        proc_terminate($proc);
        proc_close($proc);
        $db->exec("DELETE FROM verify_rate WHERE ip = '127.0.0.1'");
    } else {
        t_check('curl unavailable: HTTP checks skipped', true);
    }
} finally {
    $db->prepare('DELETE FROM verification_logs WHERE certificate_id_found = :c')->execute(['c' => $cid]);
    $db->prepare('DELETE FROM certificates WHERE certificate_id = :c')->execute(['c' => $cid]);
    $db->prepare('DELETE FROM students WHERE id = :s')->execute(['s' => $stuId]);
    $db->prepare('DELETE FROM institution_keys WHERE institution_id = :i')->execute(['i' => $instId]);
    $db->prepare('DELETE FROM institutions WHERE id = :i')->execute(['i' => $instId]);
    $db->prepare('DELETE FROM users WHERE id IN (:a, :b)')->execute(['a' => $adminUid, 'b' => $stuUid]);
    @unlink($file);
}

exit(t_summary('test_credentials') ? 0 : 1);
