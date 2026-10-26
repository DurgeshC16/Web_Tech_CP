<?php
// tests/test_workflow.php
// Regression tests for core-workflow consistency that test_certflow.php
// does not cover:
//   - ownership decisions (can_access_certificate) across roles
//   - effectiveStatus() display override
//   - supersession verdict + superseded_by pointer, and its precedence
//   - hash / signature failure boundaries
//   - QR token format
// DB-backed; runs against the isolated test database.
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/VerificationService.php';

$db = test_db();
$tag = bin2hex(random_bytes(4));

// ── Fixtures ──────────────────────────────────────────────────────────
$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "admin", 1)')
   ->execute(['e' => "wf-admin-$tag@example.com"]);
$admin_uid = (int)$db->lastInsertId();
$keys = CryptoService::generateRSAKeyPair();
$db->prepare('INSERT INTO institutions (user_id, name, status) VALUES (:u, "WF Uni", "approved")')
   ->execute(['u' => $admin_uid]);
$inst_id = (int)$db->lastInsertId();
test_insert_institution_key($db, $inst_id, $keys['public_key'], CryptoService::encryptPrivateKey($keys['private_key']));

$db->prepare('INSERT INTO users (email, password_hash, role, is_verified) VALUES (:e, "x", "student", 1)')
   ->execute(['e' => "wf-student-$tag@example.com"]);
$student_uid = (int)$db->lastInsertId();
$db->prepare('INSERT INTO students (user_id, full_name) VALUES (:u, "WF Student")')->execute(['u' => $student_uid]);
$student_id = (int)$db->lastInsertId();

/** Create a certificate row + backing file; returns [cid, qr, file, id]. */
function wf_make_cert($db, $inst_id, $student_id, $keys, $tag, $num, $status = 'active') {
    $cid = sprintf('CV-2026-%06d', $num);
    $qr = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $filename = "wf-$tag-$num.pdf";
    $path = __DIR__ . '/../private_data/uploads/' . $filename;
    file_put_contents($path, "%PDF-1.4 wf $tag $num\n" . str_repeat('W', 200));
    $data = [
        'certificate_id' => $cid,
        'institution_id' => $inst_id,
        'student_id'     => $student_id,
        'title'          => 'WF Degree ' . $num,
        'issue_date'     => '2024-01-01',
        'expiry_date'    => '2099-01-01',
    ];
    $hash = CryptoService::computeCertificateHash($data, $path);
    $sig = CryptoService::signCertificateHash($hash, $keys['private_key']);
    // Defensive: clear any stale row with this id from an earlier aborted run.
    $db->prepare('DELETE FROM certificates WHERE certificate_id = :cid')->execute(['cid' => $cid]);
    $db->prepare('INSERT INTO certificates (certificate_id, institution_id, student_id, title, issue_date, expiry_date, file_path, status, version, qr_token, sha256_hash, digital_signature)
                  VALUES (:cid, :iid, :sid, :title, "2024-01-01", "2099-01-01", :fp, :st, 1, :qr, :hash, :sig)')
       ->execute(['cid' => $cid, 'iid' => $inst_id, 'sid' => $student_id, 'title' => 'WF Degree ' . $num, 'fp' => $filename, 'st' => $status, 'qr' => $qr, 'hash' => $hash, 'sig' => $sig]);
    return ['cid' => $cid, 'qr' => $qr, 'file' => $filename, 'id' => (int)$db->lastInsertId()];
}

// Run-unique numeric suffix so re-runs never collide on certificate_id.
$base = random_int(100000, 899998);
$a = wf_make_cert($db, $inst_id, $student_id, $keys, $tag, $base + 1);
$b = wf_make_cert($db, $inst_id, $student_id, $keys, $tag, $base + 2);

// Rotate to v2 after issuance: old certificates must continue to verify
// against the retired v1 public key stored with their key_id.
$newKeys = CryptoService::generateRSAKeyPair();
$db->prepare('UPDATE institution_keys SET status="retired",valid_to=NOW() WHERE institution_id=:iid AND key_id=1')->execute(['iid'=>$inst_id]);
$db->prepare('INSERT INTO institution_keys (institution_id,key_id,public_key,encrypted_private_key,status,valid_from) VALUES (:iid,2,:pub,:priv,"active",NOW())')
   ->execute(['iid'=>$inst_id,'pub'=>$newKeys['public_key'],'priv'=>CryptoService::encryptPrivateKey($newKeys['private_key'])]);

echo "== workflow consistency ==\n";

// ── 1. Ownership matrix (can_access_certificate) ──────────────────────
$cert = ['institution_id' => $inst_id, 'student_id' => $student_id];
t_check('owner admin allowed', can_access_certificate($cert, 'admin', $inst_id) === true);
t_check('foreign admin denied', can_access_certificate($cert, 'admin', $inst_id + 1) === false);
t_check('owner student allowed', can_access_certificate($cert, 'student', $student_id) === true);
t_check('foreign student denied', can_access_certificate($cert, 'student', $student_id + 1) === false);
t_check('unknown role denied', can_access_certificate($cert, 'super_admin', $inst_id) === false);
t_check('zero owner denied', can_access_certificate($cert, 'admin', 0) === false);
t_check('non-array cert denied', can_access_certificate(null, 'admin', $inst_id) === false);

// ── 2. effectiveStatus() display override ─────────────────────────────
t_check('active+past expiry => expired', VerificationService::effectiveStatus(['status' => 'active', 'expiry_date' => '2020-01-01']) === 'expired');
t_check('active+future expiry => active', VerificationService::effectiveStatus(['status' => 'active', 'expiry_date' => '2099-01-01']) === 'active');
t_check('active+no expiry => active', VerificationService::effectiveStatus(['status' => 'active', 'expiry_date' => null]) === 'active');
t_check('revoked stays revoked', VerificationService::effectiveStatus(['status' => 'revoked', 'expiry_date' => '2020-01-01']) === 'revoked');
t_check('superseded stays superseded', VerificationService::effectiveStatus(['status' => 'superseded', 'expiry_date' => '2099-01-01']) === 'superseded');

// ── 3. QR token format (32 bytes base64url, unpadded => 43 chars) ─────
t_check('QR token is 43-char base64url', preg_match('#^[A-Za-z0-9_-]{43}$#', $a['qr']) === 1);

// ── 4. Baseline: both active certificates verify VALID ────────────────
$ra = VerificationService::verify($db, VerificationService::findByToken($db, $a['qr']));
t_check('new active cert => VALID', $ra['verdict'] === 'VALID');
t_check('retired v1 key still verifies its old certificates', VerificationService::verify($db, VerificationService::findByToken($db, $b['qr']))['verdict'] === 'VALID');

// ── 5. Supersession: status + pointer, and precedence over tampering ──
$db->prepare('UPDATE certificates SET status = "superseded", superseded_by_id = :newid WHERE id = :old')
   ->execute(['newid' => $b['id'], 'old' => $a['id']]);
$ra = VerificationService::verify($db, VerificationService::findByToken($db, $a['qr']));
t_check('superseded cert => SUPERSEDED', $ra['verdict'] === 'SUPERSEDED');
t_check('superseded_by points at the new cert', ($ra['superseded_by']['certificate_id'] ?? null) === $b['cid']);
t_check('superseded_by includes the new QR token', ($ra['superseded_by']['qr_token'] ?? null) === $b['qr']);
t_check('superseding cert still VALID', VerificationService::verify($db, VerificationService::findByToken($db, $b['qr']))['verdict'] === 'VALID');

// Tamper the superseded file: status is server-authoritative, so the
// verdict must remain SUPERSEDED (not TAMPERED).
file_put_contents(__DIR__ . '/../private_data/uploads/' . $a['file'], 'TAMPERED');
t_check('superseded + tampered => still SUPERSEDED', VerificationService::verify($db, VerificationService::findByToken($db, $a['qr']))['verdict'] === 'SUPERSEDED');

// ── 6. Hash / signature failure boundaries on the active cert B ───────
$bp = __DIR__ . '/../private_data/uploads/' . $b['file'];
file_put_contents($bp, file_get_contents($bp) . 'X');
t_check('altered file => TAMPERED', VerificationService::verify($db, VerificationService::findByToken($db, $b['qr']))['verdict'] === 'TAMPERED');
// Restore by re-issuing B's correct hash/signature for the original bytes.
$orig = "%PDF-1.4 wf $tag " . ($base + 2) . "\n" . str_repeat('W', 200);
file_put_contents($bp, $orig);
$dataB = ['certificate_id' => $b['cid'], 'institution_id' => $inst_id, 'student_id' => $student_id, 'title' => 'WF Degree ' . ($base + 2), 'issue_date' => '2024-01-01', 'expiry_date' => '2099-01-01'];
$hashB = CryptoService::computeCertificateHash($dataB, $bp);
$db->prepare('UPDATE certificates SET sha256_hash = :h, digital_signature = :s WHERE id = :id')
   ->execute(['h' => $hashB, 's' => CryptoService::signCertificateHash($hashB, $keys['private_key']), 'id' => $b['id']]);
t_check('restored => VALID again', VerificationService::verify($db, VerificationService::findByToken($db, $b['qr']))['verdict'] === 'VALID');

// Valid hash but a signature from a different key => TAMPERED.
$otherKeys = CryptoService::generateRSAKeyPair();
$db->prepare('UPDATE certificates SET digital_signature = :s WHERE id = :id')
   ->execute(['s' => CryptoService::signCertificateHash($hashB, $otherKeys['private_key']), 'id' => $b['id']]);
t_check('wrong-key signature => TAMPERED', VerificationService::verify($db, VerificationService::findByToken($db, $b['qr']))['verdict'] === 'TAMPERED');

// Restore a good signature, then corrupt the stored hash => TAMPERED.
$db->prepare('UPDATE certificates SET digital_signature = :s WHERE id = :id')
   ->execute(['s' => CryptoService::signCertificateHash($hashB, $keys['private_key']), 'id' => $b['id']]);
$db->prepare('UPDATE certificates SET sha256_hash = :h WHERE id = :id')
   ->execute(['h' => str_repeat('0', 64), 'id' => $b['id']]);
t_check('corrupted stored hash => TAMPERED', VerificationService::verify($db, VerificationService::findByToken($db, $b['qr']))['verdict'] === 'TAMPERED');

// Missing backing file => TAMPERED (cannot recompute the hash).
@unlink($bp);
t_check('missing file => TAMPERED', VerificationService::verify($db, VerificationService::findByToken($db, $b['qr']))['verdict'] === 'TAMPERED');

// ── Cleanup (break the self-reference before deleting) ────────────────
$db->prepare('UPDATE certificates SET superseded_by_id = NULL, previous_version_id = NULL WHERE institution_id = :i')->execute(['i' => $inst_id]);
$db->prepare('DELETE FROM certificates WHERE institution_id = :i')->execute(['i' => $inst_id]);
@unlink(__DIR__ . '/../private_data/uploads/' . $a['file']);
@unlink(__DIR__ . '/../private_data/uploads/' . $b['file']);
$db->prepare('DELETE FROM students WHERE id = :s')->execute(['s' => $student_id]);
$db->prepare('DELETE FROM institutions WHERE id = :i')->execute(['i' => $inst_id]);
$db->prepare('DELETE FROM users WHERE id IN (:a, :s)')->execute(['a' => $admin_uid, 's' => $student_uid]);

exit(t_summary('test_workflow') ? 0 : 1);
