<?php
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/AttestedCredentialService.php';
require_once __DIR__ . '/../src/services/TrustScoreService.php';

$keys = CryptoService::generateRSAKeyPair();
$record = [
    'student_id'=>41, 'student_name'=>'Ada Example', 'issuer_slug'=>'coursera', 'issuer_label'=>'Coursera',
    'issuer_code'=>'ABC123', 'verification_url'=>'https://www.coursera.org/verify/ABC123',
    'title'=>'Algorithms', 'issue_date'=>'2025-02-03', 'file_sha256'=>str_repeat('a',64),
    'attesting_institution_id'=>12, 'attesting_institution_name'=>'Example University', 'attested_at'=>'2026-10-26 12:00:00',
];
$hash = AttestedCredentialService::canonicalHash($record);
$sig = CryptoService::signCertificateHash($hash, $keys['private_key']);
t_check('external credential: canonical hash reproducible', hash_equals($hash, AttestedCredentialService::canonicalHash($record)));
t_check('external credential: baseline institutional signature valid', CryptoService::verifyCertificateSignature($hash, $sig, $keys['public_key']));

$tamperCases = [
    'student_id'=>'student_id', 'student_name'=>'student_name', 'issuer_slug'=>'issuer_slug',
    'issuer_label'=>'issuer_label', 'issuer_code'=>'issuer_code', 'verification_url'=>'verification_url',
    'title'=>'title', 'issue_date'=>'issue_date', 'file_sha256'=>'file_sha256',
    'attesting_institution_id'=>'attesting_institution_id', 'attesting_institution_name'=>'attesting_institution_name',
    'attested_at'=>'attested_at',
];
foreach ($tamperCases as $field) {
    $changed = $record;
    $changed[$field] = is_int($changed[$field]) ? $changed[$field] + 1 : ((string)$changed[$field] . '-tampered');
    $changedHash = AttestedCredentialService::canonicalHash($changed);
    t_check('external credential: tamper signed field ' . $field,
        !hash_equals($hash, $changedHash) && !CryptoService::verifyCertificateSignature($changedHash, $sig, $keys['public_key']));
}

class AttestedCredentialNoRegistryDb { public function query($sql) { throw new RuntimeException('no registry'); } }
$urlDb = new AttestedCredentialNoRegistryDb();
[$goodUrl] = AttestedCredentialService::validateIssuerUrl($urlDb, 'coursera', 'https://www.coursera.org/verify/ABC123');
t_check('external credential: official Coursera exact host allowed', is_array($goodUrl));
foreach ([
    'https://coursera.org.evil.example/verify/ABC123',
    'https://www.coursera.org.example/verify/ABC123',
    'https://www.coursera.org:444/verify/ABC123',
    'http://www.coursera.org/verify/ABC123',
    'https://www.coursera.org@evil.example/verify/ABC123',
] as $unsafeUrl) {
    [$badUrl] = AttestedCredentialService::validateIssuerUrl($urlDb, 'coursera', $unsafeUrl);
    t_check('external credential: rejected untrusted URL ' . parse_url($unsafeUrl, PHP_URL_HOST), $badUrl === null);
}
t_check('external credential: self declaration never VALID',
    AttestedCredentialService::verdict(null, ['status'=>'SELF_DECLARED']) === 'SELF_DECLARED');
t_check('external credential: withdrawn never VALID',
    AttestedCredentialService::verdict(null, ['status'=>'WITHDRAWN']) === 'WITHDRAWN');
t_check('external credential: edited attestation state cannot downgrade to self-declared',
    AttestedCredentialService::verdict(null, ['status'=>'SELF_DECLARED','signature'=>'signature','attestation_hash'=>str_repeat('a',64)]) === 'TAMPERED');
t_check('external credential: cleared withdrawal marker is tampering',
    AttestedCredentialService::verdict(null, ['status'=>'ATTESTED','withdrawn_at'=>'2026-10-26']) === 'TAMPERED');
$unattestedScore = TrustScoreService::computeExternalCredential(null, ['status'=>'SELF_DECLARED']);
t_check('external credential: self-declared score is zero and capped', $unattestedScore['score'] === 0 && $unattestedScore['verdict'] === 'SELF_DECLARED');

// Optional MySQL integration: use the isolated test DB from bootstrap, never
// the application's certivault database. This also exercises decrypt/sign/
// persistence/verification through the real approved institution record.
try {
    $db = test_db();
    $db->exec("CREATE TABLE IF NOT EXISTS external_credentials (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY, public_token CHAR(43) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
        student_id INT NOT NULL, student_name VARCHAR(255) NOT NULL, issuer_slug VARCHAR(300) NOT NULL, issuer_label VARCHAR(120) NOT NULL,
        verification_url VARCHAR(2048) NOT NULL, issuer_code VARCHAR(255) NULL, title VARCHAR(200) NOT NULL, issue_date DATE NOT NULL,
        file_path VARCHAR(255) NULL, file_sha256 CHAR(64) NULL, status ENUM('SELF_DECLARED','ATTESTED','WITHDRAWN') NOT NULL DEFAULT 'SELF_DECLARED',
        attesting_institution_id INT NULL, attesting_key_id INT NULL, attesting_institution_name VARCHAR(255) NULL, attested_at DATETIME NULL,
        attestation_hash CHAR(64) NULL, signature TEXT NULL, withdrawn_at DATETIME NULL, withdrawn_by INT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $tag = bin2hex(random_bytes(6));
    $db->prepare('INSERT INTO users (email,password_hash,role,is_verified) VALUES (:e,"x","student",1)')->execute(['e'=>"attested-student-$tag@example.test"]);
    $studentUser = (int)$db->lastInsertId();
    $db->prepare('INSERT INTO students (user_id,full_name) VALUES (:u,"Attested Test Student")')->execute(['u'=>$studentUser]);
    $studentId = (int)$db->lastInsertId();
    $db->prepare('INSERT INTO users (email,password_hash,role,is_verified) VALUES (:e,"x","admin",1)')->execute(['e'=>"attested-admin-$tag@example.test"]);
    $adminUser = (int)$db->lastInsertId();
    $pair = CryptoService::generateRSAKeyPair();
    $db->prepare('INSERT INTO institutions (user_id,name,status) VALUES (:u,"Attested Test University","approved")')
        ->execute(['u'=>$adminUser]);
    $institutionId = (int)$db->lastInsertId();
    test_insert_institution_key($db,$institutionId,$pair['public_key'],CryptoService::encryptPrivateKey($pair['private_key']));
    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $insert = $db->prepare('INSERT INTO external_credentials (public_token,student_id,student_name,issuer_slug,issuer_label,verification_url,issuer_code,title,issue_date,status) VALUES (:token,:sid,"Attested Test Student","coursera","Coursera","https://www.coursera.org/verify/TEST01","TEST01","Test Course","2025-01-10","SELF_DECLARED")');
    $insert->execute(['token'=>$token,'sid'=>$studentId]);
    $credentialId = (int)$db->lastInsertId();
    AttestedCredentialService::attest($db, $credentialId, $institutionId);
    $get = $db->prepare('SELECT * FROM external_credentials WHERE id=:id'); $get->execute(['id'=>$credentialId]); $persisted = $get->fetch(PDO::FETCH_ASSOC);
    t_check('external credential: approved institution attests with valid signature', AttestedCredentialService::verdict($db,$persisted)==='ATTESTED');
    $db->prepare('UPDATE external_credentials SET title="Changed title" WHERE id=:id')->execute(['id'=>$credentialId]);
    $get->execute(['id'=>$credentialId]);
    t_check('external credential: persisted signed-field edit becomes TAMPERED', AttestedCredentialService::verdict($db,$get->fetch(PDO::FETCH_ASSOC))==='TAMPERED');
    $db->prepare('UPDATE external_credentials SET status="WITHDRAWN",withdrawn_at=NOW(),withdrawn_by=:uid WHERE id=:id')->execute(['uid'=>$adminUser,'id'=>$credentialId]);
    $get->execute(['id'=>$credentialId]);
    t_check('external credential: withdrawal verdict overrides signature state', AttestedCredentialService::verdict($db,$get->fetch(PDO::FETCH_ASSOC))==='WITHDRAWN');
    $db->prepare('DELETE FROM external_credentials WHERE id=:id')->execute(['id'=>$credentialId]);
    $db->prepare('DELETE FROM students WHERE id=:id')->execute(['id'=>$studentId]);
    $db->prepare('DELETE FROM institutions WHERE id=:id')->execute(['id'=>$institutionId]);
    $db->prepare('DELETE FROM users WHERE id IN (:student,:admin)')->execute(['student'=>$studentUser,'admin'=>$adminUser]);
} catch (Throwable $e) {
    echo 'SKIP external credential MySQL integration: ' . get_class($e) . "\n";
}

exit(t_summary('test_attested_credentials') ? 0 : 1);
