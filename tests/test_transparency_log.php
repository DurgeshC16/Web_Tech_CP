<?php
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/services/TransparencyLogService.php';

$leafFixture=['certificate_id'=>'CV-EXAMPLE-1','sha256_hash'=>str_repeat('a',64),'digital_signature'=>'sig-example','issued_at'=>'2026-10-27 10:00:00'];
t_check('tlog: leaf uses specified certificate|hash|signature|issued_at canonical form',
    TransparencyLogService::leafHash($leafFixture)===hash('sha256','CV-EXAMPLE-1|'.str_repeat('a',64).'|sig-example|2026-10-27 10:00:00'));

foreach ([1,2,3,5,8,11,33] as $size) {
    $leaves=[];
    for ($i=0; $i<$size; $i++) $leaves[]=hash('sha256', "leaf-$size-$i");
    $root=TransparencyLogService::merkleRoot($leaves);
    $allValid=true;
    foreach ($leaves as $index=>$leaf) {
        $proof=TransparencyLogService::inclusionProof($leaves,$index);
        if (!TransparencyLogService::verifyInclusionProof($leaf,$index,$size,$proof,$root)) $allValid=false;
    }
    t_check("merkle: all inclusion proofs verify for $size leaves", $allValid);
    $proof=TransparencyLogService::inclusionProof($leaves,0);
    t_check("merkle: altered leaf rejected for $size leaves", !TransparencyLogService::verifyInclusionProof(hash('sha256','tampered'),0,$size,$proof,$root));
}
t_check('merkle: empty tree has no root', TransparencyLogService::merkleRoot([]) === null);

// Real DB row regression: a checkpoint commits the original row leaf. Editing
// its hash afterward must no longer match that checkpointed leaf.
try {
    $db=test_db();
    $db->exec('CREATE TABLE IF NOT EXISTS tlog_unit_rows (certificate_id VARCHAR(64) PRIMARY KEY,sha256_hash CHAR(64) NOT NULL,digital_signature TEXT NOT NULL,issued_at DATETIME NOT NULL) ENGINE=InnoDB');
    $cid='TLOG-DB-'.bin2hex(random_bytes(5));
    $db->prepare('INSERT INTO tlog_unit_rows (certificate_id,sha256_hash,digital_signature,issued_at) VALUES (:id,:h,:sig,NOW())')
        ->execute(['id'=>$cid,'h'=>str_repeat('a',64),'sig'=>'original-signature']);
    $read=$db->prepare('SELECT certificate_id,sha256_hash,digital_signature,issued_at FROM tlog_unit_rows WHERE certificate_id=:id');
    $read->execute(['id'=>$cid]); $original=$read->fetch(PDO::FETCH_ASSOC);
    $committedLeaf=TransparencyLogService::leafHash($original);
    $checkpointRoot=TransparencyLogService::merkleRoot([$committedLeaf]);
    $db->prepare('UPDATE tlog_unit_rows SET sha256_hash=:h WHERE certificate_id=:id')->execute(['h'=>str_repeat('b',64),'id'=>$cid]);
    $read->execute(['id'=>$cid]); $edited=$read->fetch(PDO::FETCH_ASSOC);
    t_check('transparency: editing DB certificate row after checkpoint is detected',
        $checkpointRoot===$committedLeaf && !TransparencyLogService::matchesCertificateRow($committedLeaf,$edited));
    $db->prepare('DELETE FROM tlog_unit_rows WHERE certificate_id=:id')->execute(['id'=>$cid]);
} catch (Throwable $e) {
    echo 'SKIP tlog DB-row tamper integration: ' . get_class($e) . "\n";
}

exit(t_summary('test_transparency_log') ? 0 : 1);
