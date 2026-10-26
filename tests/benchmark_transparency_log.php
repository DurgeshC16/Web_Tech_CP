<?php
// Paper benchmark for the in-memory SHA-256 Merkle implementation.
// Measures leaf append/hash, one proof build, and proof verification; SQL/network
// I/O and checkpoint signing are deliberately excluded from primitive timings.
if (PHP_SAPI !== 'cli') { http_response_code(403); exit("CLI only.\n"); }
require_once __DIR__ . '/../src/services/TransparencyLogService.php';

echo "entries,append_ms,proof_generation_ms,proof_verification_ms,root\n";
foreach ([1000,10000,100000] as $size) {
    $leaves=[];
    $start=hrtime(true);
    for ($i=0;$i<$size;$i++) $leaves[]=hash('sha256','benchmark-certificate-'.$i.'|'.hash('sha256','payload-'.$i).'|signature-'.$i.'|2026-01-01 00:00:00');
    $appendMs=(hrtime(true)-$start)/1e6;

    $index=intdiv($size,2);
    $start=hrtime(true);
    $proof=TransparencyLogService::inclusionProof($leaves,$index);
    $root=TransparencyLogService::merkleRoot($leaves);
    $proofMs=(hrtime(true)-$start)/1e6;

    $start=hrtime(true);
    $ok=TransparencyLogService::verifyInclusionProof($leaves[$index],$index,$size,$proof,$root);
    $verifyMs=(hrtime(true)-$start)/1e6;
    if (!$ok) { fwrite(STDERR,"Internal benchmark proof verification failed at $size entries.\n"); exit(1); }
    echo $size . ',' . number_format($appendMs,3,'.','') . ',' . number_format($proofMs,3,'.','') . ',' . number_format($verifyMs,3,'.','') . ",$root\n";
    unset($leaves,$proof);
}
