<?php
require_once __DIR__ . '/CryptoService.php';

/** Merkle helpers and DB facade for the append-only certificate event log. */
class TransparencyLogService
{
    public static function leafHash(array $certificate): string
    {
        $issuedAt = (string)($certificate['issued_at'] ?? $certificate['created_at'] ?? '');
        return hash('sha256', (string)$certificate['certificate_id'] . '|'
            . (string)$certificate['sha256_hash'] . '|'
            . (string)$certificate['digital_signature'] . '|'
            . $issuedAt);
    }

    public static function matchesCertificateRow(string $loggedLeafHash, array $certificate): bool
    {
        return preg_match('/^[a-f0-9]{64}$/i', $loggedLeafHash) === 1
            && hash_equals(strtolower($loggedLeafHash), self::leafHash($certificate));
    }

    /** Merkle nodes use SHA256(0x01 || left || right); odd final nodes duplicate. */
    private static function parent(string $left, string $right): string
    {
        return hash('sha256', "\x01" . hex2bin($left) . hex2bin($right));
    }

    public static function merkleLevels(array $leafHashes): array
    {
        foreach ($leafHashes as $hash) if (!is_string($hash) || !preg_match('/^[a-f0-9]{64}$/i', $hash)) throw new InvalidArgumentException('Merkle leaves must be SHA-256 hex hashes.');
        if (!$leafHashes) return [];
        $levels = [array_values(array_map('strtolower', $leafHashes))];
        while (count($levels[count($levels)-1]) > 1) {
            $current = $levels[count($levels)-1];
            $next = [];
            for ($i=0, $n=count($current); $i<$n; $i+=2) {
                $right = $current[$i+1] ?? $current[$i];
                $next[] = self::parent($current[$i], $right);
            }
            $levels[] = $next;
        }
        return $levels;
    }

    public static function merkleRoot(array $leafHashes): ?string
    {
        $levels = self::merkleLevels($leafHashes);
        return $levels ? $levels[count($levels)-1][0] : null;
    }

    /** @return array<int,array{side:string,hash:string}> */
    public static function inclusionProof(array $leafHashes, int $index): array
    {
        if ($index < 0 || $index >= count($leafHashes)) throw new OutOfBoundsException('Merkle leaf index is outside the tree.');
        $levels = self::merkleLevels($leafHashes);
        $proof = [];
        $position = $index;
        for ($level=0; $level<count($levels)-1; $level++) {
            $nodes = $levels[$level];
            $sibling = $position ^ 1;
            if ($sibling >= count($nodes)) $sibling = $position;
            $proof[] = ['side' => ($sibling < $position ? 'left' : 'right'), 'hash' => $nodes[$sibling]];
            $position = intdiv($position, 2);
        }
        return $proof;
    }

    public static function verifyInclusionProof(string $leafHash, int $index, int $treeSize, array $proof, string $expectedRoot): bool
    {
        if ($treeSize < 1 || $index < 0 || $index >= $treeSize || !preg_match('/^[a-f0-9]{64}$/i', $leafHash)
            || !preg_match('/^[a-f0-9]{64}$/i', $expectedRoot)) return false;
        $width = $treeSize;
        $hash = strtolower($leafHash);
        foreach ($proof as $step) {
            if (!isset($step['side'], $step['hash']) || !preg_match('/^[a-f0-9]{64}$/i', (string)$step['hash'])) return false;
            $sibling = strtolower((string)$step['hash']);
            if ($step['side'] === 'left') $hash = self::parent($sibling, $hash);
            elseif ($step['side'] === 'right') $hash = self::parent($hash, $sibling);
            else return false;
            $index = intdiv($index, 2);
            $width = intdiv($width + 1, 2);
        }
        return $width === 1 && hash_equals(strtolower($expectedRoot), $hash);
    }

    /** Append an event within the caller's certificate transaction. */
    public static function append($db, string $certificateId, string $eventType): int
    {
        if (!defined('CERTIFICATE_TRANSPARENCY_ENABLED') || !CERTIFICATE_TRANSPARENCY_ENABLED) return 0;
        if (!in_array($eventType, ['ISSUE','REVOKE','SUPERSEDE'], true)) throw new InvalidArgumentException('Unsupported transparency event.');
        $stmt = $db->prepare('SELECT certificate_id,sha256_hash,digital_signature,created_at AS issued_at FROM certificates WHERE certificate_id=:cid LIMIT 1');
        $stmt->execute(['cid'=>$certificateId]);
        $cert = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$cert) throw new RuntimeException('Cannot append a missing certificate to the transparency log.');
        $last = $db->query('SELECT root_hash FROM tlog_checkpoints ORDER BY id DESC LIMIT 1')->fetchColumn();
        $insert = $db->prepare('INSERT INTO tlog_entries (certificate_id,event_type,leaf_hash,prev_root) VALUES (:cid,:event,:leaf,:prev)');
        $insert->execute(['cid'=>$certificateId,'event'=>$eventType,'leaf'=>self::leafHash($cert),'prev'=>$last ?: null]);
        return (int)$db->lastInsertId();
    }

    /** Create/reuse the signed checkpoint for the current log prefix. */
    public static function checkpoint($db, string $privatePem, string $publicPem): array
    {
        if (!defined('CERTIFICATE_TRANSPARENCY_ENABLED') || !CERTIFICATE_TRANSPARENCY_ENABLED) throw new RuntimeException('Certificate transparency is disabled in config.php.');
        $stmt = $db->query('SELECT seq,leaf_hash FROM tlog_entries ORDER BY seq');
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $leaves = array_column($rows, 'leaf_hash');
        $size = count($leaves);
        if ($size === 0) throw new RuntimeException('Cannot publish an empty transparency log.');
        $root = self::merkleRoot($leaves);
        $fingerprint = CryptoService::fingerprintPublicKey($publicPem);
        $lastSeq=(int)end($rows)['seq'];
        $existing = $db->prepare('SELECT tree_size,last_seq,root_hash,signature,public_key_fingerprint,created_at FROM tlog_checkpoints WHERE tree_size=:size LIMIT 1');
        $existing->execute(['size'=>$size]);
        $checkpoint = $existing->fetch(PDO::FETCH_ASSOC);
        if ($checkpoint) {
            if (!hash_equals((string)$checkpoint['root_hash'], (string)$root)
                || !hash_equals((string)$checkpoint['public_key_fingerprint'], $fingerprint)
                || (int)$checkpoint['last_seq'] !== $lastSeq) throw new RuntimeException('Existing checkpoint conflicts with the current log prefix or platform key.');
        } else {
            $signature = CryptoService::signCertificateHash((string)$root, $privatePem);
            if (!CryptoService::verifyCertificateSignature((string)$root, $signature, $publicPem)) throw new RuntimeException('Platform checkpoint signature self-check failed.');
            $ins = $db->prepare('INSERT INTO tlog_checkpoints (tree_size,last_seq,root_hash,signature,public_key_fingerprint) VALUES (:size,:last_seq,:root,:sig,:fp)');
            $ins->execute(['size'=>$size,'last_seq'=>$lastSeq,'root'=>$root,'sig'=>$signature,'fp'=>$fingerprint]);
            $checkpoint = ['tree_size'=>$size,'last_seq'=>$lastSeq,'root_hash'=>$root,'signature'=>$signature,'public_key_fingerprint'=>$fingerprint,'created_at'=>date('Y-m-d H:i:s')];
        }
        return [
            'format'=>'certivault-tlog-checkpoint-v1', 'algorithm'=>'sha256-merkle-duplicate-odd-v1',
            'tree_size'=>(int)$checkpoint['tree_size'], 'last_seq'=>(int)$checkpoint['last_seq'], 'root_hash'=>(string)$checkpoint['root_hash'],
            'signature'=>(string)$checkpoint['signature'], 'signature_algorithm'=>'RSA-SHA256',
            'public_key_fingerprint'=>(string)$checkpoint['public_key_fingerprint'],
            'platform_public_key'=>$publicPem,
            'checkpointed_at'=>(string)$checkpoint['created_at'],
        ];
    }

    /** DB reconciliation and signed inclusion proof for one live certificate row. */
    public static function certificateStatus($db, array $certificate): array
    {
        $base = ['reconciled'=>false,'warning'=>null,'proof'=>null];
        try {
            $cp = $db->query('SELECT tree_size,last_seq,root_hash,signature,public_key_fingerprint,created_at FROM tlog_checkpoints ORDER BY id DESC LIMIT 1')->fetch(PDO::FETCH_ASSOC);
            if (!$cp) return array_merge($base, ['warning'=>'No signed transparency checkpoint has been published yet.']);
            if (!is_file(TLOG_PUBLIC_KEY_FILE) || !is_readable(TLOG_PUBLIC_KEY_FILE)) return array_merge($base, ['warning'=>'Trusted transparency public key is unavailable; the checkpoint cannot be verified.']);
            $platformPublic = file_get_contents(TLOG_PUBLIC_KEY_FILE);
            $fp = CryptoService::fingerprintPublicKey($platformPublic);
            $signatureOK = hash_equals((string)$cp['public_key_fingerprint'], $fp)
                && CryptoService::verifyCertificateSignature((string)$cp['root_hash'], (string)$cp['signature'], $platformPublic);
            if (!$signatureOK) return array_merge($base, ['warning'=>'Transparency checkpoint signature or platform-key fingerprint is invalid.']);

            $newer = $db->prepare('SELECT MAX(seq) FROM tlog_entries WHERE certificate_id=:cid');
            $newer->execute(['cid'=>$certificate['certificate_id']]);
            if ((int)$newer->fetchColumn() > (int)$cp['last_seq']) {
                return array_merge($base, ['warning'=>'A newer issue/revoke/supersede event is not yet covered by the published checkpoint.']);
            }

            $log = $db->prepare('SELECT seq,leaf_hash FROM tlog_entries WHERE certificate_id=:cid AND seq<=:last_seq ORDER BY seq DESC LIMIT 1');
            $log->execute(['cid'=>$certificate['certificate_id'],'last_seq'=>(int)$cp['last_seq']]);
            $entry = $log->fetch(PDO::FETCH_ASSOC);
            if (!$entry) return array_merge($base, ['warning'=>'This certificate is not included in the published transparency checkpoint.']);

            $allStmt = $db->prepare('SELECT seq,leaf_hash FROM tlog_entries WHERE seq<=:last_seq ORDER BY seq');
            $allStmt->execute(['last_seq'=>(int)$cp['last_seq']]);
            $allRows = $allStmt->fetchAll(PDO::FETCH_ASSOC);
            $leaves = array_column($allRows, 'leaf_hash');
            $seqStrings = array_map('strval', array_column($allRows, 'seq'));
            $seqIndex = array_search((string)$entry['seq'], $seqStrings, true);
            if (count($leaves) !== (int)$cp['tree_size'] || $seqIndex === false || !isset($leaves[$seqIndex])) {
                return array_merge($base, ['warning'=>'Transparency log sequence has gaps or entries were removed.']);
            }
            $proof = self::inclusionProof($leaves, $seqIndex);
            $logRoot = self::merkleRoot($leaves);
            $dbLogMatches = self::matchesCertificateRow((string)$entry['leaf_hash'], $certificate);
            $logRootMatches = $logRoot !== null && hash_equals((string)$cp['root_hash'], $logRoot);
            $proofValid = self::verifyInclusionProof((string)$entry['leaf_hash'], $seqIndex, (int)$cp['tree_size'], $proof, (string)$cp['root_hash']);
            $ok = $dbLogMatches && $logRootMatches && $proofValid;
            return [
                'reconciled'=>$ok,
                'warning'=>$ok ? null : 'WARNING: certificate data or transparency entries no longer reconcile with the signed checkpoint.',
                'proof'=>['seq'=>(int)$entry['seq'],'tree_size'=>(int)$cp['tree_size'],'leaf_hash'=>(string)$entry['leaf_hash'],'root_hash'=>(string)$cp['root_hash'],'proof'=>$proof,'signature'=>(string)$cp['signature'],'public_key_fingerprint'=>$fp,'checkpointed_at'=>(string)$cp['created_at']],
            ];
        } catch (Throwable $e) {
            error_log('[CertiVault] Transparency log reconciliation failed: ' . $e->getMessage());
            return array_merge($base, ['warning'=>'WARNING: transparency log could not be reconciled.']);
        }
    }
}
