<?php
// src/services/TrustScoreService.php
// ─────────────────────────────────────────────────────────────────────
// Phase 2 — rule-based trust score (0–100) derived EXCLUSIVELY from the
// existing VerificationService checks, replayed read-only so the score
// can never contradict a verdict:
//
//   exists                   20 pts   (row in CertiVault's own DB)
//   file hash matches        30 pts
//   signature valid          30 pts
//   not expired              10 pts
//   not revoked/superseded   10 pts
//
// Any failed CRITICAL check (exists / hash / signature) caps the total
// at 40. External/other references score null (unscorable) — they are
// never, ever presented as CertiVault-verified. DISCLAIMER is rendered
// beside the gauge.
// ─────────────────────────────────────────────────────────────────────

class TrustScoreService
{
    public const DISCLAIMER = 'CertiVault confirms the record passes technical checks; '
        . 'it does not verify the real-world achievement.';

    /** External credentials never receive a VALID verdict; an attestation caps at 70. */
    public static function computeExternalCredential($db, array $credential): array
    {
        $status = class_exists('AttestedCredentialService')
            ? AttestedCredentialService::verdict($db, $credential)
            : (string)($credential['status'] ?? 'SELF_DECLARED');
        $checks = [
            ['id'=>'student_declaration','label'=>'Student supplied an external credential record','pass'=>true,'points'=>10,'critical'=>false],
            ['id'=>'institution_attestation','label'=>'Approved institution signed the attestation','pass'=>$status==='ATTESTED','points'=>60,'critical'=>false],
        ];
        $score = $status === 'ATTESTED' ? 70 : 0;
        return ['score'=>min(70, $score), 'verdict'=>$status, 'checks'=>$checks, 'disclaimer'=>'Attestation is an institution’s statement that it checked the external record; CertiVault did not verify it with the issuer.'];
    }

    /**
     * Replay the same order of checks as VerificationService::verify().
     * @param array $cert full certificate row (with institution_name etc.)
     * @return array{score:int, verdict:string, checks:array<int,array{id:string,label:string,pass:bool,points:int,critical:bool}>}
     */
    public static function compute($db, array $cert): array
    {
        $status = (string)$cert['status'];
        $effectiveStatus = VerificationService::effectiveStatus($cert);

        $checks = [
            ['id' => 'exists', 'label' => 'Record exists in CertiVault', 'pass' => true, 'points' => 20, 'critical' => true],
        ];

        // Server-side status FIRST (mirrors verdict order):
        // revoked/superseded win over everything below.
        if ($status === 'revoked') {
            $checks[] = ['id' => 'status', 'label' => 'Not revoked', 'pass' => false, 'points' => 10, 'critical' => false];
        } elseif ($status === 'superseded') {
            $checks[] = ['id' => 'status', 'label' => 'Not superseded by a newer version', 'pass' => false, 'points' => 10, 'critical' => false];
        } else {
            $checks[] = ['id' => 'status', 'label' => 'Not revoked or superseded', 'pass' => true, 'points' => 10, 'critical' => false];
        }

        // File integrity — the SAME certificate hash as verify().
        $filePath = __DIR__ . '/../../private_data/uploads/' . $cert['file_path'];
        $hashOK = false;
        $signatureOK = false;
        if (file_exists($filePath) && !empty($cert['sha256_hash'])) {
            $certData = [
                'certificate_id' => $cert['certificate_id'],
                'institution_id' => $cert['institution_id'],
                'student_id'     => $cert['student_id'],
                'title'          => $cert['title'],
                'issue_date'     => $cert['issue_date'],
                'expiry_date'    => $cert['expiry_date'],
            ];
            try {
                $recomputed = CryptoService::computeCertificateHash($certData, $filePath);
                $hashOK = hash_equals($cert['sha256_hash'], $recomputed);

                // Mirror verify(): the signature step only runs after the
                // hash passed, so a hash-failed row reports the signature
                // as untestable (failed) in the score too.
                if ($hashOK && !empty($cert['digital_signature']) && !empty($cert['public_key'])) {
                    $signatureOK = CryptoService::verifyCertificateSignature(
                        $recomputed,
                        $cert['digital_signature'],
                        $cert['public_key']
                    );
                }
            } catch (Throwable $e) {
                $hashOK = false;
                $signatureOK = false;
            }
        }

        $checks[] = ['id' => 'hash', 'label' => 'File hash matches issuance (SHA-256)', 'pass' => $hashOK, 'points' => 30, 'critical' => true];
        $checks[] = ['id' => 'signature', 'label' => "Issuer signature verifies ({$cert['institution_name']})", 'pass' => $signatureOK, 'points' => 30, 'critical' => true];
        $checks[] = ['id' => 'expiry', 'label' => 'Not expired', 'pass' => $effectiveStatus !== 'expired', 'points' => 10, 'critical' => false];

        $score = 0;
        foreach ($checks as $c) {
            $score += $c['pass'] ? $c['points'] : 0;
        }
        $criticalFailed = false;
        foreach ($checks as $c) {
            if ($c['critical'] && !$c['pass']) {
                $criticalFailed = true;
                break;
            }
        }
        if ($criticalFailed && $score > 40) {
            $score = 40;
        }

        // Derive the canonical verdict from the same check outcomes
        // (mirroring verify(); verify.php must still use VerificationService
        // as the decision engine — this only describes consistency).
        if ($status === 'revoked') {
            $verdict = 'REVOKED';
        } elseif ($status === 'superseded') {
            $verdict = 'SUPERSEDED';
        } elseif (!$hashOK || !$signatureOK) {
            $verdict = 'TAMPERED';
        } elseif (!$checks[4]['pass']) {
            $verdict = 'EXPIRED';
        } else {
            $verdict = 'VALID';
        }

        return ['score' => $score, 'verdict' => $verdict, 'checks' => $checks];
    }
}
