<?php
// src/services/StudentStatsService.php
// ─────────────────────────────────────────────────────────────────────
// Phase 4 — student portal quality-of-life: per-certificate verification
// visibility (how often each of MY certificates has been verified and
// when it was last checked), computed read-only over verification_logs.
// LEFT JOIN keeps never-verified certificates visible with 0/NULL.
// ─────────────────────────────────────────────────────────────────────

class StudentStatsService
{
    /**
     * Verification counts per certificate row (c.id keyed) for one student.
     * @return array<int,array{row_id:int, verifications:int, valid_hits:int, last_at:?string}>
     */
    public static function perCertificate($db, int $studentId): array
    {
        $stmt = $db->prepare('
            SELECT c.id AS row_id,
                   COUNT(v.id) AS verifications,
                   COALESCE(SUM(v.result = "VALID"), 0) AS valid_hits,
                   MAX(v.verified_at) AS last_at
            FROM certificates c
            LEFT JOIN verification_logs v
                   ON v.certificate_id_found = c.certificate_id
            WHERE c.student_id = :sid
            GROUP BY c.id
        ');
        $stmt->execute(['sid' => $studentId]);
        $out = [];
        foreach ($stmt->fetchAll() as $row) {
            $out[(int)$row['row_id']] = [
                'row_id'       => (int)$row['row_id'],
                'verifications' => (int)$row['verifications'],
                'valid_hits'   => (int)$row['valid_hits'],
                'last_at'      => $row['last_at'] ?: null,
            ];
        }
        return $out;
    }

    /**
     * Totals for the dashboard strip.
     * @return array{verifications:int, valid_hits:int, last_at:?string}
     */
    public static function totals($db, int $studentId): array
    {
        $stmt = $db->prepare('
            SELECT COUNT(v.id) AS verifications,
                   COALESCE(SUM(v.result = "VALID"), 0) AS valid_hits,
                   MAX(v.verified_at) AS last_at
            FROM certificates c
            LEFT JOIN verification_logs v
                   ON v.certificate_id_found = c.certificate_id
            WHERE c.student_id = :sid
        ');
        $stmt->execute(['sid' => $studentId]);
        $row = $stmt->fetch() ?: [];
        return [
            'verifications' => (int)($row['verifications'] ?? 0),
            'valid_hits'    => (int)($row['valid_hits'] ?? 0),
            'last_at'       => ($row['last_at'] ?? null) ?: null,
        ];
    }
}
