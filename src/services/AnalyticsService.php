<?php
// src/services/AnalyticsService.php
// Read-only verification analytics for ONE institution (analytics.php).
// Counts verification_logs rows that resolved to the institution's own
// certificates (certificate_id_found); lookups that matched nothing cannot
// be attributed to an institution and are not included. Exports/reports
// are counted as checks too (they are lookups of the certificate).

class AnalyticsService
{
    public const RANGES = [7, 30, 90];
    public const VERDICTS = ['VALID', 'EXPIRED', 'SUPERSEDED', 'REVOKED', 'TAMPERED', 'INVALID'];

    public static function normaliseRange($days): int
    {
        $d = (int)$days;
        return in_array($d, self::RANGES, true) ? $d : 30;
    }

    /**
     * @return array{days:int, from:string, to:string, daily:array<string,int>, total:int, previous:int,
     *               valid:int, verifiers:int, verdicts:array<string,int>, top:array<int,array>, certificates:int}
     */
    public static function summary($db, int $institutionId, int $days, ?string $today = null): array
    {
        $today = $today ?? date('Y-m-d');
        $from = date('Y-m-d', strtotime("$today -" . ($days - 1) . ' days'));
        $prevFrom = date('Y-m-d', strtotime("$from -$days days"));
        $end = date('Y-m-d', strtotime("$today +1 day"));
        $join = 'FROM verification_logs v JOIN certificates c ON c.certificate_id = v.certificate_id_found
                 WHERE c.institution_id = :iid';

        $daily = [];
        // Calendar arithmetic, not +86400 s: a range crossing a DST change has
        // a 23- or 25-hour day, which would skip or repeat a date.
        for ($i = 0; $i < $days; $i++) {
            $daily[date('Y-m-d', strtotime("$from +$i days"))] = 0;
        }
        $q = $db->prepare("SELECT DATE(v.verified_at) AS d, COUNT(*) AS n $join
                           AND v.verified_at >= :f AND v.verified_at < :e GROUP BY DATE(v.verified_at)");
        $q->execute(['iid' => $institutionId, 'f' => $from, 'e' => $end]);
        foreach ($q->fetchAll(PDO::FETCH_ASSOC) as $r) {
            if (isset($daily[$r['d']])) {
                $daily[$r['d']] = (int)$r['n'];
            }
        }

        $q = $db->prepare("SELECT COUNT(*) $join AND v.verified_at >= :f AND v.verified_at < :e");
        $q->execute(['iid' => $institutionId, 'f' => $prevFrom, 'e' => $from]);
        $previous = (int)$q->fetchColumn();

        $verdicts = array_fill_keys(self::VERDICTS, 0);
        $q = $db->prepare("SELECT v.result, COUNT(*) AS n $join AND v.verified_at >= :f AND v.verified_at < :e GROUP BY v.result");
        $q->execute(['iid' => $institutionId, 'f' => $from, 'e' => $end]);
        foreach ($q->fetchAll(PDO::FETCH_ASSOC) as $r) {
            if (isset($verdicts[$r['result']])) {
                $verdicts[$r['result']] = (int)$r['n'];
            }
        }

        $q = $db->prepare("SELECT COUNT(DISTINCT v.verifier_ip) $join AND v.verified_at >= :f AND v.verified_at < :e");
        $q->execute(['iid' => $institutionId, 'f' => $from, 'e' => $end]);
        $verifiers = (int)$q->fetchColumn();

        $q = $db->prepare("SELECT c.certificate_id, c.title, COUNT(*) AS n $join AND v.verified_at >= :f AND v.verified_at < :e
                           GROUP BY c.certificate_id, c.title ORDER BY n DESC, c.certificate_id LIMIT 5");
        $q->execute(['iid' => $institutionId, 'f' => $from, 'e' => $end]);
        $top = array_map(fn($r) => ['certificate_id' => $r['certificate_id'], 'title' => $r['title'], 'count' => (int)$r['n']],
            $q->fetchAll(PDO::FETCH_ASSOC));

        $q = $db->prepare('SELECT COUNT(*) FROM certificates WHERE institution_id = :iid AND status = "active"');
        $q->execute(['iid' => $institutionId]);

        $total = array_sum($daily);
        arsort($verdicts);
        return [
            'days' => $days, 'from' => $from, 'to' => $today, 'daily' => $daily, 'total' => $total,
            'previous' => $previous, 'valid' => $verdicts['VALID'] ?? 0, 'verifiers' => $verifiers,
            'verdicts' => $verdicts, 'top' => $top, 'certificates' => (int)$q->fetchColumn(),
        ];
    }

    /** Clean axis maximum + tick step (0 / step / 2·step …) for a positive max. */
    public static function niceScale(int $max): array
    {
        if ($max <= 4) {
            return [4, 1];
        }
        $raw = $max / 4;
        $mag = 10 ** floor(log10($raw));
        foreach ([1, 2, 5, 10] as $m) {
            if ($m * $mag >= $raw) {
                $step = (int)($m * $mag);
                return [(int)(ceil($max / $step) * $step), $step];
            }
        }
        return [$max, (int)ceil($max / 4)];
    }

    /** Compact number: 1,284 / 12.9K / 4.2M. */
    public static function compact(int $n): string
    {
        if ($n >= 1000000) { return rtrim(rtrim(number_format($n / 1000000, 1), '0'), '.') . 'M'; }
        if ($n >= 10000) { return rtrim(rtrim(number_format($n / 1000, 1), '0'), '.') . 'K'; }
        return number_format($n);
    }
}
