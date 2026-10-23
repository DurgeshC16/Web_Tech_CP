<?php
// src/services/ReportService.php
// ─────────────────────────────────────────────────────────────────────
// Phase 2 — "Download verification report" PDF (dompdf). Contains ONLY
// what the public verify page shows: no tokens, no hashes beyond the
// publicly displayed SHA-256, no private keys, no file paths.
// Composer package: dompdf/dompdf (vendor/). Never throws to the page.
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/../utils/phpqrcode/phpqrcode.php';

class ReportService
{
    public static function dompdfAvailable(): bool
    {
        return class_exists('\\Dompdf\\Dompdf')
            || (is_file(dirname(__DIR__, 2) . '/vendor/autoload.php')
                && (require_once dirname(__DIR__, 2) . '/vendor/autoload.php') !== false
                && class_exists('\\Dompdf\\Dompdf'));
    }

    /**
     * HTML for the report. Escaped at build time; the caller is the
     * public report.php controller which has already rate-limited.
     * @return string PDF bytes ('' = unavailable)
     */
    public static function buildReportPdf(array $cert, ?string $detail, array $trusted, ?array $supersededBy): string
    {
        if (!self::dompdfAvailable()) {
            return '';
        }
        $e = fn($v) => htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8');

        // QR code that links back to the LIVE verification page.
        $token = (string)($cert['qr_token'] ?? '');
        if (strlen($token) === 43) {
            $qs = 'token=' . rawurlencode($token);
        } else {
            $qs = 'certificate_id=' . rawurlencode((string)$cert['certificate_id']);
        }
        $liveUrl = rtrim(BASE_URL, '/') . '/verify.php?' . $qs;
        ob_start();
        QRcode::png($liveUrl, false, QR_ECLEVEL_M, 5, 2);
        $qrPng = (string)ob_get_clean();
        $qrDataUri = 'data:image/png;base64,' . base64_encode($qrPng);

        $score = $trusted['score'] ?? null;
        $checksHtml = '';
        foreach (($trusted['checks'] ?? []) as $c) {
            $mark = $c['pass'] ? '#1a7a4a' : '#b32032';
            $sym = $c['pass'] ? '&#10003;' : '&#10007;';
            $checksHtml .= '<tr><td style="color:' . $mark . ';font-weight:bold;">' . $sym . '</td><td>' . $e($c['label'])
                . '</td><td style="text-align:right;color:' . ($c['pass'] ? '#1a7a4a' : '#888') . ';">+'
                . ($c['pass'] ? $c['points'] : 0) . ' / ' . $c['points'] . '</td></tr>';
        }
        $gaugeArc = self::gaugeArc($score !== null ? (int)$score : 0);

        $supersedeLine = '';
        if (($cert['status'] ?? '') === 'superseded' && $supersededBy) {
            $supersedeLine = '<p style="color:#b3541e;">Superseded by: '
                . $e($supersededBy['certificate_id'] ?? '') . ' — verify the current version for the live result.</p>';
        }

        $madeAt = date('r');

        $html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
            body { font-family: DejaVu Sans, sans-serif; color: #222; }
            h1 { font-size: 21px; color: #2b2b2b; border-bottom: 3px solid #c9a227; padding-bottom: 6px; }
            h2 { font-size: 15px; margin-top: 18px; }
            table.dl td { padding: 3px 8px 3px 0; }
            table.dl td:first-child { font-weight: bold; color: #555; width: 140px; }
            table.checks td { padding: 4px 10px 4px 0; border-bottom: 1px solid #ddd; }
            .warn { color: #b32032; font-weight: bold; }
            .note { color: #666; font-size: 10px; }
            .sealbox { border: 3px solid #c9a227; display: inline-block; padding: 10px 22px; font-weight: bold; font-size: 18px; }
        </style></head><body>
            <h1>CertiVault — Verification Report</h1>
            <p class="note">Generated ' . $e($madeAt) . ' · live verification: ' . $e($liveUrl) . '</p>

            <h2>Verdict</h2>
            <p><span class="sealbox">' . $e($trusted['verdict'] ?? '?') . '</span></p>
            <p class="note">' . $e($detail ?? '') . '</p>

            <h2>Trust score</h2>
            <table><tr>
                <td style="width:120px;"><svg width="110" height="66" viewBox="0 0 110 66">
                    <path d="M8 58 A47 47 0 0 1 102 58" fill="none" stroke="#e0e0e0" stroke-width="10"/>
                    <path d="' . $gaugeArc . '" fill="none" stroke="#c9a227" stroke-width="10"/>
                </svg></td>
                <td style="vertical-align:bottom;"><span style="font-size:30px;font-weight:bold;">' . $e($score === null ? 'n/a' : (string)$score) . '</span> / 100</td>
            </tr></table>
            <table class="checks">' . $checksHtml . '</table>
            <p class="note">' . $e(TrustScoreService::DISCLAIMER) . '</p>

            <h2>Certificate</h2>
            <table class="dl">
                <tr><td>Certificate ID</td><td>' . $e($cert['certificate_id']) . '</td></tr>
                <tr><td>Awarded To</td><td>' . $e($cert['student_name']) . '</td></tr>
                <tr><td>Title</td><td>' . $e($cert['title']) . '</td></tr>
                <tr><td>Issued By</td><td>' . $e($cert['institution_name']) . '</td></tr>
                <tr><td>Issue Date</td><td>' . $e(date('F j, Y', strtotime($cert['issue_date']))) . '</td></tr>
                <tr><td>Status</td><td>' . $e($cert['status']) . '</td></tr>
                <tr><td>SHA-256</td><td style="font-family:monospace;font-size:9px;">' . $e($cert['sha256_hash'] ?? '—') . '</td></tr>
                <tr><td>Signature algorithm</td><td>SHA-256 with RSA (PKCS#1), per-institution key</td></tr>
            </table>
            ' . $supersedeLine . '

            <h2>This report</h2>
            <p class="note">This document is generated from the live state of the CertiVault database at the
            timestamp above. Scan the QR code to re-verify against the live page.</p>
            <img src="' . $qrDataUri . '" alt="Live verification QR" width="110" height="110"/>
        </body></html>';

        $dompdf = new \Dompdf\Dompdf(['isRemoteEnabled' => false, 'defaultFont' => 'DejaVu Sans']);
        @$dompdf->loadHtml($html);
        @$dompdf->setPaper('A4', 'portrait');
        @$dompdf->render();
        return (string)$dompdf->output();
    }

    /** SVG arc path for the 0–100 semicircular gauge. */
    public static function gaugeArc(int $score): string
    {
        $angle = max(0, min(100, $score)) / 100.0 * 180.0; // degrees across semicircle
        $rad = deg2rad(180.0 - $angle);
        $cx = 55.0; $cy = 58.0; $r = 47.0;
        $x = $cx + $r * cos($rad);
        $y = $cy - $r * sin($rad);
        return sprintf('M8 58 A47 47 0 0 1 %.1f %.1f', $x, $y);
    }
}
