<?php
// src/services/CertificatePdfService.php
// ─────────────────────────────────────────────────────────────────────
// Generates the certificate document itself (A4 landscape PDF, dompdf)
// with the verification QR code embedded — used by bulk issuance, where
// institutions issue from a CSV instead of uploading one file per student.
//
// The generated PDF is the file that gets hashed and signed, exactly like
// an uploaded file, so it verifies by exact upload, by the QR inside it
// (server or browser decoding) and by certificate ID.
// No remote resources are loaded (isRemoteEnabled = false); all values are
// HTML-escaped; the QR is embedded as a data: URI.
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/../utils/composer_autoload.php';

class CertificatePdfService
{
    public static function available(): bool
    {
        return class_exists('\\Dompdf\\Dompdf') || (cv_composer_autoload() && class_exists('\\Dompdf\\Dompdf'));
    }

    /**
     * @param array{institution:string, student:string, title:string, certificate_id:string,
     *              issue_date:string, expiry_date:?string, verify_url:string} $d
     * @param string $qrPngPath path of the QR PNG (generated for this certificate)
     * @return string PDF bytes
     */
    public static function render(array $d, string $qrPngPath): string
    {
        if (!self::available()) {
            throw new RuntimeException('Certificate PDF generation needs dompdf — run "composer install".');
        }
        $e = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
        $date = fn($s) => $s ? date('F j, Y', strtotime((string)$s)) : '';
        $qr = 'data:image/png;base64,' . base64_encode((string)file_get_contents($qrPngPath));
        $expiry = !empty($d['expiry_date']) ? '<p class="meta">Valid until ' . $e($date($d['expiry_date'])) . '</p>' : '';

        $html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
            @page { margin: 0; }
            body { font-family: "DejaVu Serif", serif; margin: 0; color: #15213B; }
            .frame { position: absolute; top: 28px; left: 28px; right: 28px; bottom: 28px; border: 6px double #8A6D3B; padding: 46px 60px; text-align: center; }
            .inst { font-size: 20px; letter-spacing: 2px; text-transform: uppercase; color: #8A6D3B; margin: 0; }
            h1 { font-size: 40px; margin: 18px 0 8px; font-weight: normal; }
            .lead { font-family: "DejaVu Sans", sans-serif; font-size: 13px; color: #5B6472; margin: 14px 0 4px; }
            .name { font-size: 34px; margin: 6px 0; border-bottom: 1px solid #D9DEE5; display: inline-block; padding: 0 30px 6px; }
            .title { font-size: 22px; margin: 10px 0 0; }
            .meta { font-family: "DejaVu Sans", sans-serif; font-size: 12px; color: #5B6472; margin: 6px 0 0; }
            .foot { position: absolute; bottom: 34px; left: 60px; right: 60px; font-family: "DejaVu Sans", sans-serif; font-size: 10px; color: #5B6472; text-align: left; }
            .qr { position: absolute; bottom: 30px; right: 54px; text-align: center; font-family: "DejaVu Sans", sans-serif; font-size: 9px; color: #5B6472; }
        </style></head><body><div class="frame">
            <p class="inst">' . $e($d['institution']) . '</p>
            <h1>Certificate of Achievement</h1>
            <p class="lead">This certifies that</p>
            <p class="name">' . $e($d['student']) . '</p>
            <p class="lead">has successfully completed</p>
            <p class="title">' . $e($d['title']) . '</p>
            <p class="meta">Issued on ' . $e($date($d['issue_date'])) . '</p>' . $expiry . '
            <div class="foot">
                Certificate ID: <strong>' . $e($d['certificate_id']) . '</strong><br>
                Digitally signed by the issuing institution. Verify at ' . $e($d['verify_url']) . '
            </div>
            <div class="qr"><img src="' . $qr . '" width="118" height="118" alt="Verification QR code"><br>Scan to verify</div>
        </div></body></html>';

        $dompdf = new \Dompdf\Dompdf(['isRemoteEnabled' => false, 'defaultFont' => 'DejaVu Serif']);
        @$dompdf->loadHtml($html, 'UTF-8');
        @$dompdf->setPaper('A4', 'landscape');
        @$dompdf->render();
        $pdf = (string)$dompdf->output();
        if (strncmp($pdf, '%PDF', 4) !== 0) {
            throw new RuntimeException('Certificate PDF could not be generated.');
        }
        return $pdf;
    }
}
