<?php
// tests/fixtures/pdf_builder.php
// Minimal, dependency-free PDF writer used ONLY to build test fixtures
// (certificate PDFs containing QR images). No external libraries.
//
// Each page may carry one RGB image, compressed with FlateDecode, so the
// output exercises pdf.js's real image/stream rendering path.

/**
 * Read a PNG and return width/height plus a FlateDecode-compressed raw
 * RGB buffer suitable for an image XObject.
 */
function cv_pdf_image_from_png($pngPath) {
    $im = @imagecreatefrompng($pngPath);
    if (!$im) {
        throw new RuntimeException("Cannot read PNG for PDF: $pngPath");
    }
    $w = imagesx($im);
    $h = imagesy($im);
    $tc = imagecreatetruecolor($w, $h);
    imagecopy($tc, $im, 0, 0, 0, 0, $w, $h);
    $raw = '';
    for ($y = 0; $y < $h; $y++) {
        for ($x = 0; $x < $w; $x++) {
            $c = imagecolorat($tc, $x, $y);
            $raw .= chr(($c >> 16) & 0xFF) . chr(($c >> 8) & 0xFF) . chr($c & 0xFF);
        }
    }
    imagedestroy($im);
    imagedestroy($tc);
    return ['w' => $w, 'h' => $h, 'data' => gzcompress($raw, 9)];
}

/**
 * Build a PDF document.
 *
 * @param array $pages list where each item is either null (blank page) or
 *                     ['png' => '/path/to/qr.png'].
 * @return string raw PDF bytes
 */
function cv_build_pdf(array $pages) {
    $images = [];
    foreach ($pages as $p) {
        $images[] = ($p && !empty($p['png'])) ? cv_pdf_image_from_png($p['png']) : null;
    }

    // Object numbering: 1 = Catalog, 2 = Pages, then per page: page, content, [image].
    $next = 3;
    $pageIds = $contentIds = $imageIds = [];
    foreach ($images as $i => $img) {
        $pageIds[$i]    = $next++;
        $contentIds[$i] = $next++;
        $imageIds[$i]   = $img ? $next++ : null;
    }
    $maxId = $next - 1;

    $bodies = [];
    // Catalog + Pages tree.
    $kids = [];
    foreach ($pageIds as $id) { $kids[] = $id . ' 0 R'; }
    $bodies[1] = '<< /Type /Catalog /Pages 2 0 R >>';
    $bodies[2] = '<< /Type /Pages /Kids [ ' . implode(' ', $kids) . ' ] /Count ' . count($pageIds) . ' >>';

    foreach ($images as $i => $img) {
        $pid = $pageIds[$i];
        $cid = $contentIds[$i];
        $iid = $imageIds[$i];

        if ($img) {
            $draw = 'q 400 0 0 400 106 196 cm /Im0 Do Q';
            $res  = '<< /XObject << /Im0 ' . $iid . ' 0 R >> >>';
            $bodies[$iid] = '<< /Type /XObject /Subtype /Image /Width ' . $img['w']
                . ' /Height ' . $img['h'] . ' /ColorSpace /DeviceRGB /BitsPerComponent 8'
                . ' /Filter /FlateDecode /Length ' . strlen($img['data']) . " >>\nstream\n"
                . $img['data'] . "\nendstream";
        } else {
            $draw = 'q Q';
            $res  = '<< >>';
        }
        $bodies[$cid] = '<< /Length ' . strlen($draw) . " >>\nstream\n" . $draw . "\nendstream";
        $bodies[$pid] = '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]'
            . ' /Resources ' . $res . ' /Contents ' . $cid . ' 0 R >>';
    }

    $out = "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";
    $offsets = [];
    for ($id = 1; $id <= $maxId; $id++) {
        $offsets[$id] = strlen($out);
        $out .= $id . " 0 obj\n" . $bodies[$id] . "\nendobj\n";
    }
    $xrefPos = strlen($out);
    $out .= "xref\n0 " . ($maxId + 1) . "\n";
    $out .= "0000000000 65535 f \n";
    for ($id = 1; $id <= $maxId; $id++) {
        $out .= sprintf("%010d 00000 n \n", $offsets[$id]);
    }
    $out .= "trailer\n<< /Size " . ($maxId + 1) . " /Root 1 0 R >>\nstartxref\n" . $xrefPos . "\n%%EOF";
    return $out;
}
