<?php
// src/services/FileVerifyService.php
// ─────────────────────────────────────────────────────────────────────
// Smart Verify UPLOAD pipeline (Phase 1). Ordered stages that stop at the
// first conclusive result; the temp file is deleted by the CALLER in a
// finally block and is NEVER stored.
//
//   a. v_upload() (real finfo MIME, 5 MB cap) + SHA-256 byte match
//      against stored hashes of ORIGINALS and STAMPED copies.
//   b. QR decode (images directly; PDF page 1 rendered only when
//      Imagick or pdftoppm exists — skipped gracefully otherwise).
//      Decoded text is routed through the Smart Verify TEXT pipeline.
//   c. Text extraction (PDF via smalot/pdfparser when installed;
//      images via tesseract only when its binary exists) and regex
//      scanning for IDs / issuer URLs / "verify at <url>".
//
// A staged outcome is conclusive when the candidate produces a LOCAL
// lookup hit, or the user explicitly selected an issuer and an
// external-reference candidate appears (rendered as informational link,
// never a CertiVault verdict).
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/SmartVerifyService.php';

class FileVerifyService
{
    /**
     * True when the $_FILES entry represents an ACTUAL upload (any error
     * code other than UPLOAD_ERR_NO_FILE). verify.php tests this BEFORE
     * calling run(), so v_upload()'s "required" message can never fire
     * for an omitted file — omitted file means the ID input carries the
     * request (Smart Verify either/or).
     */
    public static function fileProvided($file): bool
    {
        return is_array($file)
            && isset($file['error'])
            && $file['error'] !== UPLOAD_ERR_NO_FILE;
    }

    /** @return array candidate[] (empty when nothing actionable found) */
    public static function run($db, array $file): array
    {
        $check = v_upload($file);
        if ($check !== true) {
            return ['__upload_error' => $check];
        }
        $tmp = $file['tmp_name'];
        return self::pipelineFromTemp($db, $tmp, null);
    }

    /**
     * Pipeline stages for an already-validated temp file. Separated from
     * run() so tests can build harmless runtime fixtures without faking
     * an HTTP upload. $mimeHint null → re-derived with finfo.
     */
    public static function pipelineFromTemp($db, string $tmp, ?string $mimeHint = null): array
    {
        $mime = $mimeHint ?? self::realMime($tmp);

        // ── Stage a: byte-level hash match (originals + stamped copies) ──
        $hash = hash_file('sha256', $tmp);
        if ($hash === false) {
            return ['__upload_error' => 'The file could not be read. Please try again.'];
        }
        foreach (self::findLocalByContentHash($db, $hash) as $cert) {
            return [
                '__cert' => $cert,
                '__candidates' => [],
                '__resolved' => [
                    'query_type' => 'file',
                    'stage' => 'file byte hash match (sha256)',
                ],
            ];
        }

        // ── Stage b: QR decode → text pipeline ──
        $decoded = self::decodeQr($tmp, $mime);
        if (is_string($decoded) && trim($decoded) !== '') {
            $hits = self::resolveCandidates($db, SmartVerifyService::extractCandidates($decoded));
            $res = self::firstConclusive($hits);
            if ($res !== null) {
                return [
                    '__cert' => $res['cert'],
                    '__candidates' => ($res['cert'] === null) ? [$res['candidate']] : [],
                    '__resolved' => $res['cert'] !== null && ($res['candidate']['type'] ?? '') === 'token'
                        ? [
                            'query_type' => 'qr_image',
                            'stage' => 'QR code decoded from uploaded file',
                        ]
                        : [
                            'query_type' => ($res['candidate']['type'] ?? '') === 'external_ref' ? 'external_ref' : 'text',
                            'stage' => 'QR code decoded from uploaded file',
                        ],
                ];
            }
        }

        // ── Stage c: text extraction + regex scan ──
        $text = self::extractText($tmp, $mime);
        if (is_string($text) && $text !== '') {
            $hits = self::resolveCandidates($db, SmartVerifyService::scanExtractedText($text));
            $res = self::firstConclusive($hits);
            if ($res !== null) {
                $res['stage'] = 'text extracted from uploaded file';
                return [
                    '__cert' => $res['cert'],
                    '__candidates' => ($res['cert'] === null) ? [$res['candidate']] : [],
                    '__resolved' => [
                        'query_type' => ($res['candidate']['type'] ?? '') === 'external_ref' ? 'external_ref' : 'text',
                        'stage' => $res['stage'],
                    ],
                ];
            }
        }

        return ['__cert' => null, '__candidates' => [], '__resolved' => null];
    }

    /** Prefer an original-byte hit over a stamped-copy hit. */
    public static function findLocalByContentHash($db, string $hash): array
    {
        if (!preg_match('/^[a-f0-9]{64}$/i', $hash)) {
            return [];
        }
        foreach (['sha256_hash', 'stamped_sha256'] as $col) {
            $cert = self::findByHashColumn($db, $col, $hash);
            if ($cert) {
                return [$cert];
            }
        }
        return [];
    }

    private static function findByHashColumn($db, string $column, string $hash)
    {
        $sql = '
            SELECT c.*, i.name AS institution_name, i.public_key,
                   s.full_name AS student_name
            FROM certificates c
            JOIN institutions i ON c.institution_id = i.id
            JOIN students     s ON c.student_id     = s.id
            WHERE ' . $column . ' = :hash
            LIMIT 1
        ';
        $stmt = $db->prepare($sql);
        $stmt->execute(['hash' => $hash]);
        return $stmt->fetch() ?: null;
    }

    private static function realMime(string $path): string
    {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = $finfo ? (finfo_file($finfo, $path) ?: '') : '';
        if ($finfo) {
            finfo_close($finfo);
        }
        return $mime;
    }

    private static function resolveCandidates($db, array $candidates): array
    {
        $hits = [];
        foreach ($candidates as $cand) {
            if (($cand['type'] ?? '') === 'external_ref') {
                $hits[] = ['cert' => null, 'candidate' => $cand];
                continue;
            }
            $value = (string)($cand['value'] ?? '');
            if ($value === '') {
                continue;
            }
            $cert = ($cand['type'] ?? '') === 'token'
                ? VerificationService::findByToken($db, $value)
                : VerificationService::findByFlexibleCertificateId($db, $value);
            if ($cert) {
                $hits[] = ['cert' => $cert, 'candidate' => $cand];
            }
        }
        return $hits;
    }

    private static function firstConclusive(array $hits): ?array
    {
        foreach ($hits as $h) {
            return $h; // first local hit wins; external refs return as informational
        }
        return null;
    }

    /**
     * QR decode from the upload. PDFs are rendered to a temporary page-1
     * image only if Imagick or pdftoppm exists; otherwise skipped (null).
     * Image files decode directly with the bundled Zxing reader.
     */
    private static function decodeQr(string $tmp, string $mime): ?string
    {
        try {
            if ($mime === 'application/pdf') {
                $rendered = self::renderPdfPage1($tmp);
                if ($rendered === null) {
                    return null; // no renderer available — skip gracefully
                }
                try {
                    $text = (new Zxing\QrReader($rendered))->text();
                    return $text !== false ? (string)$text : null;
                } finally {
                    @unlink($rendered); // renderer temp file deleted immediately
                }
            }
            if (in_array($mime, ['image/png', 'image/jpeg', 'image/webp'], true)) {
                $text = (new Zxing\QrReader($tmp))->text();
                return $text !== false ? (string)$text : null;
            }
        } catch (Throwable $e) {
            error_log('[CertiVault] Smart Verify QR decode failed: ' . get_class($e));
        }
        return null;
    }

    private static function renderPdfPage1(string $pdf): ?string
    {
        $out = tempnam(sys_get_temp_dir(), 'cvpdf_');
        $png = $out . '.png';
        @unlink($out);

        // Imagick?
        if (class_exists('Imagick')) {
            try {
                $im = new Imagick();
                $im->setResolution(150, 150);
                $im->readImage($pdf . '[0]');
                $im->setImageFormat('png');
                $im->writeImage($png);
                $im->destroy();
                if (is_file($png)) {
                    return $png;
                }
            } catch (Throwable $e) {
                error_log('[CertiVault] Imagick PDF render failed: ' . $e->getMessage());
            }
        }
        // pdftoppm (poppler-utils)?
        $pdftoppm = self::findBinary(['pdftoppm']);
        if ($pdftoppm !== null) {
            $cmd = '"' . addcslashes($pdftoppm, '\\') . '" -png -r 120 -singlefile ' .
                   '"' . addcslashes($pdf, '\\') . '" "' . addcslashes(substr($png, 0, -4), '\\') . '"';
            @exec($cmd, $o, $code);
            if (($code === 0) && is_file($png)) {
                return $png;
            }
        }
        return null;
    }

    /**
     * Text extraction. PDFs: smalot/pdfparser when Composer-installed.
     * Images: tesseract binary only when it exists (configurable via
     * CV_TESSERACT_BIN). Returns null when extraction is unavailable or
     * fails — the pipeline then reports NOT-FOUND (no error to the user).
     */
    private static function extractText(string $tmp, string $mime): ?string
    {
        try {
            if ($mime === 'application/pdf') {
                if (!self::pdfParserAvailable()) {
                    return null;
                }
                $parser = new \Smalot\PdfParser\Parser();
                return (string)$parser->parseFile($tmp)->getText();
            }
            $tesseract = self::findBinary(['tesseract']);
            if ($tesseract === null || !in_array($mime, ['image/png', 'image/jpeg'], true)) {
                return null;
            }
            $outName = tempnam(sys_get_temp_dir(), 'cvocr_');
            @unlink($outName);
            $txtPath = $outName; // tesseract appends .txt by itself
            $cfgBase = sys_get_temp_dir(); // keep stdout out of the picture
            $cmd = '"' . addcslashes($tesseract, '\\') . '" "' . addcslashes($tmp, '\\') . '" "'
                 . addcslashes($txtPath, '\\') . '" --psm 6 2>nul';
            @exec($cmd, $o, $code);
            if ($code === 0 && is_file($txtPath . '.txt')) {
                $text = (string)@file_get_contents($txtPath . '.txt');
                @unlink($txtPath . '.txt');
                return $text;
            }
        } catch (Throwable $e) {
            error_log('[CertiVault] Smart Verify text extraction failed: ' . get_class($e));
        }
        return null;
    }

    public static function pdfParserAvailable(): bool
    {
        if (class_exists('\\Smalot\\PdfParser\\Parser')) {
            return true;
        }
        // Only allow loading from our own vendor dir.
        $vendor = dirname(__DIR__, 2) . '/vendor/autoload.php';
        if (is_file($vendor)) {
            require_once $vendor;
        }
        return class_exists('\\Smalot\\PdfParser\\Parser');
    }

    private static function findBinary(array $names): ?string
    {
        foreach ($names as $n) {
            if ($n === 'tesseract' && getenv('CV_TESSERACT_BIN')) {
                $p = getenv('CV_TESSERACT_BIN');
                if (is_file($p)) {
                    return $p;
                }
            }
            foreach (explode(PATH_SEPARATOR, getenv('PATH') ?: '') as $dir) {
                if ($dir === '') {
                    continue;
                }
                $candidate = rtrim($dir, '\\/') . DIRECTORY_SEPARATOR . $n . (DIRECTORY_SEPARATOR === '\\' ? '.exe' : '');
                if (is_file($candidate) && is_executable($candidate)) {
                    return $candidate;
                }
            }
        }
        return null;
    }
}
