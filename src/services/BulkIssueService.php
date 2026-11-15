<?php
// src/services/BulkIssueService.php
// CSV parsing/validation and CSV export helpers for bulk issuance
// (public/bulk_issue.php). Validation uses exactly the same validators as
// single issuance; nothing here writes to the database.

require_once __DIR__ . '/../utils/helpers.php';
require_once __DIR__ . '/../utils/validators.php';

class BulkIssueService
{
    public const MAX_ROWS = 200;
    public const MAX_BYTES = 1048576;
    public const REQUIRED = ['student_email', 'student_name', 'title', 'issue_date'];
    public const OPTIONAL = ['expiry_date', 'certificate_id'];

    /**
     * Parse + validate a CSV file.
     * @return array{0: array<int, array>, 1: ?string} rows (each with 'line' and
     *         'errors'), or a fatal error message for the whole file
     */
    public static function parseCsv($db, string $path, string $originalName, int $size): array
    {
        if ($size > self::MAX_BYTES) {
            return [[], 'The CSV file is larger than 1 MB.'];
        }
        if (strtolower(pathinfo($originalName, PATHINFO_EXTENSION)) !== 'csv') {
            return [[], 'Upload a .csv file (use the template).'];
        }
        $mime = (new finfo(FILEINFO_MIME_TYPE))->file($path);
        if (!in_array($mime, ['text/plain', 'text/csv', 'application/csv', 'text/x-csv', 'application/vnd.ms-excel'], true)) {
            return [[], 'The file does not look like a CSV text file.'];
        }
        $fh = fopen($path, 'r');
        $header = fgetcsv($fh, 0, ',', '"', '');
        if (!$header || $header === [null]) {
            fclose($fh);
            return [[], 'The CSV file is empty.'];
        }
        $header[0] = preg_replace('/^\xEF\xBB\xBF/', '', (string)$header[0]); // Excel BOM
        $cols = array_map(fn($h) => strtolower(trim((string)$h)), $header);
        $missing = array_diff(self::REQUIRED, $cols);
        if ($missing) {
            fclose($fh);
            return [[], 'Missing column(s): ' . implode(', ', $missing) . '. Download the template for the exact header row.'];
        }

        $rows = [];
        $seenIds = [];
        $line = 1;
        while (($cells = fgetcsv($fh, 0, ',', '"', '')) !== false) {
            $line++;
            if ($cells === [null] || trim(implode('', $cells)) === '') {
                continue; // blank line
            }
            if (count($rows) >= self::MAX_ROWS) {
                fclose($fh);
                return [[], 'Too many rows: at most ' . self::MAX_ROWS . ' certificates per file.'];
            }
            $r = ['line' => $line];
            foreach (array_merge(self::REQUIRED, self::OPTIONAL) as $c) {
                $i = array_search($c, $cols, true);
                $r[$c] = $i === false ? '' : sanitize_input((string)($cells[$i] ?? ''));
            }
            $e = [];
            if (($m = v_required($r['student_email'], 'Student email')) !== true || ($m = v_email($r['student_email'])) !== true) { $e[] = $m; }
            if (($m = v_required($r['student_name'], 'Student name')) !== true || ($m = v_person_name($r['student_name'])) !== true) { $e[] = $m; }
            if (($m = v_required($r['title'], 'Title')) !== true || ($m = v_length($r['title'], 3, 200, 'Title')) !== true) { $e[] = $m; }
            if (($m = v_required($r['issue_date'], 'Issue date')) !== true || ($m = v_date_range($r['issue_date'], null)) !== true) { $e[] = $m; }
            if ($r['expiry_date'] !== '' && empty($e) && ($m = v_date_after($r['expiry_date'], $r['issue_date'], 'Expiry date')) !== true) { $e[] = $m; }
            if ($r['certificate_id'] !== '') {
                if (($m = v_certificate_id_flexible($r['certificate_id'], $db)) !== true) { $e[] = $m; }
                $key = strtolower($r['certificate_id']);
                if (isset($seenIds[$key])) { $e[] = 'Certificate ID repeats row ' . $seenIds[$key] . '.'; }
                $seenIds[$key] = $line;
            }
            $r['errors'] = $e;
            $rows[] = $r;
        }
        fclose($fh);
        return $rows ? [$rows, null] : [[], 'The CSV file has no data rows.'];
    }

    /** Neutralise spreadsheet formula injection in exported cells. */
    public static function csvCell($v): string
    {
        $v = (string)$v;
        return ($v !== '' && strpbrk($v[0], "=+-@\t\r") !== false) ? "'" . $v : $v;
    }

    /** Stream a CSV download and exit. */
    public static function sendCsv(string $name, array $header, array $rows): void
    {
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="' . $name . '"');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store');
        $out = fopen('php://output', 'w');
        fwrite($out, "\xEF\xBB\xBF"); // UTF-8 BOM for spreadsheet apps
        fputcsv($out, $header, ',', '"', '');
        foreach ($rows as $r) {
            fputcsv($out, array_map([self::class, 'csvCell'], $r), ',', '"', '');
        }
        fclose($out);
        exit;
    }
}
