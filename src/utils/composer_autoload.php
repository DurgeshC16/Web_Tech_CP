<?php
// src/utils/composer_autoload.php
// ─────────────────────────────────────────────────────────────────────
// Safe loader for the OPTIONAL Composer packages (dompdf, smalot/pdfparser).
//
// vendor/ is not committed — run `composer install` to populate it. A
// partially installed vendor/ (autoload.php present but package folders
// empty) used to make Composer's eager "files" autoload throw a fatal
// "Failed opening required ..." error, which crashed report.php and the
// Smart Verify PDF text pipeline instead of degrading gracefully.
//
// This loader verifies that every eagerly-required file exists before
// including the autoloader, and never lets a broken install take a page
// down: callers just see "package unavailable" and use their fallback.
// ─────────────────────────────────────────────────────────────────────

function cv_composer_autoload(): bool
{
    static $loaded = null;
    if ($loaded !== null) {
        return $loaded;
    }

    $vendor   = dirname(__DIR__, 2) . '/vendor';
    $autoload = $vendor . '/autoload.php';
    if (!is_file($autoload)) {
        return $loaded = false;
    }

    // Composer requires these files unconditionally on load; if any is
    // missing the install is incomplete and including autoload.php fails.
    $filesMap = $vendor . '/composer/autoload_files.php';
    if (is_file($filesMap)) {
        $files = include $filesMap;
        if (is_array($files)) {
            foreach ($files as $file) {
                if (!is_file($file)) {
                    error_log('[CertiVault] vendor/ is incomplete (missing ' . basename($file)
                        . '); run "composer install". Optional PDF features are disabled.');
                    return $loaded = false;
                }
            }
        }
    }

    try {
        require_once $autoload;
        return $loaded = true;
    } catch (\Throwable $e) {
        error_log('[CertiVault] Composer autoload failed: ' . get_class($e) . '; optional PDF features are disabled.');
        return $loaded = false;
    }
}
