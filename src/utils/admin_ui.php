<?php
// src/utils/admin_ui.php — presentation helpers for the institution /
// super-admin pages (admin_dashboard, issue/bulk, audit, analytics, revoke,
// supersede, rotate_key, view_certificate_admin, attestations, super_admin).
//
// Markup only: no database access, no session access, no side effects.
// Icons are inline SVG (CSP img-src forbids data: URIs) and always
// aria-hidden — every icon sits next to visible text or an aria-label.

if (!function_exists('cv_icon')) {
    /**
     * Return an inline stroke icon (24x24 grid) as an SVG string.
     * Unknown names return an empty string.
     */
    function cv_icon(string $name, string $class = ''): string
    {
        static $paths = [
            'check'     => '<path d="M20 6 9 17l-5-5"/>',
            'plus'      => '<path d="M12 5v14M5 12h14"/>',
            'award'     => '<circle cx="12" cy="8" r="6"/><path d="M15.5 12.9 17 22l-5-3-5 3 1.5-9.1"/>',
            'layers'    => '<path d="m12 2 10 5-10 5L2 7z"/><path d="m2 17 10 5 10-5"/><path d="m2 12 10 5 10-5"/>',
            'chart'     => '<path d="M3 3v18h18"/><path d="m7 15 4-4 3 3 6-6"/>',
            'history'   => '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/>',
            'key'       => '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.8-9.8M17 6l3 3M14 9l2 2"/>',
            'shield'    => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
            'search'    => '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
            'eye'       => '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
            'ban'       => '<circle cx="12" cy="12" r="9"/><path d="m5.7 5.7 12.6 12.6"/>',
            'refresh'   => '<path d="M21 12a9 9 0 0 1-15.4 6.4L3 16"/><path d="M3 12a9 9 0 0 1 15.4-6.4L21 8"/><path d="M21 3v5h-5M3 21v-5h5"/>',
            'alert'     => '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
            'users'     => '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>',
            'download'  => '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5M12 15V3"/>',
            'upload'    => '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5M12 3v12"/>',
            'copy'      => '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
            'arrow-right' => '<path d="M5 12h14M13 5l7 7-7 7"/>',
            'arrow-left'  => '<path d="M19 12H5M11 19l-7-7 7-7"/>',
            'file'      => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h5"/>',
            'inbox'     => '<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5.1 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.7 1.1z"/>',
            'calendar'  => '<rect x="3" y="4" width="18" height="18" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>',
            'mail'      => '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-10 6L2 7"/>',
            'user'      => '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
            'external'  => '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6M10 14 21 3"/>',
            'building'  => '<path d="M3 21h18M5 21V7l7-4 7 4v14"/><path d="M9 21v-6h6v6M9 10h.01M15 10h.01"/>',
            'lock'      => '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
            'x'         => '<path d="M18 6 6 18M6 6l12 12"/>',
            'activity'  => '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
            'filter'    => '<path d="M22 3H2l8 9.5V19l4 2v-8.5z"/>',
            'sparkles'  => '<path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z"/><path d="M19 17v4M17 19h4"/>',
            'database'  => '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5"/><path d="M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/>',
            'home'      => '<path d="m3 10 9-7 9 7v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M9 22V12h6v10"/>',
            'qr'        => '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 14v.01M14 20h.01M17 20h4v-3"/>',
            'hash'      => '<path d="M4 9h16M4 15h16M10 3 8 21M16 3l-2 18"/>',
            'clock'     => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
            'pen'       => '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>',
        ];
        if (!isset($paths[$name])) {
            return '';
        }
        $cls = 'icon' . ($class !== '' ? ' ' . $class : '');
        return '<svg class="' . htmlspecialchars($cls, ENT_QUOTES, 'UTF-8') . '" viewBox="0 0 24 24" width="20" height="20" fill="none"'
            . ' stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"'
            . ' aria-hidden="true" focusable="false">' . $paths[$name] . '</svg>';
    }
}

if (!function_exists('cv_initials')) {
    /** Up to two initials for an avatar bubble ("Léa Moreau" -> "LM"). */
    function cv_initials(?string $name): string
    {
        $parts = preg_split('/[\s._@-]+/u', trim((string)$name), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $out = '';
        foreach (array_slice($parts, 0, 2) as $p) {
            $out .= mb_strtoupper(mb_substr($p, 0, 1));
        }
        return $out !== '' ? $out : '?';
    }
}

if (!function_exists('cv_avatar_hue')) {
    /** Stable avatar colour slot (0-5) derived from the name — presentation only. */
    function cv_avatar_hue(?string $name): int
    {
        return (int)(crc32((string)$name) % 6);
    }
}

if (!function_exists('cv_error_art')) {
    /**
     * Decorative illustration for the error / 403 cards (inline SVG,
     * coloured by admin.css through theme tokens). $kind: 'lock' | 'broken'.
     */
    function cv_error_art(string $kind): string
    {
        $art = $kind === 'lock'
            ? '<path class="ea-fill" d="M84 20l34 13v25c0 23-14 41-34 50-20-9-34-27-34-50V33z"/>'
              . '<rect class="ea-line" x="70" y="60" width="28" height="22" rx="4"/><path class="ea-line" d="M75 60v-7a9 9 0 0 1 18 0v7"/>'
            : '<path class="ea-fill" d="M58 22h38l20 20v70a6 6 0 0 1-6 6H58a6 6 0 0 1-6-6V28a6 6 0 0 1 6-6z"/><path class="ea-line" d="M96 22v20h20"/>'
              . '<path class="ea-mark" d="M74 68l20 20M94 68l-20 20"/>';
        return '<svg class="error-art" viewBox="0 0 168 140" width="168" height="140" aria-hidden="true" focusable="false">'
            . '<ellipse class="ea-bg" cx="84" cy="72" rx="78" ry="60"/>'
            . '<circle class="ea-dot" cx="20" cy="28" r="5"/><circle class="ea-dot" cx="150" cy="112" r="4"/><circle class="ea-dot" cx="142" cy="22" r="3"/>'
            . $art . '</svg>';
    }
}

if (!function_exists('cv_status_badge')) {
    /** Badge class suffix for a certificate / verdict / bulk status. */
    function cv_status_badge(string $status): string
    {
        $s = strtolower($status);
        $map = ['active' => 'valid', 'pending_activation' => 'pending', 'skipped' => 'invalid', 'self_declared' => 'pending',
                'attested' => 'valid', 'withdrawn' => 'invalid'];
        return $map[$s] ?? $s;
    }
}
