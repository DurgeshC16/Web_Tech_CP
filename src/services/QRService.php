<?php
// src/services/QRService.php
require_once __DIR__ . '/../utils/phpqrcode/qrlib.php';

class QRService {
    /**
     * Generate a QR code for a given URL and save it to the file path.
     */
    public static function generateQRCode($url, $filePath) {
        // level = L (Low), size = 10, margin = 2
        QRcode::png($url, $filePath, 'L', 10, 2);
    }
}
