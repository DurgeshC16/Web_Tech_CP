<?php
// src/services/QRService.php
require_once __DIR__ . '/../utils/phpqrcode/qrlib.php';
require_once __DIR__ . '/FileStore.php';

class QRService {
    /**
     * Generate a QR code for a given URL and save it to the file path.
     * With CV_FILE_STORE=db the PNG is also stored durably (FileStore;
     * throws when that fails, so an open issuance transaction rolls back).
     */
    public static function generateQRCode($url, $filePath) {
        // level = L (Low), size = 10, margin = 2
        QRcode::png($url, $filePath, 'L', 10, 2);
        FileStore::persist($filePath);
    }
}
