<?php
// public/two_factor_qr.php — QR image (PNG) of the otpauth:// URI for the
// 2FA setup in progress. Served same-origin (no data: URI, CSP-friendly),
// only to the signed-in user, only while a setup secret is in their session.
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/TotpService.php';
require_once __DIR__ . '/../src/utils/phpqrcode/qrlib.php';

require_role(['admin', 'student', 'super_admin']);
$setup = $_SESSION['totp_setup'] ?? null;
if (!$setup || $setup['created'] < time() - 900) {
    http_response_code(404);
    exit;
}
$db = Database::getInstance();
$s = $db->prepare('SELECT email FROM users WHERE id = :id');
$s->execute(['id' => (int)$_SESSION['user_id']]);
$email = (string)$s->fetchColumn();

header('Content-Type: image/png');
header('Cache-Control: no-store, max-age=0');
header('X-Content-Type-Options: nosniff');
QRcode::png(TotpService::otpauthUri($setup['secret'], $email), false, 'M', 6, 2);
