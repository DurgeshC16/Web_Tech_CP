<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_role('student');

$cert_id = (int)($_GET['id'] ?? 0);
$db = Database::getInstance();

// Verify ownership
$stmt = $db->prepare('SELECT id FROM students WHERE user_id = :user_id LIMIT 1');
$stmt->execute(['user_id' => $_SESSION['user_id']]);
$student_id = $stmt->fetchColumn();

$stmt = $db->prepare('SELECT file_path FROM certificates WHERE id = :id AND student_id = :student_id');
$stmt->execute(['id' => $cert_id, 'student_id' => $student_id]);
$cert = $stmt->fetch();

if (!$cert) {
    show_error_page('Access Denied', 'You do not have permission to download this file.');
}

$filepath = __DIR__ . '/../private_data/uploads/' . $cert['file_path'];

if (file_exists($filepath)) {
    // Serve the file
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $filepath);
    finfo_close($finfo);
    
    header('Content-Description: File Transfer');
    header('Content-Type: ' . $mime);
    header('Content-Disposition: attachment; filename="' . basename($filepath) . '"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($filepath));
    readfile($filepath);
    exit;
} else {
    show_error_page('File Missing', 'The certificate file could not be found on the server.');
}
