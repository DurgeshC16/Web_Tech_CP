<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_role('student');

$cert_id = (int)($_GET['id'] ?? 0);
$db = Database::getInstance();

// Ownership enforced centrally: any miss (no row, wrong owner, bad id)
// ends in a uniform 403, never an existence oracle.
$student_id = current_student_id($db);
$cert = require_owned_certificate($db, $cert_id, 'student', $student_id, 'c.file_path, c.student_id');

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
