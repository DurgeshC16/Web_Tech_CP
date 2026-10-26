<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/config/config.php';
if (!defined('ATTESTED_EXTERNAL_CREDENTIALS_ENABLED') || !ATTESTED_EXTERNAL_CREDENTIALS_ENABLED) { http_response_code(404); exit('External credential attestations are disabled.'); }
require_role('admin');
require_approved_institution();
$db = Database::getInstance();
$id = (int)($_GET['id'] ?? 0);
$stmt = $db->prepare('SELECT file_path FROM external_credentials WHERE id=:id AND file_path IS NOT NULL AND (status="SELF_DECLARED" OR attesting_institution_id=:iid) LIMIT 1');
$stmt->execute(['id'=>$id,'iid'=>(int)current_institution_id($db)]);
$name = $stmt->fetchColumn();
if (!is_string($name) || basename($name) !== $name || !preg_match('/^[a-f0-9]{48}\.pdf$/', $name)) deny_access_403();
$path = __DIR__ . '/../private_data/external_credentials/' . $name;
if (!is_file($path)) { http_response_code(404); exit('Supporting PDF not found.'); }
header('Content-Type: application/pdf');
header('Content-Disposition: attachment; filename="student-supporting-document.pdf"');
header('Content-Length: ' . filesize($path));
header('X-Content-Type-Options: nosniff');
readfile($path);
exit;
