<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/CryptoService.php';

require_role('super_admin');

$db = Database::getInstance();
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');
    
    if (isset($_POST['approve_id'])) {
        $inst_id = (int)$_POST['approve_id'];
        
        try {
            $db->beginTransaction();
            
            // Check if still pending
            $stmt = $db->prepare('SELECT id FROM institutions WHERE id = :id AND status = "pending" FOR UPDATE');
            $stmt->execute(['id' => $inst_id]);
            
            if ($stmt->fetch()) {
                // Generate Keys
                $keys = CryptoService::generateRSAKeyPair();
                $encryptedPriv = CryptoService::encryptPrivateKey($keys['private_key']);
                
                // Update
                $update = $db->prepare('UPDATE institutions SET status = "approved", public_key = :pub, encrypted_private_key = :priv WHERE id = :id');
                $update->execute([
                    'pub' => $keys['public_key'],
                    'priv' => $encryptedPriv,
                    'id' => $inst_id
                ]);
                
                $db->commit();
                $message = "Institution approved and RSA keys generated successfully.";
            } else {
                $db->rollBack();
                $message = "Institution not found or already processed.";
            }
        } catch (Exception $e) {
            $db->rollBack();
            $message = "Error approving institution: " . $e->getMessage();
        }
    }
}

// Fetch pending institutions
$stmt = $db->query('SELECT i.id, i.name, u.email FROM institutions i JOIN users u ON i.user_id = u.id WHERE i.status = "pending"');
$pending_institutions = $stmt->fetchAll();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Super Admin - CertiVault</title>
    <link rel="stylesheet" href="assets/css/style.css">
    <?php require_once __DIR__ . '/../src/partials/head_fonts.php'; ?>
</head>
<body>
    <div class="container shell-wide">
        <div class="page-head">
            <h2>Super Admin Dashboard</h2>
            <a href="logout.php" class="btn btn-secondary">Logout</a>
        </div>

        <?php if ($message): ?>
            <div class="alert alert-info"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>
        
        <h3>Pending Institutions</h3>
        <?php if (count($pending_institutions) > 0): ?>
            <div class="table-wrap">
            <table class="table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($pending_institutions as $inst): ?>
                        <tr>
                            <td><?= $inst['id'] ?></td>
                            <td><?= htmlspecialchars($inst['name']) ?></td>
                            <td><?= htmlspecialchars($inst['email']) ?></td>
                            <td>
                                <form method="POST" action="" class="inline-form">
                                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                                    <input type="hidden" name="approve_id" value="<?= $inst['id'] ?>">
                                    <button type="submit" class="btn btn-primary">Approve</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            </div>
        <?php else: ?>
            <p>No pending institutions.</p>
        <?php endif; ?>
    </div>
</body>
</html>
