<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/CryptoService.php';

require_role('super_admin');

$db = Database::getInstance();
$message = '';
$errors = [];

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

    if (isset($_POST['reject_id'])) {
        $inst_id = (int)$_POST['reject_id'];
        $reason = trim($_POST['rejection_reason'] ?? '');

        if (($e = v_required($reason, 'Rejection reason')) !== true) {
            $errors['rejection_reason'] = $e;
        } elseif (($e = v_length($reason, 3, 500, 'Rejection reason')) !== true) {
            $errors['rejection_reason'] = $e;
        }

        if (empty($errors)) {
            $stmt = $db->prepare('UPDATE institutions SET status = "rejected", rejection_reason = :reason WHERE id = :id AND status = "pending"');
            $stmt->execute(['reason' => $reason, 'id' => $inst_id]);
            $message = $stmt->rowCount() > 0
                ? 'Institution rejected.'
                : 'Institution not found or already processed.';
        } else {
            $message = 'Please correct the highlighted fields below.';
        }
    }
}

// ── Status filter (Pending / Approved / Rejected) ───────────────────
$allowed_filters = ['pending', 'approved', 'rejected'];
$active_filter = $_GET['status'] ?? 'pending';
if (!in_array($active_filter, $allowed_filters, true)) {
    $active_filter = 'pending';
}

$stmt = $db->prepare('SELECT i.id, i.name, u.email, i.rejection_reason FROM institutions i JOIN users u ON i.user_id = u.id WHERE i.status = :status ORDER BY i.id DESC');
$stmt->execute(['status' => $active_filter]);
$filtered_institutions = $stmt->fetchAll();

?>
<?php $page_title = 'Super Admin - CertiVault'; require __DIR__ . '/../src/partials/head.php'; ?>
<?php require __DIR__ . '/../src/partials/header.php'; ?>
<main id="main">
    <div class="container shell-wide">
        <div class="page-head">
            <h2>Super Admin Dashboard</h2>
            <div>
                <a href="change_password.php" class="btn btn-secondary">Change Password</a>
            </div>
        </div>

        <?php if ($message): ?>
            <div class="alert alert-info"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>
        <?php if (!empty($errors['rejection_reason'])): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($errors['rejection_reason']) ?></div>
        <?php endif; ?>

        <div class="tabs">
            <a class="tab <?= $active_filter === 'pending' ? 'active' : '' ?>" href="super_admin.php?status=pending">Pending</a>
            <a class="tab <?= $active_filter === 'approved' ? 'active' : '' ?>" href="super_admin.php?status=approved">Approved</a>
            <a class="tab <?= $active_filter === 'rejected' ? 'active' : '' ?>" href="super_admin.php?status=rejected">Rejected</a>
        </div>

        <h3><?= htmlspecialchars(ucfirst($active_filter)) ?> Institutions</h3>
        <?php if (count($filtered_institutions) > 0): ?>
            <div class="table-wrap">
            <table class="table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Email</th>
                        <?php if ($active_filter === 'rejected'): ?><th>Reason</th><?php endif; ?>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($filtered_institutions as $inst): ?>
                        <tr>
                            <td><?= (int)$inst['id'] ?></td>
                            <td><?= htmlspecialchars($inst['name']) ?></td>
                            <td><?= htmlspecialchars($inst['email']) ?></td>
                            <?php if ($active_filter === 'rejected'): ?>
                                <td><?= htmlspecialchars($inst['rejection_reason'] ?? '') ?></td>
                            <?php endif; ?>
                            <td>
                                <?php if ($active_filter === 'pending'): ?>
                                <form method="POST" action="" class="inline-form" onsubmit="return confirm('Approve this institution and generate its RSA keys?');">
                                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                                    <input type="hidden" name="approve_id" value="<?= (int)$inst['id'] ?>">
                                    <button type="submit" class="btn btn-primary">Approve</button>
                                </form>
                                <form method="POST" action="" class="inline-form" style="margin-top:6px;" onsubmit="return confirm('Reject this institution?');">
                                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                                    <input type="hidden" name="reject_id" value="<?= (int)$inst['id'] ?>">
                                    <input type="text" name="rejection_reason" placeholder="Reason (required)" data-validate="required|min:3|max:500" required>
                                    <button type="submit" class="btn btn-danger">Reject</button>
                                </form>
                                <?php else: ?>
                                    —
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            </div>
        <?php else: ?>
            <p>No <?= htmlspecialchars($active_filter) ?> institutions.</p>
        <?php endif; ?>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
    <script src="assets/js/validation.js"></script>
</body>
</html>
