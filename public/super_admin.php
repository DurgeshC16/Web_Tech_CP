<?php
require_once __DIR__ . '/../src/config/Database.php';
require_once __DIR__ . '/../src/utils/helpers.php';
require_once __DIR__ . '/../src/services/CryptoService.php';
require_once __DIR__ . '/../src/services/KeyPinService.php';
require_once __DIR__ . '/../src/services/ExternalSourceService.php';

require_role('super_admin');

$db = Database::getInstance();
$message = '';
$errors = [];
$active_tab = ($_GET['tab'] ?? $_POST['tab'] ?? 'institutions') === 'external_sources' ? 'external_sources' : 'institutions';
$source_form = ['id' => 0, 'slug' => '', 'label' => '', 'type' => 'open_badges', 'allowed_host' => '', 'rate_limit' => 15, 'enabled' => 0, 'config_json' => ''];

function external_source_hosts_valid(string $hosts, bool $remoteDb = false): bool {
    foreach (explode(',', strtolower(trim($hosts))) as $host) {
        $host = trim($host);
        if ($remoteDb && in_array($host, ['localhost', '127.0.0.1', '::1'], true)) continue;
        if ($host === '' || strlen($host) > 253 || !preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/', $host)) return false;
    }
    return true;
}
function external_source_adapter(array $source): ExternalSourceInterface {
    $config = $source['config'];
    $hosts = array_map('trim', explode(',', strtolower($source['allowed_host'])));
    if ($source['type'] === 'open_badges' && ($config['provider'] ?? '') === 'credly') {
        return new CredlyAdapter($source['label'], $hosts, $source['rate_limit']);
    }
    if ($source['type'] === 'open_badges') {
        return new OpenBadgesAdapter((string)($config['template'] ?? ''), $source['label'], $hosts, $source['rate_limit']);
    }
    $config['label'] = $source['label']; $config['allowed_hosts'] = $hosts; $config['rate_limit'] = $source['rate_limit'];
    return new RemoteDbAdapter($config);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validate_csrf_token($_POST['csrf_token'] ?? '');

    if (isset($_POST['source_save']) || isset($_POST['source_test'])) {
        $source_form = [
            'id' => (int)($_POST['source_id'] ?? 0), 'slug' => trim((string)($_POST['slug'] ?? '')),
            'label' => trim((string)($_POST['label'] ?? '')), 'type' => (string)($_POST['type'] ?? ''),
            'allowed_host' => strtolower(trim((string)($_POST['allowed_host'] ?? ''))),
            'rate_limit' => (int)($_POST['rate_limit'] ?? 15), 'enabled' => isset($_POST['enabled']) ? 1 : 0,
            'config_json' => trim((string)($_POST['config_json'] ?? '')),
        ];
        $config = $source_form['config_json'] === '' ? [] : json_decode($source_form['config_json'], true);
        $configIsObject = $source_form['config_json'] === '' || is_object(json_decode($source_form['config_json']));
        if (!preg_match('/^[a-z0-9][a-z0-9_-]{1,63}$/', $source_form['slug'])) $errors['source'] = 'Use a lowercase slug with letters, numbers, _ or -.';
        elseif ($source_form['label'] === '' || mb_strlen($source_form['label']) > 120) $errors['source'] = 'A label (max 120 characters) is required.';
        elseif (!in_array($source_form['type'], ['open_badges', 'remote_db'], true)) $errors['source'] = 'Choose a supported source type.';
        elseif (!external_source_hosts_valid($source_form['allowed_host'], $source_form['type'] === 'remote_db')) $errors['source'] = 'Allowed hosts must be comma-separated DNS hostnames (no scheme, path, port, or wildcard).';
        elseif ($source_form['rate_limit'] < 1 || $source_form['rate_limit'] > 1000) $errors['source'] = 'Rate limit must be between 1 and 1000.';
        elseif (!is_array($config) || !$configIsObject) $errors['source'] = 'Configuration must be a JSON object.';
        else {
            try {
                $existing = null;
                if ($source_form['id'] > 0) {
                    $q = $db->prepare('SELECT config_json FROM external_sources WHERE id = :id');
                    $q->execute(['id' => $source_form['id']]); $existing = $q->fetchColumn();
                }
                if ($source_form['config_json'] === '' && is_string($existing)) $config = json_decode(CryptoService::decryptConfig($existing), true) ?: [];
                elseif (is_string($existing)) {
                    $old = json_decode(CryptoService::decryptConfig($existing), true) ?: [];
                    foreach ($config as $key => $value) {
                        if (preg_match('/pass|password|secret|token|api.?key/i', (string)$key)
                            && ($value === '' || $value === '[stored]') && array_key_exists($key, $old)) $config[$key] = $old[$key];
                    }
                }
                if (isset($_POST['source_test'])) {
                    $adapter = external_source_adapter($source_form + ['config' => $config]);
                    $sample = trim((string)($_POST['sample_id'] ?? ''));
                    if ($sample === '') $sample = $source_form['type'] === 'open_badges' && ($config['provider'] ?? '') === 'credly'
                        ? '00000000-0000-4000-8000-000000000000' : 'DEMO-MOOC-001';
                    $hit = $adapter->fetch($sample);
                    $message = $hit ? 'Connection succeeded; sample record returned.' : 'Connection attempted; no sample record was returned.';
                } else {
                    $encrypted = CryptoService::encryptConfig(json_encode($config, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
                    if ($source_form['id'] > 0) {
                        $stmt = $db->prepare('UPDATE external_sources SET slug=:slug,label=:label,type=:type,config_json=:config,enabled=:enabled,allowed_host=:host,rate_limit=:limit WHERE id=:id');
                        $stmt->execute(['slug'=>$source_form['slug'],'label'=>$source_form['label'],'type'=>$source_form['type'],'config'=>$encrypted,'enabled'=>$source_form['enabled'],'host'=>$source_form['allowed_host'],'limit'=>$source_form['rate_limit'],'id'=>$source_form['id']]);
                    } else {
                        $stmt = $db->prepare('INSERT INTO external_sources (slug,label,type,config_json,enabled,allowed_host,rate_limit) VALUES (:slug,:label,:type,:config,:enabled,:host,:limit)');
                        $stmt->execute(['slug'=>$source_form['slug'],'label'=>$source_form['label'],'type'=>$source_form['type'],'config'=>$encrypted,'enabled'=>$source_form['enabled'],'host'=>$source_form['allowed_host'],'limit'=>$source_form['rate_limit']]);
                    }
                    $message = 'External source saved.';
                    $source_form['config_json'] = '';
                }
            } catch (Throwable $e) {
                error_log('[CertiVault] External source admin action failed: ' . get_class($e) . ': ' . $e->getMessage());
                $errors['source'] = isset($_POST['source_test']) ? 'Connection failed. Check the source configuration and allow-list.' : 'Source could not be saved. Check the slug is unique and configuration is valid.';
            }
        }
    } elseif (isset($_POST['source_disable'])) {
        $stmt = $db->prepare('UPDATE external_sources SET enabled = 0 WHERE id = :id');
        $stmt->execute(['id' => (int)$_POST['source_disable']]);
        $message = 'External source disabled.';
        $active_tab = 'external_sources';
    }

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

                // Round-trip test before committing approval
                $roundTripPriv = CryptoService::decryptPrivateKey($encryptedPriv);
                if (!CryptoService::verifyKeyPair($roundTripPriv, $keys['public_key'])) {
                    throw new Exception('Generated key pair failed the round-trip verification.');
                }

                // Update
                $update = $db->prepare('UPDATE institutions SET status = "approved" WHERE id = :id');
                $update->execute(['id' => $inst_id]);
                $keyInsert = $db->prepare('INSERT INTO institution_keys (institution_id,key_id,public_key,encrypted_private_key,status,valid_from) VALUES (:iid,1,:pub,:priv,"active",NOW())');
                $keyInsert->execute(['iid'=>$inst_id,'pub'=>$keys['public_key'],'priv'=>$encryptedPriv]);

                $db->commit();
                // Pin the new key's fingerprint outside the database.
                KeyPinService::pinQuietly((int)$inst_id, 1, $keys['public_key'], 'approval');
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

if (isset($_GET['edit_source'])) {
    $stmt = $db->prepare('SELECT * FROM external_sources WHERE id = :id');
    $stmt->execute(['id' => (int)$_GET['edit_source']]);
    $row = $stmt->fetch();
    if ($row) {
        $source_form = array_merge($source_form, $row);
        try {
            $config = json_decode(CryptoService::decryptConfig((string)$row['config_json']), true) ?: [];
            foreach ($config as $key => $value) if (preg_match('/pass|password|secret|token|api.?key/i', (string)$key)) $config[$key] = '[stored]';
            $source_form['config_json'] = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        } catch (Throwable $e) { $source_form['config_json'] = '{}'; }
        $active_tab = 'external_sources';
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
<?php
require_once __DIR__ . '/../src/utils/admin_ui.php';
$filter_labels = ['pending' => 'Pending', 'approved' => 'Approved', 'rejected' => 'Rejected'];
$filter_icons = ['pending' => 'clock', 'approved' => 'check', 'rejected' => 'x'];
$page_title = 'Super Admin - CertiVault';
require __DIR__ . '/../src/partials/head.php';
require __DIR__ . '/../src/partials/header.php';
?>
<main id="main">
    <div class="admin-shell">
        <section class="admin-hero" aria-labelledby="saTitle">
            <span class="admin-hero-art" aria-hidden="true"><?= cv_icon('building') ?></span>
            <div class="admin-hero-grid">
                <div>
                    <span class="admin-eyebrow"><?= cv_icon('shield') ?> Platform administration</span>
                    <h1 id="saTitle">Super Admin Dashboard</h1>
                    <p class="admin-hero-sub">Review institutions before they can sign certificates, and manage the external registries verifiers can query.</p>
                    <div class="hero-chips">
                        <span class="hero-chip"><?= cv_icon('building') ?> <?= count($filtered_institutions) ?> <?= htmlspecialchars(strtolower($filter_labels[$active_filter])) ?> institution<?= count($filtered_institutions) === 1 ? '' : 's' ?></span>
                        <span class="hero-chip"><?= cv_icon('database') ?> Registry lookups <?= EXT_REGISTRY_ENABLED ? 'enabled' : 'disabled' ?></span>
                    </div>
                </div>
                <div class="admin-hero-actions">
                    <a href="change_password.php" class="btn btn-outline-light"><?= cv_icon('lock') ?> Change Password</a>
                </div>
            </div>
        </section>

        <?php if ($message): ?>
            <div class="alert alert-info" role="status"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>
        <?php if (!empty($errors['rejection_reason'])): ?>
            <div class="alert alert-danger" role="alert"><?= htmlspecialchars($errors['rejection_reason']) ?></div>
        <?php endif; ?>

        <div class="tab-bar">
            <nav class="tabs" aria-label="Sections">
                <a class="tab <?= $active_tab === 'institutions' ? 'active' : '' ?>"<?= $active_tab === 'institutions' ? ' aria-current="page"' : '' ?> href="super_admin.php?tab=institutions&amp;status=<?= htmlspecialchars($active_filter) ?>"><?= cv_icon('building') ?> Institutions</a>
                <a class="tab <?= $active_tab === 'external_sources' ? 'active' : '' ?>"<?= $active_tab === 'external_sources' ? ' aria-current="page"' : '' ?> href="super_admin.php?tab=external_sources"><?= cv_icon('database') ?> External sources</a>
            </nav>
            <?php if ($active_tab === 'institutions'): ?>
            <nav class="tabs" aria-label="Institution status">
                <?php foreach ($filter_labels as $fk => $fl): ?>
                    <a class="tab <?= $active_filter === $fk ? 'active' : '' ?>"<?= $active_filter === $fk ? ' aria-current="page"' : '' ?> href="super_admin.php?status=<?= $fk ?>"><?= cv_icon($filter_icons[$fk]) ?> <?= $fl ?></a>
                <?php endforeach; ?>
            </nav>
            <?php endif; ?>
        </div>

        <?php if ($active_tab === 'institutions'): ?>
        <section aria-labelledby="queueTitle">
            <div class="section-label">
                <h2 id="queueTitle"><?= htmlspecialchars(ucfirst($active_filter)) ?> Institutions</h2>
                <p><?= $active_filter === 'pending' ? 'Approving generates the institution’s RSA signing keys.' : 'Read-only list.' ?></p>
            </div>
            <?php if (count($filtered_institutions) > 0): ?>
                <div class="approval-grid">
                    <?php foreach ($filtered_institutions as $idx => $inst): ?>
                        <article class="card approval-card" data-reveal data-reveal-delay="<?= min(5, $idx + 1) ?>">
                            <div class="approval-top">
                                <span class="avatar avatar-lg avatar-<?= cv_avatar_hue($inst['name']) ?>" aria-hidden="true"><?= htmlspecialchars(cv_initials($inst['name'])) ?></span>
                                <div class="flex-1">
                                    <h3><?= htmlspecialchars($inst['name']) ?></h3>
                                    <p><?= htmlspecialchars($inst['email']) ?></p>
                                </div>
                            </div>
                            <div class="approval-meta">
                                <span class="id-chip">ID <?= (int)$inst['id'] ?></span>
                                <span class="badge-status badge-<?= htmlspecialchars($active_filter) ?>"><?= htmlspecialchars($active_filter) ?></span>
                            </div>
                            <?php if ($active_filter === 'rejected'): ?>
                                <p class="reason-note"><strong>Reason:</strong> <?= htmlspecialchars($inst['rejection_reason'] ?? '') ?></p>
                            <?php endif; ?>
                            <?php if ($active_filter === 'pending'): ?>
                            <div class="approval-actions">
                                <form method="POST" action="" class="inline-form" data-confirm="Approve this institution and generate its RSA keys?">
                                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                                    <input type="hidden" name="approve_id" value="<?= (int)$inst['id'] ?>">
                                    <button type="submit" class="btn btn-verified btn-block"><?= cv_icon('check') ?> Approve</button>
                                </form>
                                <form method="POST" action="" class="inline-form" data-confirm="Reject this institution?">
                                    <input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>">
                                    <input type="hidden" name="reject_id" value="<?= (int)$inst['id'] ?>">
                                    <div class="form-group m-0">
                                        <label for="reject_reason_<?= (int)$inst['id'] ?>" class="visually-hidden">Rejection reason for <?= htmlspecialchars($inst['name']) ?></label>
                                        <div class="reject-form">
                                            <input type="text" name="rejection_reason" id="reject_reason_<?= (int)$inst['id'] ?>" placeholder="Reason (required)" data-validate="required|min:3|max:500" required>
                                            <button type="submit" class="btn btn-danger"><?= cv_icon('x') ?> Reject</button>
                                        </div>
                                    </div>
                                </form>
                            </div>
                            <?php endif; ?>
                        </article>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="card">
                    <div class="empty-state">
                        <span class="empty-state-icon"><?= cv_icon($active_filter === 'pending' ? 'inbox' : 'building') ?></span>
                        <h3><?= $active_filter === 'pending' ? 'Queue is empty' : 'Nothing here' ?></h3>
                        <p>No <?= htmlspecialchars($active_filter) ?> institutions.</p>
                    </div>
                </div>
            <?php endif; ?>
        </section>
        <?php else: ?>
        <section class="card data-card" aria-labelledby="sourcesTitle">
            <div class="card-head">
                <div class="card-head-text">
                    <h2 id="sourcesTitle">Managed external sources</h2>
                    <p>Registry lookups are <?= EXT_REGISTRY_ENABLED ? 'enabled' : 'disabled by default' ?>. Source settings are encrypted at rest; secret values are never shown again.</p>
                </div>
            </div>
            <?php if (!empty($errors['source'])): ?><div class="alert alert-danger" role="alert"><?= htmlspecialchars($errors['source']) ?></div><?php endif; ?>
            <?php
            $sources = $db->query('SELECT id,slug,label,type,enabled,allowed_host,rate_limit FROM external_sources ORDER BY label')->fetchAll();
            ?>
            <?php if ($sources): ?><div class="table-wrap"><table class="table admin-table"><thead><tr><th scope="col">Source</th><th scope="col">Type</th><th scope="col">Allowed hosts</th><th scope="col">Rate/min</th><th scope="col">State</th><th scope="col" class="actions-cell">Actions</th></tr></thead><tbody>
            <?php foreach ($sources as $s): ?><tr>
                <td data-label="Source"><span class="cell-stack"><span class="cell-title"><?= htmlspecialchars($s['label']) ?></span><span class="cell-sub">(<?= htmlspecialchars($s['slug']) ?>)</span></span></td>
                <td data-label="Type"><?= htmlspecialchars($s['type']) ?></td>
                <td data-label="Allowed hosts" class="wrap-anywhere"><?= htmlspecialchars($s['allowed_host']) ?></td>
                <td data-label="Rate/min" class="num"><?= (int)$s['rate_limit'] ?></td>
                <td data-label="State"><span class="badge-status badge-<?= $s['enabled'] ? 'valid' : 'invalid' ?>"><?= $s['enabled'] ? 'Enabled' : 'Disabled' ?></span></td>
                <td data-label="Actions" class="actions-cell"><span class="row-actions"><a class="btn btn-secondary btn-sm" href="super_admin.php?tab=external_sources&amp;edit_source=<?= (int)$s['id'] ?>"><?= cv_icon('pen') ?> Edit</a> <form method="POST" class="inline-form"><input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>"><input type="hidden" name="tab" value="external_sources"><button class="btn btn-danger btn-sm" name="source_disable" value="<?= (int)$s['id'] ?>">Disable</button></form></span></td>
            </tr><?php endforeach; ?>
            </tbody></table></div><?php else: ?>
                <div class="empty-state">
                    <span class="empty-state-icon"><?= cv_icon('database') ?></span>
                    <h3>No external sources yet</h3>
                    <p>Add an Open Badges / Credly source or a remote database below.</p>
                </div>
            <?php endif; ?>
        </section>

        <section class="card form-card" aria-labelledby="sourceFormTitle">
            <div class="card-head">
                <div class="card-head-text">
                    <h2 id="sourceFormTitle"><?= $source_form['id'] ? 'Edit' : 'Add' ?> source</h2>
                    <p>Hosts are allow-listed; anything else is refused.</p>
                </div>
            </div>
            <form method="POST" class="source-form"><input type="hidden" name="csrf_token" value="<?= generate_csrf_token() ?>"><input type="hidden" name="tab" value="external_sources"><input type="hidden" name="source_id" value="<?= (int)$source_form['id'] ?>">
                <fieldset class="form-section">
                    <legend class="form-section-title"><span class="form-section-num" aria-hidden="true">1</span> Identity</legend>
                    <div class="form-row">
                        <div class="form-group"><label for="src_slug">Slug</label><input id="src_slug" name="slug" required pattern="[a-z0-9][a-z0-9_-]{1,63}" data-validate="required|min:2|max:64" value="<?= htmlspecialchars((string)$source_form['slug']) ?>"></div>
                        <div class="form-group"><label for="src_label">Label</label><input id="src_label" name="label" required maxlength="120" data-validate="required|min:1|max:120" value="<?= htmlspecialchars((string)$source_form['label']) ?>"></div>
                    </div>
                    <div class="form-group"><label for="src_type">Type</label><select id="src_type" name="type"><option value="open_badges" <?= $source_form['type']==='open_badges'?'selected':'' ?>>Open Badges / Credly</option><option value="remote_db" <?= $source_form['type']==='remote_db'?'selected':'' ?>>Remote database</option></select></div>
                </fieldset>
                <fieldset class="form-section">
                    <legend class="form-section-title"><span class="form-section-num" aria-hidden="true">2</span> Network &amp; limits</legend>
                    <div class="form-row">
                        <div class="form-group"><label for="src_hosts">Allowed hosts (comma-separated)</label><input id="src_hosts" name="allowed_host" required data-validate="required|max:255" value="<?= htmlspecialchars((string)$source_form['allowed_host']) ?>" placeholder="api.credly.com,www.credly.com"></div>
                        <div class="form-group"><label for="src_rate">Rate limit / 10 minutes / IP</label><input id="src_rate" type="number" name="rate_limit" min="1" max="1000" value="<?= (int)$source_form['rate_limit'] ?>" data-validate="required|number|range:1,1000" required></div>
                    </div>
                </fieldset>
                <fieldset class="form-section">
                    <legend class="form-section-title"><span class="form-section-num" aria-hidden="true">3</span> Adapter</legend>
                    <div class="form-group"><label for="src_config">Adapter configuration (JSON; secrets encrypted)</label><textarea id="src_config" class="mono" name="config_json" rows="7" data-validate="json" placeholder='Credly: {"provider":"credly"}; Open Badges: {"template":"https://…/{id}"}; remote DB: {"dsn":"mysql:…","user":"…","pass":"…","table":"external_certificates","cols":{"id":"certificate_id","holder":"holder","title":"title","issuer":"issuer","date":"issue_date","status":"status"}}'><?= htmlspecialchars((string)$source_form['config_json']) ?></textarea></div>
                    <label class="checkbox-row"><input type="checkbox" name="enabled" value="1" <?= $source_form['enabled']?'checked':'' ?>> Enable this source</label>
                    <div class="form-group"><label for="src_sample">Sample lookup ID (optional)</label><input id="src_sample" name="sample_id" maxlength="255"></div>
                </fieldset>
                <div class="form-actions">
                    <p class="config-hint">To enable lookups set <code>EXT_REGISTRY_ENABLED</code> to true in <code>src/config/config.php</code> or local configuration. Legacy EXT_* config remains a fallback.</p>
                    <div class="btn-row m-0">
                        <button class="btn btn-primary" name="source_save" value="1"><?= cv_icon('check') ?> Save source</button>
                        <button class="btn btn-secondary" name="source_test" value="1"><?= cv_icon('activity') ?> Test connection (without saving)</button>
                    </div>
                </div>
            </form>
        </section>
        <?php endif; ?>
    </div>
</main>
<?php require __DIR__ . '/../src/partials/footer.php'; ?>
    <script src="assets/js/validation.js"></script>
    <script src="assets/js/admin-ui.js" defer></script>
</body>
</html>
