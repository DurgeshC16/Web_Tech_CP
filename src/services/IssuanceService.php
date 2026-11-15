<?php
// src/services/IssuanceService.php
// ─────────────────────────────────────────────────────────────────────
// The certificate issuance pipeline, shared by issue_certificate.php
// (single, uploaded file) and bulk_issue.php (CSV, generated PDFs) so both
// paths are cryptographically identical:
//
//   resolveStudent()  verified student → id; otherwise create/keep a pending
//                     account, email an activation code, and STOP (gate)
//   issue()           one DB transaction:
//                       certificate ID (custom or next CV-YYYY-NNNNNN)
//                       → QR token + QR image
//                       → certificate file (moved upload or generated PDF)
//                       → canonical SHA-256 → RSA signature (active key,
//                         decrypted + key-pair checked) → INSERT
//                       → transparency-log leaf
//                     Any failure rolls back and deletes the file + QR.
// ─────────────────────────────────────────────────────────────────────

require_once __DIR__ . '/../utils/helpers.php';
require_once __DIR__ . '/../utils/validators.php';
require_once __DIR__ . '/CryptoService.php';
require_once __DIR__ . '/QRService.php';
require_once __DIR__ . '/TransparencyLogService.php';

class IssuanceService
{
    /**
     * @return array{status:'ok', student_id:int}
     *       | array{status:'pending_activation', user_id:int, message:string}
     */
    public static function resolveStudent($db, string $email, string $fullName): array
    {
        $db->beginTransaction();
        try {
            $stmt = $db->prepare('SELECT s.id, u.id AS user_id, u.is_verified FROM users u JOIN students s ON u.id = s.user_id WHERE u.email = :email LIMIT 1');
            $stmt->execute(['email' => $email]);
            $row = $stmt->fetch();
            if ($row && (int)$row['is_verified'] === 1) {
                $db->commit();
                return ['status' => 'ok', 'student_id' => (int)$row['id']];
            }
            if (!$row) {
                // Create an inline (unverified) student account.
                $db->prepare('INSERT INTO users (email, password_hash, role) VALUES (:email, :hash, "student")')
                   ->execute(['email' => $email, 'hash' => password_hash(bin2hex(random_bytes(8)), PASSWORD_BCRYPT)]);
                $userId = (int)$db->lastInsertId();
                $db->prepare('INSERT INTO students (user_id, full_name) VALUES (:user_id, :full_name)')
                   ->execute(['user_id' => $userId, 'full_name' => $fullName]);
            } else {
                $userId = (int)$row['user_id'];
            }
            $db->commit(); // persist the pending account; issuance stops here
        } catch (Throwable $e) {
            if ($db->inTransaction()) { $db->rollBack(); }
            throw $e;
        }

        $otp = create_otp($db, $userId, 'activation', BASE_URL . '/activate_account.php?user_id=' . $userId);
        $base = 'This student has not activated their account yet. ';
        $message = match ($otp) {
            'sent' => $base . 'An activation code was sent to ' . mask_email($email) . ' — issue the certificate after the student activates.',
            'cooldown' => $base . 'An activation code was sent recently — ask the student to check their email, then issue the certificate after activation.',
            'limit' => $base . 'Too many activation codes were requested. Please try again later, after the student activates.',
            'smtp_not_configured' => $base . smtp_not_configured_message(),
            default => $base . "We couldn't send the activation email right now. Please try again in a minute.",
        };
        return ['status' => 'pending_activation', 'user_id' => $userId, 'message' => $message];
    }

    /**
     * Tell the student their certificate was issued (verify link included).
     * Best effort: a delivery failure is logged and never undoes issuance.
     */
    public static function notifyStudent(string $email, string $certId, string $title, string $institution, string $verifyUrl): bool
    {
        try {
            return send_notification_email(
                $email,
                'Your certificate "' . $title . '" has been issued',
                'Your certificate is ready',
                $institution . ' issued you the certificate "' . $title . '" (ID ' . $certId . '). '
                    . 'Anyone can check it at ' . $verifyUrl . ' — sign in to CertiVault to download it, share a link, '
                    . 'or export a signed credential.',
                'You received this email because ' . $institution . ' issued you a certificate on CertiVault.'
            );
        } catch (Throwable $e) {
            error_log('[CertiVault] Issuance notification failed for ' . $certId . ': ' . get_class($e));
            return false;
        }
    }

    /**
     * Issue one certificate. $placeFile is called INSIDE the transaction as
     *   fn(string $certId, string $qrToken, string $verifyUrl, string $qrPath, string $destination): void
     * and must write the certificate file to $destination (move the upload,
     * or render a PDF that embeds the QR at $qrPath).
     *
     * @param array{title:string, issue_date:string, expiry_date:?string, custom_id:?string} $f
     * @return array{certificate_id:string, qr_token:string, file:string, verify_url:string}
     * @throws Exception (message safe to show) / PDOException (23000 = duplicate ID)
     */
    public static function issue($db, int $institutionId, int $studentId, array $f, string $ext, callable $placeFile): array
    {
        $destination = null;
        $qrPath = null;
        $db->beginTransaction();
        try {
            // 1. Certificate ID: custom when given (re-checked inside the
            //    transaction; the UNIQUE index is the final backstop), else
            //    the next CV-YYYY-NNNNNN under a row lock.
            $customId = trim((string)($f['custom_id'] ?? ''));
            if ($customId !== '') {
                if (($e = v_certificate_id_flexible($customId, $db)) !== true) {
                    throw new Exception($e);
                }
                $certId = $customId;
            } else {
                $year = date('Y');
                $stmt = $db->prepare('SELECT certificate_id FROM certificates WHERE certificate_id LIKE :prefix ORDER BY id DESC LIMIT 1 FOR UPDATE');
                $stmt->execute(['prefix' => "CV-$year-%"]);
                $last = $stmt->fetchColumn();
                $num = $last ? ((int)substr((string)$last, strrpos((string)$last, '-') + 1)) + 1 : 1;
                $certId = sprintf('CV-%s-%06d', $year, $num);
            }

            // 2. Storage locations (outside the web root, unguessable names).
            $uploadDir = __DIR__ . '/../../private_data/uploads/';
            $qrDir = __DIR__ . '/../../public/qrcodes/';
            foreach ([$uploadDir => 'Upload', $qrDir => 'QR'] as $dir => $label) {
                if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
                    throw new Exception("$label directory is not available. Please contact the administrator.");
                }
                if (!is_writable($dir)) {
                    throw new Exception("$label directory is not writable. Please contact the administrator.");
                }
            }
            $filename = sanitize_filename($certId) . '_' . bin2hex(random_bytes(16)) . '.' . strtolower($ext);
            $destination = $uploadDir . $filename;

            // 3. QR token + image (the QR encodes only the verify URL).
            $qrToken = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            $verifyUrl = BASE_URL . '/verify.php?token=' . $qrToken;
            $qrPath = $qrDir . $qrToken . '.png';
            QRService::generateQRCode($verifyUrl, $qrPath);

            // 4. The certificate file itself.
            $placeFile($certId, $qrToken, $verifyUrl, $qrPath, $destination);
            if (!is_file($destination) || filesize($destination) === 0) {
                throw new Exception('The certificate file could not be stored.');
            }

            // 5. Canonical digest over fields + file.
            $expiry = ($f['expiry_date'] ?? '') !== '' ? $f['expiry_date'] : null;
            $hash = CryptoService::computeCertificateHash([
                'certificate_id' => $certId,
                'institution_id' => $institutionId,
                'student_id' => $studentId,
                'title' => $f['title'],
                'issue_date' => $f['issue_date'],
                'expiry_date' => $expiry,
            ], $destination);

            // 6. Sign with the institution's active key.
            $k = $db->prepare('SELECT key_id, public_key, encrypted_private_key FROM institution_keys WHERE institution_id = :id AND status = "active" ORDER BY key_id DESC LIMIT 1 FOR UPDATE');
            $k->execute(['id' => $institutionId]);
            $key = $k->fetch();
            if (!$key) {
                throw new Exception('This institution has no active signing key. Please contact the platform administrator.');
            }
            try {
                $privateKey = CryptoService::decryptPrivateKey($key['encrypted_private_key'] ?? '');
                if (!empty($key['public_key']) && !CryptoService::verifyKeyPair($privateKey, $key['public_key'])) {
                    throw new Exception('Stored private key does not match the stored public key.');
                }
                while (openssl_error_string()) {}
                $signature = CryptoService::signCertificateHash($hash, $privateKey);
            } catch (Exception $keyException) {
                error_log('[CertiVault] Institution ' . $institutionId . ' signing key error: ' . $keyException->getMessage());
                throw new Exception('This institution\'s signing key is not available. Please contact the platform administrator.');
            }

            // 7. Persist + transparency log.
            $db->prepare('INSERT INTO certificates (certificate_id, institution_id, key_id, student_id, title, issue_date, expiry_date, file_path, status, version, qr_token, sha256_hash, file_sha256, digital_signature)
                          VALUES (:cid, :iid, :key_id, :sid, :title, :issue, :expiry, :path, "active", 1, :qr, :hash, :fhash, :sig)')
               ->execute([
                   'cid' => $certId, 'iid' => $institutionId, 'key_id' => (int)$key['key_id'], 'sid' => $studentId,
                   'title' => $f['title'], 'issue' => $f['issue_date'], 'expiry' => $expiry, 'path' => $filename,
                   'qr' => $qrToken, 'hash' => $hash, 'fhash' => hash_file('sha256', $destination), 'sig' => $signature,
               ]);
            TransparencyLogService::append($db, $certId, 'ISSUE');
            $db->commit();
            return ['certificate_id' => $certId, 'qr_token' => $qrToken, 'file' => $filename, 'verify_url' => $verifyUrl];
        } catch (Throwable $e) {
            if ($db->inTransaction()) { $db->rollBack(); }
            if ($destination && is_file($destination)) { @unlink($destination); }
            if ($qrPath && is_file($qrPath)) { @unlink($qrPath); }
            throw $e;
        }
    }
}
