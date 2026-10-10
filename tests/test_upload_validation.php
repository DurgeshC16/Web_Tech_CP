<?php
// tests/test_upload_validation.php — v_upload() against mocked $_FILES
// arrays, one case per PHP upload error code plus the guard clauses.
// NOTE: is_uploaded_file() is always false under CLI (nothing comes from
// an HTTP POST), so the UPLOAD_ERR_OK branch can only reach the
// 'temporary file missing' guard here. The full happy path is covered by
// the live multipart tests in docs/TEST_PLAN.md.
// Run: php tests/test_upload_validation.php
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/utils/validators.php';

t_check('missing file => required', v_upload(null) === 'A certificate file is required.');
t_check('no error key => required', v_upload(['name' => 'a.pdf']) === 'A certificate file is required.');
t_check('INI_SIZE mapped', str_contains(v_upload(['error' => UPLOAD_ERR_INI_SIZE]), 'upload_max_filesize'));
t_check('FORM_SIZE mapped', str_contains(v_upload(['error' => UPLOAD_ERR_FORM_SIZE]), 'MAX_FILE_SIZE'));
t_check('PARTIAL mapped', str_contains(v_upload(['error' => UPLOAD_ERR_PARTIAL]), 'partially'));
t_check('NO_FILE => required', v_upload(['error' => UPLOAD_ERR_NO_FILE]) === 'A certificate file is required.');
t_check('NO_TMP_DIR mapped', str_contains(v_upload(['error' => UPLOAD_ERR_NO_TMP_DIR]), 'temporary upload folder'));
t_check('CANT_WRITE mapped', str_contains(v_upload(['error' => UPLOAD_ERR_CANT_WRITE]), 'failed to write'));
t_check('EXTENSION mapped', str_contains(v_upload(['error' => UPLOAD_ERR_EXTENSION]), 'blocked by a server extension'));
t_check('unknown code mapped', str_contains(v_upload(['error' => 999]), 'unknown upload error'));
t_check(
    'OK + CLI tmp => guard message (is_uploaded_file is HTTP-only)',
    v_upload(['error' => UPLOAD_ERR_OK, 'name' => 'CERT.PDF', 'tmp_name' => '/tmp/x', 'size' => 500])
        === 'The file upload failed (temporary file missing). Please try again.'
);
t_check(
    'size/min/type branches unreachable in CLI (guard fires first)',
    v_upload(['error' => UPLOAD_ERR_OK, 'name' => 'evil.exe', 'tmp_name' => '/tmp/x', 'size' => 1]) !== true
);

exit(t_summary('test_upload_validation') ? 0 : 1);
