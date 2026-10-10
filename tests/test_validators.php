<?php
// tests/test_validators.php — cases for every validator in
// src/utils/validators.php. Pure functions, no database needed.
// Run: php tests/test_validators.php
require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../src/utils/validators.php';

// ── v_required ──
t_check('required: text ok', v_required('hello', 'Name') === true);
t_check('required: empty rejected', v_required('', 'Name') !== true);
t_check('required: spaces rejected', v_required('   ', 'Name') !== true);
t_check('required: null rejected', v_required(null, 'Name') !== true);

// ── v_range ──
t_check('range: inside ok', v_range('5', 2, 18, 'CAPTCHA answer') === true);
t_check('range: lower bound ok', v_range('2', 2, 18, 'CAPTCHA answer') === true);
t_check('range: below rejected', v_range('1', 2, 18, 'CAPTCHA answer') !== true);
t_check('range: above rejected', v_range('19', 2, 18, 'CAPTCHA answer') !== true);
t_check('range: non-numeric rejected', v_range('abc', 2, 18, 'CAPTCHA answer') !== true);

// ── v_compare ──
t_check('compare: equal ok', v_compare('Secret1!x', 'Secret1!x', 'Passwords') === true);
t_check('compare: mismatch rejected', v_compare('a', 'b', 'Passwords') !== true);

// ── v_email ──
t_check('email: valid ok', v_email('student@example.com') === true);
t_check('email: missing @ rejected', v_email('not-an-email') !== true);
t_check('email: 255 chars rejected', v_email(str_repeat('a', 243) . '@example.com') !== true);

// ── v_number ──
t_check('number: digits ok', v_number('12345', 0) === true);
t_check('number: negative rejected by min 0', v_number('-1234', 0) !== true);
t_check('number: float rejected (integer-only)', v_number('12.5') !== true);
t_check('number: alpha rejected', v_number('12AB') !== true);

// ── v_certificate_id ──
t_check('certid: valid ok', v_certificate_id('CV-2026-000001') === true);
t_check('certid: bad format rejected', v_certificate_id('XX-123') !== true);
t_check('certid: empty rejected', v_certificate_id('') !== true);

// ── v_person_name ──
t_check('personname: valid ok', v_person_name("O'Brien Tester") === true);
t_check('personname: digits rejected', v_person_name('John123') !== true);
t_check('personname: too short rejected', v_person_name('J') !== true);

// ── v_password_strong ──
t_check('strong: valid ok', v_password_strong('Str0ng!Pass') === true);
t_check('strong: short rejected', v_password_strong('Ab1!') !== true);
t_check('strong: no upper rejected', v_password_strong('str0ng!pass') !== true);
t_check('strong: no digit rejected', v_password_strong('Strong!Pass') !== true);
t_check('strong: no special rejected', v_password_strong('Str0ngPass1') !== true);

// ── v_date_range ──
t_check('daterange: past issue ok', v_date_range('2024-05-01', null) === true);
t_check('daterange: future issue rejected', v_date_range('2999-01-01', null) !== true);
t_check('daterange: pre-1950 rejected', v_date_range('1940-01-01', null) !== true);
t_check('daterange: expiry after issue ok', v_date_range('2024-05-01', '2026-05-01') === true);
t_check('daterange: expiry before issue rejected', v_date_range('2024-05-01', '2024-04-01') !== true);

exit(t_summary('test_validators') ? 0 : 1);
