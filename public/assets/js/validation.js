/* public/assets/js/validation.js
 * Shared client-side validation for every CertiVault form.
 * Vanilla JS, no libraries. Declarative rules via data-validate, e.g.:
 *   data-validate="required|email"
 *   data-validate="required|min:8|max:72|strong"
 *   data-validate="required|match:#password"
 *   data-validate="required|number|range:2,18"
 *   data-validate="otp"  data-validate="certid"  data-validate="personname"
 *   data-validate="upload"  data-validate="daterange"  data-validate="after:#issue_date"
 * Client rules mirror the server-side validators.php exactly; the server
 * remains authoritative (it must, since JS can be disabled).
 */
(function () {
    'use strict';

    var FILE_OK_EXT = ['pdf', 'png', 'jpg', 'jpeg'];
    var FILE_OK_MIME = ['application/pdf', 'image/png', 'image/jpeg'];
    var FILE_MIN = 100;              // 100 bytes (mirrors v_upload())
    var FILE_MAX = 5 * 1024 * 1024;  // 5 MB
    // Smart Verify "optional upload" rule: WEBP is decodable by the QR
    // scanner client-side; the server still gives its own specific error
    // when it cannot process a type.
    var FILE_OK_EXT_OPTIONAL = ['pdf', 'png', 'jpg', 'jpeg', 'webp'];
    var SV_EITHER_OR_MSG = 'Enter a certificate ID or upload a certificate file.';

    // ── Rule implementations (mirror src/utils/validators.php) ────────
    function ruleRequired(v) {
        return v.trim() !== '' ? true : 'This field is required.';
    }
    // Mirrors v_email() in validators.php: 254 max, dot-atom local part
    // (no leading/trailing/double dots, max 64), domain of 2+ labels made
    // of letters/digits/hyphens (no edge hyphens, max 63 each), and a TLD
    // of 2+ letters (or an IDN xn-- label). IP literals are rejected.
    var EMAIL_LOCAL = /^[A-Za-z0-9!#$%&'*+\/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+\/=?^_`{|}~-]+)*$/;
    var EMAIL_LABEL = /^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;
    var EMAIL_TLD = /^([A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})$/;
    function ruleEmail(v) {
        var bad = 'Please provide a valid email address.';
        if (v.length > 254) return 'Email address must not exceed 254 characters.';
        var at = v.lastIndexOf('@');
        if (at < 1 || at === v.length - 1) return bad;
        var local = v.slice(0, at), domain = v.slice(at + 1);
        if (local.length > 64 || !EMAIL_LOCAL.test(local)) return bad;
        var labels = domain.split('.');
        if (labels.length < 2) return 'Please provide a valid email address (the domain needs a dot, e.g. example.com).';
        for (var i = 0; i < labels.length; i++) {
            if (!EMAIL_LABEL.test(labels[i])) return bad;
        }
        if (!EMAIL_TLD.test(labels[labels.length - 1])) return 'Please provide a valid email address (check the ending, e.g. .com or .in).';
        return true;
    }
    function ruleNumber(v) {
        return /^-?\d+$/.test(v.trim()) ? true : 'Value must be a whole number.';
    }
    function ruleStrong(v) {
        if (v.length < 8) return 'Password must be at least 8 characters long.';
        if (v.length > 72) return 'Password must not exceed 72 characters.';
        if (!/[A-Z]/.test(v)) return 'Password must contain at least one uppercase letter.';
        if (!/[a-z]/.test(v)) return 'Password must contain at least one lowercase letter.';
        if (!/\d/.test(v)) return 'Password must contain at least one digit.';
        if (!/[^A-Za-z0-9]/.test(v)) return 'Password must contain at least one special character.';
        return true;
    }
    function ruleOtp(v) {
        return /^\d{6}$/.test(v.trim()) ? true : 'Verification code must be exactly 6 digits.';
    }
    function ruleCertId(v) {
        v = v.trim();
        // Flexible rule (mirrors v_certificate_id_flexible without the DB
        // uniqueness check — the server is authoritative). The strict
        // CV-YYYY-NNNNNN shape is only a hint (placeholder text); loose
        // forms like "cv-2026-1" are normalized server-side.
        if (v.length < 3 || v.length > 40) return 'Certificate ID must be between 3 and 40 characters.';
        return /^[A-Za-z0-9\-_\/. ]+$/.test(v) ? true : 'Certificate ID may only contain letters, digits, spaces, and - _ / .';
    }
    function rulePersonName(v) {
        if (v.length < 2 || v.length > 100) return 'Name must be between 2 and 100 characters.';
        return /^[A-Za-zÀ-ÿ .'\-;]+$/.test(v) ? true : "Name may only contain letters, spaces, and the characters . ' - ;";
    }
    function ruleEnrollment(v) {
        if (!/^\d{5,20}$/.test(v.trim())) return 'Enrollment number must be 5-20 digits.';
        return true;
    }
    function ruleDateRange(v, input) {
        var d = new Date(v + 'T00:00:00');
        if (isNaN(d.getTime())) return 'Please provide a valid issue date.';
        var today = new Date(); today.setHours(0, 0, 0, 0);
        if (d > today) return 'Issue date cannot be in the future.';
        if (d < new Date(1950, 0, 1)) return 'Issue date cannot be before 1950.';
        var form = input.closest('form');
        var exp = form ? form.querySelector('[name="expiry_date"]') : null;
        if (exp && exp.value) {
            var e = new Date(exp.value + 'T00:00:00');
            if (!isNaN(e.getTime()) && e <= d) return 'Expiry date must be after the issue date.';
        }
        return true;
    }
    function ruleAfter(v, targetSel) {
        var t = document.querySelector(targetSel);
        if (!t || !t.value || !v) return true;
        var a = new Date(v + 'T00:00:00');
        var b = new Date(t.value + 'T00:00:00');
        if (isNaN(a.getTime())) return 'Please provide a valid date.';
        if (!isNaN(b.getTime()) && a <= b) return 'Expiry date must be after the issue date.';
        return true;
    }
    function ruleUpload(input) {
        var f = input.files && input.files[0];
        if (!f) return 'A certificate file is required.';
        var ext = (f.name.split('.').pop() || '').toLowerCase();
        if (FILE_OK_EXT.indexOf(ext) === -1) return 'Only PDF, PNG, and JPG files are allowed.';
        if (f.type && FILE_OK_MIME.indexOf(f.type) === -1) return 'File content does not match an allowed type (PDF, PNG, JPG).';
        if (f.size < FILE_MIN) return 'File appears to be empty or corrupted (minimum 100 bytes).';
        if (f.size > FILE_MAX) return 'File size exceeds the 5MB limit.';
        return true;
    }
    // Smart Verify only: no file chosen is NOT an error (either/or with the
    // ID input). A chosen file still gets type + size checks.
    function ruleUploadOptional(input) {
        var f = input.files && input.files[0];
        if (!f) return true;
        var ext = (f.name.split('.').pop() || '').toLowerCase();
        if (FILE_OK_EXT_OPTIONAL.indexOf(ext) === -1) return 'Only PDF, PNG, JPG, or WEBP files are allowed.';
        if (f.type && f.type !== 'application/pdf' && f.type !== 'image/png' && f.type !== 'image/jpeg' && f.type !== 'image/webp') {
            return 'File content does not match an allowed type (PDF, PNG, JPG, WEBP).';
        }
        if (f.size < FILE_MIN) return 'File appears to be empty or corrupted (minimum 100 bytes).';
        if (f.size > FILE_MAX) return 'File size exceeds the 5MB limit.';
        return true;
    }

    // ── Validate one input against its data-validate rules ────────────
    function validateInput(input) {
        if (!input.dataset.validate) return true;
        if (input.type === 'file') {
            var rulesStr = input.dataset.validate;
            var r0 = rulesStr.indexOf('upload_optional') !== -1
                ? ruleUploadOptional(input)
                : ruleUpload(input);
            setState(input, r0);
            return r0 === true;
        }
        var v = input.value;
        var rules = input.dataset.validate.split('|');
        var isNumber = rules.indexOf('number') !== -1;
        var firstError = null;
        var optional = rules.indexOf('required') === -1;

        for (var i = 0; i < rules.length; i++) {
            var rule = rules[i];
            var arg = null;
            var idx = rule.indexOf(':');
            if (idx !== -1) { arg = rule.substring(idx + 1); rule = rule.substring(0, idx); }

            // Skip all checks on empty optional fields
            if (optional && v.trim() === '' && rule !== 'required') continue;

            var result = true;
            switch (rule) {
                case 'required': result = ruleRequired(v); break;
                case 'email': result = ruleEmail(v.trim()); break;
                case 'json':
                    try {
                        var parsedJson = JSON.parse(v);
                        result = parsedJson && typeof parsedJson === 'object' && !Array.isArray(parsedJson)
                            ? true : 'Configuration must be a JSON object.';
                    } catch (jsonError) { result = 'Configuration must be valid JSON.'; }
                    break;
                case 'number': result = ruleNumber(v); break;
                case 'strong': result = ruleStrong(v); break;
                case 'otp': result = ruleOtp(v); break;
                case 'certid': result = ruleCertId(v); break;
                case 'personname': result = rulePersonName(v.trim()); break;
                case 'enrollment': result = ruleEnrollment(v); break;
                case 'min':
                    var mn = parseInt(arg, 10);
                    if (isNumber) {
                        if (ruleNumber(v) === true && parseInt(v, 10) < mn) result = 'Value must be at least ' + mn + '.';
                    } else if (v.length < mn) {
                        result = 'Must be at least ' + mn + ' characters.';
                    }
                    break;
                case 'max':
                    var mx = parseInt(arg, 10);
                    if (isNumber) {
                        if (ruleNumber(v) === true && parseInt(v, 10) > mx) result = 'Value must not exceed ' + mx + '.';
                    } else if (v.length > mx) {
                        result = 'Must not exceed ' + mx + ' characters.';
                    }
                    break;
                case 'range':
                    var parts = arg.split(',');
                    var num = Number(v);
                    if (v.trim() !== '' && !isNaN(num) && num >= +parts[0] && num <= +parts[1]) result = true;
                    else result = 'Must be between ' + parts[0] + ' and ' + parts[1] + '.';
                    break;
                case 'match':
                    var t = document.querySelector(arg);
                    result = (t && v === t.value) ? true : 'Passwords do not match.';
                    break;
                case 'daterange': result = ruleDateRange(v, input); break;
                case 'after': result = ruleAfter(v, arg); break;
            }
            if (result !== true) { firstError = result; break; }
        }
        setState(input, firstError === null ? true : firstError);
        return firstError === null;
    }

    function setState(input, result) {
        var group = input.closest('.form-group') || input.parentNode;
        var msg = group.querySelector('.field-error');
        if (result === true) {
            input.removeAttribute('aria-invalid');
            if (msg) msg.textContent = '';
            if (msg) msg.style.display = 'none';
        } else {
            input.setAttribute('aria-invalid', 'true');
            if (!msg) {
                msg = document.createElement('div');
                msg.className = 'field-error';
                msg.setAttribute('aria-live', 'polite');
                var anchor = input.closest('.pw-field') || input;
                anchor.parentNode.insertBefore(msg, anchor.nextSibling);
            }
            msg.textContent = result;
            msg.style.display = 'block';
        }
    }

    // ── Password strength meter + live rule checklist ─────────────────
    // Attached to every data-validate="...strong" field (registration,
    // activation, reset, change password). The checklist mirrors
    // v_password_strong() exactly; the bar is only a coarse hint. State is
    // exposed through classes / data-score (styled in style.css), never
    // inline style attributes. The show/hide eye button lives in ui.js.
    function strengthScore(v) {
        var s = 0;
        if (v.length >= 8) s++;
        if (v.length >= 12) s++;
        if (/[A-Z]/.test(v) && /[a-z]/.test(v)) s++;
        if (/\d/.test(v)) s++;
        if (/[^A-Za-z0-9]/.test(v)) s++;
        return s; // 0..5
    }
    var METER_LABELS = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Very strong'];
    var PW_RULES = [
        ['len', '8–72 characters', function (v) { return v.length >= 8 && v.length <= 72; }],
        ['upper', 'An uppercase letter (A–Z)', function (v) { return /[A-Z]/.test(v); }],
        ['lower', 'A lowercase letter (a–z)', function (v) { return /[a-z]/.test(v); }],
        ['digit', 'A digit (0–9)', function (v) { return /\d/.test(v); }],
        ['special', 'A symbol (e.g. !@#?)', function (v) { return /[^A-Za-z0-9]/.test(v); }]
    ];

    function attachMeter(input) {
        var meter = document.createElement('div');
        meter.className = 'pw-meter';
        var bar = document.createElement('div');
        bar.className = 'pw-meter-bar';
        var fill = document.createElement('div');
        fill.className = 'pw-meter-fill';
        fill.setAttribute('data-score', '0');
        var label = document.createElement('div');
        label.className = 'pw-meter-label';
        label.setAttribute('aria-live', 'polite');
        bar.appendChild(fill);
        meter.appendChild(bar);
        meter.appendChild(label);

        var list = document.createElement('ul');
        list.className = 'pw-rules';
        list.setAttribute('aria-label', 'Password requirements');
        var items = PW_RULES.map(function (r) {
            var li = document.createElement('li');
            li.setAttribute('data-rule', r[0]);
            li.textContent = r[1];
            list.appendChild(li);
            return li;
        });
        meter.appendChild(list);

        // Place after the ui.js wrapper (input + eye button) when present.
        var anchor = input.closest('.pw-field') || input;
        anchor.parentNode.insertBefore(meter, anchor.nextSibling);

        function update() {
            var v = input.value;
            var s = v ? strengthScore(v) : 0;
            fill.setAttribute('data-score', String(s));
            label.textContent = v ? 'Strength: ' + METER_LABELS[s] : '';
            PW_RULES.forEach(function (r, i) {
                var met = v !== '' && r[2](v);
                items[i].classList.toggle('met', met);
                items[i].setAttribute('aria-label', r[1] + (met ? ' — done' : ' — missing'));
            });
        }
        input.addEventListener('input', update);
        update();
    }

    // ── Smart Verify either/or: at least one of ID / file must exist ──
    function ensureFormMessage(form) {
        var msg = form.parentNode.querySelector('[data-form-level-error]');
        if (!msg) {
            msg = document.createElement('p');
            msg.setAttribute('data-form-level-error', '1');
            msg.className = 'field-error';
            msg.setAttribute('role', 'alert');
            msg.setAttribute('aria-live', 'assertive');
            msg.style.marginTop = '8px';
            msg.style.width = '100%';
            form.parentNode.insertBefore(msg, form.nextSibling);
        }
        return msg;
    }
    function setFormMessage(form, text) {
        var msg = ensureFormMessage(form);
        if (text) {
            msg.textContent = text;
            msg.style.display = 'block';
        } else {
            msg.textContent = '';
            msg.style.display = 'none';
        }
    }
    function attachEitherOr(form) {
        var id = form.querySelector('[name="smart_id"]');
        var file = form.querySelector('input[type="file"][name="smart_file"]');
        if (!id || (form.id !== 'smartVerifyForm' && form.id !== 'smartVerifyFormIndex')) return;

        function provided() {
            var hasId = id && id.value.trim() !== '';
            var hasFile = file && file.files && file.files.length > 0;
            var hash = form.querySelector('[name="smart_hash"]');
            return hasId || hasFile || !!(hash && hash.value);
        }
        // Clear the form-level message as soon as either field has a value.
        function clearIfProvided() {
            if (provided()) setFormMessage(form, '');
        }
        id.addEventListener('input', clearIfProvided);
        if (file) file.addEventListener('change', clearIfProvided);

        // Capture phase: runs before the shared per-field submit handler so
        // a blocked request also skips the "disable submit button" step.
        form.addEventListener('submit', function (e) {
            form.dataset.svBlocked = '';
            if (!provided()) {
                // Block silently at field level: no red errors on the
                // empty inputs — one shared message under the form.
                form.dataset.svBlocked = '1';
                e.preventDefault();
                setFormMessage(form, SV_EITHER_OR_MSG);
            }
        }, true);
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('input[data-validate*="strong"]').forEach(attachMeter);

        document.querySelectorAll('[data-validate]').forEach(function (input) {
            input.addEventListener('blur', function () { validateInput(input); });
            input.addEventListener('input', function () {
                // Re-validate on input once an error is shown, for quick feedback
                if (input.getAttribute('aria-invalid') === 'true') validateInput(input);
            });
        });

        document.querySelectorAll('form').forEach(function (form) {
            attachEitherOr(form);
            form.setAttribute('novalidate', 'novalidate');
            form.addEventListener('submit', function (e) {
                // Either/or already blocked this submit — its own messages
                // are shown; skip re-validation and the button-disable step.
                if (form.dataset.svBlocked === '1') {
                    form.dataset.svBlocked = '';
                    return;
                }
                // A secondary submit button marked formnovalidate (e.g.
                // "Resend code" on reset_password.php) only needs the
                // fields the server re-checks itself — skip the rules.
                if (e.submitter && e.submitter.hasAttribute('formnovalidate')) {
                    return;
                }
                var ok = true;
                form.querySelectorAll('[data-validate]').forEach(function (input) {
                    if (!validateInput(input)) ok = false;
                });
                if (!ok) {
                    e.preventDefault();
                    var first = form.querySelector('[aria-invalid="true"]');
                    if (first) first.focus();
                    return;
                }
                // Valid submit — disable the submit button to stop double posts
                form.querySelectorAll('button[type="submit"], input[type="submit"]').forEach(function (btn) {
                    btn.disabled = true;
                });
            });
        });
    });
})();
