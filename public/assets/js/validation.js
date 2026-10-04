/* public/assets/js/validation.js
 * Shared client-side validation for every CertiVault form.
 * Vanilla JS, no libraries. Declarative rules via data-validate, e.g.:
 *   data-validate="required|email"
 *   data-validate="required|min:8|max:72|strong"
 *   data-validate="required|match:#password"
 *   data-validate="number|min:5|max:20"
 *   data-validate="otp"  data-validate="certid"  data-validate="personname"
 *   data-validate="upload"  data-validate="daterange"  data-validate="after:#issue_date"
 * Client rules mirror the server-side validators.php exactly; the server
 * remains authoritative (it must, since JS can be disabled).
 */
(function () {
    'use strict';

    var FILE_OK_EXT = ['pdf', 'png', 'jpg', 'jpeg'];
    var FILE_OK_MIME = ['application/pdf', 'image/png', 'image/jpeg'];
    var FILE_MIN = 1024;             // 1 KB
    var FILE_MAX = 5 * 1024 * 1024;  // 5 MB

    // ── Rule implementations (mirror src/utils/validators.php) ────────
    function ruleRequired(v) {
        return v.trim() !== '' ? true : 'This field is required.';
    }
    function ruleEmail(v) {
        if (v.length > 254) return 'Email address must not exceed 254 characters.';
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? true : 'Please provide a valid email address.';
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
        return /^CV-\d{4}-\d{6}$/.test(v.trim()) ? true : 'Certificate ID must match the format CV-YYYY-NNNNNN.';
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
        if (f.size < FILE_MIN) return 'File appears to be empty or corrupted (minimum 1 KB).';
        if (f.size > FILE_MAX) return 'File size exceeds the 5MB limit.';
        return true;
    }

    // ── Validate one input against its data-validate rules ────────────
    function validateInput(input) {
        if (!input.dataset.validate) return true;
        if (input.type === 'file') {
            var r0 = ruleUpload(input);
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
                    if (!isNaN(v) && (v + 0) >= +parts[0] && (v + 0) <= +parts[1]) result = true;
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
                input.parentNode.insertBefore(msg, input.nextSibling);
            }
            msg.textContent = result;
            msg.style.display = 'block';
        }
    }

    // ── Password strength meter ───────────────────────────────────────
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

    function attachMeter(input) {
        var group = input.closest('.form-group') || input.parentNode;
        var meter = document.createElement('div');
        meter.className = 'pw-meter';
        var bar = document.createElement('div');
        bar.className = 'pw-meter-bar';
        var fill = document.createElement('div');
        fill.className = 'pw-meter-fill';
        var label = document.createElement('div');
        label.className = 'pw-meter-label';
        bar.appendChild(fill);
        meter.appendChild(bar);
        meter.appendChild(label);
        input.parentNode.insertBefore(meter, input.nextSibling);
        input.addEventListener('input', function () {
            var s = input.value ? strengthScore(input.value) : 0;
            fill.style.width = (s / 5 * 100) + '%';
            fill.style.background = ['#B3261E', '#B3261E', '#C2780B', '#C2780B', '#1F7A4D', '#1F7A4D'][s];
            label.textContent = input.value ? 'Strength: ' + METER_LABELS[s] : '';
        });
    }

    // ── Show/hide password toggle ─────────────────────────────────────
    function attachToggle(input) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'pw-toggle';
        btn.textContent = 'Show';
        btn.setAttribute('aria-label', 'Show password');
        btn.addEventListener('click', function () {
            var show = input.type === 'password';
            input.type = show ? 'text' : 'password';
            btn.textContent = show ? 'Hide' : 'Show';
            btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
        });
        var ref = input.nextSibling;
        if (ref && ref.nodeType === 1 && ref.classList.contains('pw-meter')) ref = ref.nextSibling;
        input.parentNode.insertBefore(btn, ref);
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('input[data-validate*="strong"]').forEach(attachMeter);
        document.querySelectorAll('input[type="password"]').forEach(function (input) { attachToggle(input); });

        document.querySelectorAll('[data-validate]').forEach(function (input) {
            input.addEventListener('blur', function () { validateInput(input); });
            input.addEventListener('input', function () {
                // Re-validate on input once an error is shown, for quick feedback
                if (input.getAttribute('aria-invalid') === 'true') validateInput(input);
            });
        });

        document.querySelectorAll('form').forEach(function (form) {
            form.setAttribute('novalidate', 'novalidate');
            form.addEventListener('submit', function (e) {
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
