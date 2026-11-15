// tests/test_pages_browser.mjs
// Whole-app browser audit under the production Content-Security-Policy.
//
// Starts `php -S` against the isolated test DB, seeds the browser fixtures
// (tests/seed_browser_fixtures.php), logs in through the REAL login form
// (solving the offline arithmetic CAPTCHA) as an institution admin and as a
// student — each in its own isolated browser context — and loads every page.
// For every page it fails on: a CSP violation, an uncaught exception, or an
// unexpected redirect (e.g. back to login).
//
// It also proves the policy is enforced (an injected inline <script> must be
// blocked) and exercises the behaviours that moved from inline scripts into
// assets/js/ui.js: data-confirm, file-name preview, select-on-click, copy
// toast, and data-history-back.
//
// No npm deps (Node >= 21 global WebSocket). Exit 0 = pass or SKIP.
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CHROME = [process.env.CV_CHROME,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
].filter(Boolean).find((p) => existsSync(p));
const PHP = process.env.CV_PHP || (existsSync('C:/xampp/php/php.exe') ? 'C:/xampp/php/php.exe' : 'php');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
if (!CHROME) { console.log('SKIP pages-browser: no Chrome/Edge found.'); process.exit(0); }

const phpEnv = { ...process.env };
if (process.platform === 'win32' && !phpEnv.OPENSSL_CONF && existsSync('C:/xampp/apache/conf/openssl.cnf')) {
  phpEnv.OPENSSL_CONF = 'C:\\xampp\\apache\\conf\\openssl.cnf';
}
const phpRun = (args) => spawnSync(PHP, args, { cwd: ROOT, env: phpEnv, encoding: 'utf8' });

async function freePort(start) {
  for (let p = start; p < start + 200; p++) {
    const free = await new Promise((res) => {
      const s = net.createServer(); s.once('error', () => res(false));
      s.listen(p, '127.0.0.1', () => s.close(() => res(true)));
    });
    if (free) return p;
  }
  throw new Error('no free port');
}

// ── Minimal CDP client ──────────────────────────────────────────────────
class CDP {
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map(); this.handlers = [];
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id); this.pending.delete(msg.id);
        msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
      } else if (msg.method) { this.handlers.forEach((h) => h(msg)); }
    });
  }
  static async connect(url) {
    const ws = new WebSocket(url);
    await new Promise((res, rej) => { ws.addEventListener('open', res, { once: true }); ws.addEventListener('error', rej, { once: true }); });
    return new CDP(ws);
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id; const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject }); this.ws.send(JSON.stringify(payload));
      setTimeout(() => { if (this.pending.has(id)) { this.pending.delete(id); reject(new Error('timeout: ' + method)); } }, 30000);
    });
  }
  once(method, sessionId, timeoutMs = 15000) {
    return new Promise((resolve) => {
      const h = (m) => { if (m.method === method && (!sessionId || m.sessionId === sessionId)) { done(m.params); } };
      const done = (v) => { clearTimeout(t); this.handlers = this.handlers.filter((x) => x !== h); resolve(v); };
      const t = setTimeout(() => done(null), timeoutMs);
      this.handlers.push(h);
    });
  }
}

let pass = 0, fail = 0;
const ok = (name, cond, extra = '') => {
  if (cond) { pass++; console.log(`PASS ${name}`); } else { fail++; console.log(`FAIL ${name}${extra ? ' — ' + extra : ''}`); }
};

async function main() {
  // 1) Fixtures + server
  const seed = phpRun(['tests/seed_browser_fixtures.php']);
  if (seed.status !== 0) { console.log('SKIP pages-browser: fixture seeding failed\n' + seed.stdout + seed.stderr); process.exit(0); }
  const fx = Object.fromEntries((seed.stdout.match(/^[A-Z_]+=.*$/gm) || []).map((l) => l.split(/=(.*)/s).slice(0, 2)));
  phpRun(['tests/support/ui_db.php', 'reset-limiter']);

  const port = await freePort(Number(process.env.CV_PAGES_PORT || 8161));
  const BASE = `http://127.0.0.1:${port}`;
  const server = spawn(PHP, ['-S', `127.0.0.1:${port}`, '-t', 'public'], {
    cwd: ROOT, stdio: 'ignore',
    env: { ...phpEnv, CV_DB_NAME: process.env.CV_TEST_DB || 'certivault_test', CV_MAIL_TRANSPORT: 'file', CV_ENV: 'development', CV_BASE_URL: BASE },
  });
  let up = false;
  for (let i = 0; i < 80 && !up; i++) { try { up = (await fetch(`${BASE}/index.php`)).ok; } catch { /* starting */ } if (!up) await sleep(150); }
  if (!up) { console.log('SKIP pages-browser: php -S did not start'); server.kill(); process.exit(0); }

  // 2) Chrome
  const cdpPort = await freePort(Number(process.env.CV_CDP_PORT || 9351));
  const userDir = mkdtempSync(join(tmpdir(), 'cv-pages-chrome-'));
  const chrome = spawn(CHROME, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--mute-audio', ...(process.env.CI ? ['--no-sandbox'] : []), `--remote-debugging-port=${cdpPort}`, `--user-data-dir=${userDir}`, 'about:blank'], { stdio: 'ignore' });
  let wsUrl = null;
  for (let i = 0; i < 100 && !wsUrl; i++) {
    try { const r = await fetch(`http://127.0.0.1:${cdpPort}/json/version`); if (r.ok) wsUrl = (await r.json()).webSocketDebuggerUrl; } catch { /* starting */ }
    if (!wsUrl) await sleep(150);
  }
  if (!wsUrl) { console.log('SKIP pages-browser: DevTools did not start'); chrome.kill(); server.kill(); process.exit(0); }
  const cdp = await CDP.connect(wsUrl);

  // Problems per session (CSP violations, exceptions).
  const problems = new Map();
  cdp.handlers.push((m) => {
    if (!m.sessionId) return;
    const list = problems.get(m.sessionId) || [];
    if (m.method === 'Runtime.exceptionThrown') list.push('exception: ' + (m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text));
    if (m.method === 'Log.entryAdded' && /Content Security Policy|Refused to/i.test(m.params.entry.text || '')) list.push('csp: ' + m.params.entry.text);
    if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') list.push('console.error: ' + JSON.stringify(m.params.args.map((a) => a.value ?? a.description)));
    problems.set(m.sessionId, list);
  });

  async function open(contextId) {
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank', browserContextId: contextId });
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
    for (const d of ['Page', 'Runtime', 'Log', 'DOM']) await cdp.send(`${d}.enable`, {}, sessionId);
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false }, sessionId);
    return { targetId, sessionId };
  }
  async function go(page, url) {
    const loaded = cdp.once('Page.loadEventFired', page.sessionId);
    await cdp.send('Page.navigate', { url }, page.sessionId);
    await loaded; await sleep(300);
  }
  const ev = async (page, expr) => {
    const r = await cdp.send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true }, page.sessionId);
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text);
    return r.result.value;
  };
  async function login(page, email, password) {
    await go(page, `${BASE}/login.php`);
    const loaded = cdp.once('Page.loadEventFired', page.sessionId);
    await ev(page, `(() => {
      const q = (document.querySelector('.captcha-chip') || {}).textContent || '';
      const m = q.match(/(\\d+)\\s*\\+\\s*(\\d+)/);
      document.querySelector('input[name=email]').value = ${JSON.stringify(email)};
      document.querySelector('input[name=password]').value = ${JSON.stringify(password)};
      const cap = document.querySelector('input[name=captcha_answer]'); if (cap && m) cap.value = String(+m[1] + +m[2]);
      document.querySelector('input[name=email]').form.querySelector('button[type=submit]').click();
    })()`);
    await loaded; await sleep(400);
    return await ev(page, 'location.pathname');
  }
  async function audit(page, path, expectPath = path.split('?')[0]) {
    problems.set(page.sessionId, []);
    await go(page, BASE + path);
    const landed = await ev(page, 'location.pathname');
    const issues = problems.get(page.sessionId) || [];
    ok(`page ${path}: loads under CSP with no violations/exceptions`, landed === expectPath && issues.length === 0,
      landed !== expectPath ? `landed on ${landed}` : issues.slice(0, 2).join(' | '));
  }

  try {
    // ── Public pages ─────────────────────────────────────────────────
    const anon = await open((await cdp.send('Target.createBrowserContext')).browserContextId);
    for (const p of ['/index.php', '/login.php', '/verify.php', '/register_student.php', '/register_institution.php',
      '/forgot_password.php', '/institutions.php', `/verify.php?token=${fx.QR_TOKEN}`, `/verify.php?certificate_id=${encodeURIComponent(fx.CERT_ID)}`]) {
      await audit(anon, p);
    }

    // CSP is really enforced: an injected inline script must not run.
    problems.set(anon.sessionId, []);
    await go(anon, `${BASE}/index.php`);
    const ran = await ev(anon, `(() => { const s = document.createElement('script'); s.textContent = 'window.__inlineRan = true'; document.body.appendChild(s); return new Promise((r) => setTimeout(() => r(!!window.__inlineRan), 300)); })()`);
    ok('CSP blocks an injected inline <script>', ran === false);
    ok('CSP violation was reported for the injected script', (problems.get(anon.sessionId) || []).some((x) => x.startsWith('csp:')));
    const hdr = await (await fetch(`${BASE}/index.php`)).headers.get('content-security-policy');
    ok("CSP header: script-src 'self' without 'unsafe-inline'", /script-src 'self'[^;]*;/.test(hdr) && !/script-src[^;]*unsafe-inline/.test(hdr), hdr);

    // data-confirm (ui.js): dismissing the dialog cancels the submit.
    await go(anon, `${BASE}/index.php`);
    const dialog = cdp.once('Page.javascriptDialogOpening', anon.sessionId, 5000);
    await ev(anon, `(() => { const f = document.createElement('form'); f.method = 'get'; f.action = 'login.php';
      f.setAttribute('data-confirm', 'Proceed?'); const b = document.createElement('button'); b.type = 'submit'; f.appendChild(b);
      document.body.appendChild(f); setTimeout(() => b.click(), 0); return true; })()`);
    const d = await dialog;
    if (d) await cdp.send('Page.handleJavaScriptDialog', { accept: false }, anon.sessionId);
    await sleep(500);
    ok('ui.js: data-confirm shows the question', d && d.message === 'Proceed?', JSON.stringify(d));
    ok('ui.js: cancelling data-confirm keeps the page', (await ev(anon, 'location.pathname')) === '/index.php');

    // ── Zero-trust credential verifier (Web Crypto in the browser) ───
    await audit(anon, '/offline_verify.php');
    const cred = await ev(anon, `fetch('credential.php?certificate_id=' + encodeURIComponent(${JSON.stringify(fx.CERT_ID)})).then((r) => r.json())`);
    ok('credential.php returns a credential for the fixture', cred && cred.format === 'certivault-credential-v1', JSON.stringify(cred).slice(0, 120));
    const states = (r) => Object.fromEntries(r.checks.map((c) => [c.id, c.state]));
    const genuine = await ev(anon, `CertiVaultCredential.verify(${JSON.stringify(cred)}, { directory: true }).then((r) => ({ checks: r.checks, overall: CertiVaultCredential.overall(r.checks).cls }))`);
    const g = states(genuine);
    ok('browser: genuine credential — digest, signature, fingerprint pass',
      g.format === 'pass' && g.digest === 'pass' && g.signature === 'pass' && g.fingerprint === 'pass', JSON.stringify(g));
    ok('browser: key matches the published key directory', g.directory === 'pass', JSON.stringify(genuine.checks.find((c) => c.id === 'directory')));
    ok('browser: live status check = VALID', g.status === 'pass');
    ok('browser: overall verdict authentic', genuine.overall === 'pass');
    const fpSame = await ev(anon, `CertiVaultCredential.fingerprint(${JSON.stringify(cred.proof.public_key_pem)})`);
    ok('browser fingerprint algorithm == server fingerprint', fpSame === cred.proof.key_fingerprint_sha256, fpSame);

    const tampered = await ev(anon, `(() => { const c = ${JSON.stringify(cred)}; c.certificate.title = 'Forged Title';
      return CertiVaultCredential.verify(c, { directory: false }).then((r) => ({ checks: r.checks, overall: CertiVaultCredential.overall(r.checks).cls })); })()`);
    ok('browser: edited title -> digest fails, overall not authentic', states(tampered).digest === 'fail' && tampered.overall === 'fail');

    // Attacker re-signs with a fresh Web Crypto key and embeds it.
    const attacker = await ev(anon, `(async () => {
      const c = ${JSON.stringify(cred)}; c.certificate.title = 'Forged Title';
      const enc = new TextEncoder(); const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
      const can = [c.certificate.certificate_id, c.issuer.institution_id, c.subject.student_id, c.certificate.title, c.certificate.issue_date, c.certificate.expiry_date ?? '', c.certificate.file_sha256].join('|');
      c.proof.digest_sha256 = hex(await crypto.subtle.digest('SHA-256', enc.encode(can)));
      const kp = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
      const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', kp.privateKey, enc.encode(c.proof.digest_sha256));
      c.proof.signature_base64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
      const spki = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey))));
      c.proof.public_key_pem = '-----BEGIN PUBLIC KEY-----\\n' + spki.match(/.{1,64}/g).join('\\n') + '\\n-----END PUBLIC KEY-----';
      c.proof.key_fingerprint_sha256 = await CertiVaultCredential.fingerprint(c.proof.public_key_pem);
      const r = await CertiVaultCredential.verify(c, { directory: true });
      return { checks: r.checks, overall: CertiVaultCredential.overall(r.checks).cls };
    })()`);
    const a = states(attacker);
    ok('browser: attacker-key credential passes the self-contained crypto', a.digest === 'pass' && a.signature === 'pass', JSON.stringify(a));
    ok('browser: …but the key directory exposes it (overall not authentic)', a.directory === 'fail' && attacker.overall === 'fail', JSON.stringify(a));

    // Full UI flow: paste JSON, submit, read the rendered verdict.
    await go(anon, `${BASE}/offline_verify.php`);
    await ev(anon, `(() => { document.getElementById('credentialText').value = ${JSON.stringify(JSON.stringify(cred))};
      document.querySelector('#credentialForm button[type=submit]').click(); return true; })()`);
    let overallUi = null;
    for (let i = 0; i < 40 && !overallUi; i++) {
      await sleep(150);
      overallUi = await ev(anon, `document.getElementById('credentialResult').getAttribute('data-overall')`);
    }
    ok('offline_verify UI: pasted genuine credential shows Authentic', overallUi === 'pass', String(overallUi));

    // ── Institution admin ────────────────────────────────────────────
    const admin = await open((await cdp.send('Target.createBrowserContext')).browserContextId);
    const adminLanding = await login(admin, fx.ADMIN_EMAIL, fx.PASSWORD);
    ok('admin login through the real form (CAPTCHA solved)', adminLanding !== '/login.php', adminLanding);
    for (const p of ['/admin_dashboard.php', '/issue_certificate.php', '/audit_logs.php', '/change_password.php',
      `/view_certificate_admin.php?id=${fx.CERT_DB_ID}`, `/revoke_certificate.php?id=${fx.CERT_DB_ID}`, `/supersede_certificate.php?id=${fx.CERT_DB_ID}`]) {
      await audit(admin, p);
    }
    // File-name preview on issue_certificate (data-filename-target).
    await go(admin, `${BASE}/issue_certificate.php`);
    const tmpPdf = join(tmpdir(), 'cv-pages-preview.pdf');
    writeFileSync(tmpPdf, '%PDF-1.4\n' + 'x'.repeat(2048));
    const { root } = await cdp.send('DOM.getDocument', {}, admin.sessionId);
    const { nodeId } = await cdp.send('DOM.querySelector', { nodeId: root.nodeId, selector: '#certificate_file' }, admin.sessionId);
    await cdp.send('DOM.setFileInputFiles', { nodeId, files: [tmpPdf] }, admin.sessionId);
    await ev(admin, `document.getElementById('certificate_file').dispatchEvent(new Event('change', { bubbles: true }))`);
    const preview = await ev(admin, `document.getElementById('file_name_display').textContent`);
    ok('ui.js: file name + size preview on issue form', /cv-pages-preview\.pdf — 2\.0 KB/.test(preview), preview);
    rmSync(tmpPdf, { force: true });
    // Back link on change_password uses data-history-back with a real href.
    await go(admin, `${BASE}/change_password.php`);
    const back = await ev(admin, `(() => { const a = document.querySelector('a[data-history-back]'); return a ? a.getAttribute('href') : null; })()`);
    ok('change_password back link: data-history-back with a no-JS href', back === 'index.php', String(back));

    // ── Student ──────────────────────────────────────────────────────
    const student = await open((await cdp.send('Target.createBrowserContext')).browserContextId);
    const stuLanding = await login(student, fx.STUDENT_EMAIL, fx.PASSWORD);
    ok('student login through the real form', stuLanding !== '/login.php', stuLanding);
    for (const p of ['/student_dashboard.php', '/change_password.php', `/view_certificate_student.php?id=${fx.CERT_DB_ID}`]) {
      await audit(student, p);
    }
    await go(student, `${BASE}/view_certificate_student.php?id=${fx.CERT_DB_ID}`);
    // Generate a share link through the real (CSRF-protected) form.
    const genLoaded = cdp.once('Page.loadEventFired', student.sessionId);
    await ev(student, `document.querySelector('input[name=generate_share]').form.querySelector('[type=submit]').click()`);
    await genLoaded; await sleep(300);
    const share = await ev(student, `(() => { const i = document.getElementById('shareLinkInput'); return i ? i.value : ''; })()`);
    if (share) {
      await ev(student, `document.getElementById('shareLinkInput').click()`);
      const sel = await ev(student, `(() => { const i = document.getElementById('shareLinkInput'); return i.selectionStart === 0 && i.selectionEnd === i.value.length; })()`);
      ok('ui.js: share link selects on click', sel === true);
      await ev(student, `document.getElementById('copyShareBtn').click()`);
      await sleep(300);
      ok('ui.js: copy shows the toast', (await ev(student, `!document.getElementById('copiedToast').hidden`)) === true);
      const sharePath = new URL(share).pathname + new URL(share).search;
      await audit(anon, sharePath);
    } else {
      ok('student certificate page offers a share link', false, 'no #shareLinkInput');
    }
  } catch (e) {
    fail++; console.log('FAIL pages-browser exception — ' + e.message);
  } finally {
    cdp.ws.close(); chrome.kill(); server.kill();
    await sleep(400);
    try { rmSync(userDir, { recursive: true, force: true }); } catch { /* locked */ }
    phpRun(['tests/seed_browser_fixtures.php', '--clean']);
    phpRun(['tests/support/ui_db.php', 'reset-limiter']);
  }
  console.log(`\npages-browser summary: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error('pages-browser fatal:', e.message); process.exit(2); });
