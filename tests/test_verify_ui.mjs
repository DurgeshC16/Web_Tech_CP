// tests/test_verify_ui.mjs
// End-to-end test of the multi-input verification UI on verify.php.
//
// Drives a real Chrome/Edge through the DevTools Protocol (no npm deps;
// Node >= 21 provides a global WebSocket) and exercises all four input
// methods against the isolated test database:
//   1. camera      — a synthetic MediaStream showing a real QR image
//   2. QR image    — PNG upload decoded in the browser
//   3. PDF         — single + multi-page PDFs rendered by pdf.js
//   4. certificate id — the manual GET form
// plus direct links and the extraction/origin-validation rules.
//
// The script is self-contained: it starts `php -S` on a free port, builds
// fixtures (tests/fixtures/make_verify_fixtures.php) for that origin, runs
// the checks, then cleans up. Set CV_UI_SKIP=1 to bypass.
//
// Exit 0 on success, 1 on any failed assertion, 0 (SKIP) when the tooling
// or prerequisites are unavailable.
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

if (process.env.CV_UI_SKIP === '1') {
  console.log('SKIP verify-ui: CV_UI_SKIP=1');
  process.exit(0);
}

// ── Locate Chrome/Edge and PHP ──────────────────────────────────────────
const CHROME = [
  process.env.CV_CHROME,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
].filter(Boolean).find((p) => existsSync(p));
if (!CHROME) {
  console.log('SKIP verify-ui: no Chrome/Edge found (set CV_CHROME).');
  process.exit(0);
}

const PHP = [
  process.env.CV_PHP,
  'C:/xampp/php/php.exe',
  'php',
].filter(Boolean).find((p) => p === 'php' || existsSync(p));
if (!PHP) {
  console.log('SKIP verify-ui: no PHP binary found (set CV_PHP).');
  process.exit(0);
}

const PLATFORM = process.platform;
const OPENSSL_CONF = process.env.OPENSSL_CONF
  || (existsSync('C:/xampp/apache/conf/openssl.cnf') ? 'C:/xampp/apache/conf/openssl.cnf' : '');
const phpEnv = {
  ...process.env,
  CV_TEST_DB: process.env.CV_TEST_DB || 'certivault_test',
  OPENSSL_CONF,
};

function phpRun(args) {
  return spawnSync(PHP, args, { cwd: ROOT, env: phpEnv, encoding: 'utf8' });
}

// ── Free port + PHP dev server ──────────────────────────────────────────
async function portFree(port) {
  return await new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.once('listening', () => s.close(() => resolve(true)));
    s.listen(port, '127.0.0.1');
  });
}

async function pickPort(start) {
  for (let p = start; p < start + 50; p++) {
    if (await portFree(p)) return p;
  }
  return start;
}

// ── Minimal CDP client (mirrors tests/support/responsive_check.mjs) ─────
class CDP {
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map(); this.listeners = new Map();
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id !== undefined && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
      } else if (msg.method) {
        (this.listeners.get(msg.method) || []).forEach((fn) => fn(msg));
      }
    });
  }
  static async connect(wsUrl) {
    const ws = new WebSocket(wsUrl);
    await new Promise((res, rej) => {
      ws.addEventListener('open', res, { once: true });
      ws.addEventListener('error', () => rej(new Error('ws error')), { once: true });
    });
    return new CDP(ws);
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify(payload));
      setTimeout(() => {
        if (this.pending.has(id)) { this.pending.delete(id); reject(new Error(`timeout: ${method}`)); }
      }, 30000);
    });
  }
  waitEvent(method, sessionId, timeoutMs = 12000) {
    return new Promise((resolve) => {
      const handler = (msg) => {
        if (sessionId && msg.sessionId !== sessionId) return;
        clearTimeout(t); this.off(method, handler); resolve(msg.params);
      };
      this.listeners.set(method, [...(this.listeners.get(method) || []), handler]);
      const t = setTimeout(() => { this.off(method, handler); resolve(null); }, timeoutMs);
    });
  }
  off(method, handler) {
    this.listeners.set(method, (this.listeners.get(method) || []).filter((h) => h !== handler));
  }
}

async function evaluate(cdp, sessionId, expression) {
  const { result, exceptionDetails } = await cdp.send(
    'Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
  if (exceptionDetails) throw new Error(exceptionDetails.text || 'evaluate threw');
  return result.value;
}

async function newPage(cdp, { initScript } = {}) {
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Runtime.enable', {}, sessionId);
  await cdp.send('DOM.enable', {}, sessionId);
  await cdp.send('Emulation.setDeviceMetricsOverride',
    { width: 1200, height: 900, deviceScaleFactor: 1, mobile: false }, sessionId);
  if (initScript) {
    await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: initScript }, sessionId);
  }
  return { targetId, sessionId };
}

async function closePage(cdp, page) {
  if (page && page.targetId) await cdp.send('Target.closeTarget', { targetId: page.targetId }).catch(() => {});
}

async function navigate(cdp, sessionId, url) {
  const loaded = cdp.waitEvent('Page.loadEventFired', sessionId, 15000);
  await cdp.send('Page.navigate', { url }, sessionId);
  await loaded;
  await sleep(250);
  await ensureScripts(cdp, sessionId);
}

// The page is only meaningful once verify-scan.js and html5-qrcode have run.
// On a slow/() dev server an asset can occasionally miss its first load, so
// poll for the globals and reload a couple of times before giving up.
async function ensureScripts(cdp, sessionId, attempts = 3) {
  const probe = `!!(window.CertiVaultVerify && typeof window.Html5Qrcode === 'function')`;
  for (let i = 0; i < attempts; i++) {
    const ok = await evaluate(cdp, sessionId, probe).catch(() => false);
    if (ok) return true;
    const loaded = cdp.waitEvent('Page.loadEventFired', sessionId, 15000);
    await cdp.send('Page.reload', {}, sessionId);
    await loaded;
    await sleep(300);
  }
  return await evaluate(cdp, sessionId, probe).catch(() => false);
}

async function setFile(cdp, sessionId, selector, filePath) {
  const { root } = await cdp.send('DOM.getDocument', {}, sessionId);
  const { nodeId } = await cdp.send('DOM.querySelector', { nodeId: root.nodeId, selector }, sessionId);
  if (!nodeId) throw new Error(`file input not found: ${selector}`);
  await cdp.send('DOM.setFileInputFiles', { files: [normalize(filePath)], nodeId }, sessionId);
}

function stateExpr() {
  return `(() => {
    const st = document.getElementById('verifyStatus');
    const ch = document.getElementById('verifyChooser');
    return {
      url: location.pathname + location.search,
      status: st && !st.hidden ? st.textContent : '',
      statusClass: st ? st.className : '',
      chooser: ch && !ch.hidden ? ch.textContent : ''
    };
  })()`;
}

// Poll until the page either navigated (token/certificate_id in the URL),
// showed an error status, or surfaced the multi-QR chooser.
async function waitOutcome(cdp, sessionId, timeoutMs = 20000) {
  const start = Date.now();
  let last = null;
  while (Date.now() - start < timeoutMs) {
    try {
      last = await evaluate(cdp, sessionId, stateExpr());
      if (last) {
        if (/[?&](token|certificate_id)=/.test(last.url)) return { kind: 'nav', ...last };
        if (/scan-status-error/.test(last.statusClass)) return { kind: 'error', ...last };
        if (last.chooser) return { kind: 'chooser', ...last };
      }
    } catch { /* context swapping during navigation */ }
    await sleep(150);
  }
  return { kind: 'timeout', ...(last || {}) };
}

async function readVerdict(cdp, sessionId) {
  return await evaluate(cdp, sessionId,
    `(() => { const el = document.querySelector('.verdict-seal'); return el ? el.textContent.trim() : ''; })()`);
}

// ── Test bookkeeping ────────────────────────────────────────────────────
let pass = 0, fail = 0;
function ok(name, cond, extra = '') {
  if (cond) { pass++; console.log(`PASS ${name}`); }
  else { fail++; console.log(`FAIL ${name}${extra ? ' — ' + extra : ''}`); }
}

// ── Main ────────────────────────────────────────────────────────────────
async function main() {
  const port = await pickPort(Number(process.env.CV_UI_PORT || 8151));
  const BASE = `http://127.0.0.1:${port}`;
  console.log(`verify-ui: server=${BASE} php=${PHP}`);

  // 1) Build fixtures for this origin.
  const mk = phpRun(['tests/fixtures/make_verify_fixtures.php', `--base=${BASE}`]);
  if (mk.status !== 0) {
    console.log('SKIP verify-ui: fixture generation failed.');
    console.log(mk.stdout || ''); console.log(mk.stderr || '');
    process.exit(0);
  }
  const manifest = JSON.parse(readFileSync(join(ROOT, 'tests/fixtures/out/manifest.json'), 'utf8'));

  // 2) Start the PHP dev server.
  const serverEnv = {
    ...process.env,
    CV_DB_NAME: process.env.CV_TEST_DB || 'certivault_test',
    CV_MAIL_TRANSPORT: 'file',
    CV_ENV: 'development',
    CV_BASE_URL: BASE,
  };
  const server = spawn(PHP, ['-S', `127.0.0.1:${port}`, '-t', 'public'], { cwd: ROOT, env: serverEnv, stdio: 'ignore' });
  let up = false;
  for (let i = 0; i < 60 && !up; i++) {
    try { const r = await fetch(`${BASE}/verify.php`); up = r.ok; } catch { /* not yet */ }
    if (!up) await sleep(150);
  }
  if (!up) { console.log('SKIP verify-ui: PHP server did not start.'); server.kill(); process.exit(0); }

  // 3) Launch Chrome.
  const userDir = mkdtempSync(join(tmpdir(), 'cv-ui-chrome-'));
  const CDP_PORT = await pickPort(Number(process.env.CV_CDP_PORT || 9333));
  const chrome = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--mute-audio',
    '--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream',
    `--remote-debugging-port=${CDP_PORT}`, `--user-data-dir=${userDir}`, 'about:blank',
  ], { stdio: 'ignore' });

  let wsUrl = null;
  for (let i = 0; i < 100 && !wsUrl; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`);
      if (r.ok) wsUrl = (await r.json()).webSocketDebuggerUrl;
    } catch { /* not yet */ }
    if (!wsUrl) await sleep(150);
  }
  if (!wsUrl) { console.log('SKIP verify-ui: DevTools endpoint did not come up.'); chrome.kill(); server.kill(); process.exit(0); }
  const cdp = await CDP.connect(wsUrl);

  const T = manifest.tokens;
  const C = manifest.cert_ids;
  const QR = manifest.qr;
  const PDF = manifest.pdf;

  try {
    // ── A. extractIdentifier unit rules (deterministic, in-page) ────────
    {
      const page = await newPage(cdp);
      await navigate(cdp, page.sessionId, `${BASE}/verify.php`);
      const checks = await evaluate(cdp, page.sessionId, `(() => {
        const ex = window.CertiVaultVerify.extractIdentifier;
        const tok = ${JSON.stringify(T.valid)};
        const t = (x) => { const r = ex(x); return r ? r.type + ':' + r.value : null; };
        return {
          bare: t(tok),
          spaced: t('\\n  ' + tok + '  \\n'),
          urlsame: t(location.origin + '/verify.php?token=' + tok),
          urlrelative: t('verify.php?token=' + tok),
          foreign: t('https://evil.example/verify.php?token=' + tok),
          wrongpath: t(location.origin + '/index.php?token=' + tok),
          javascript: t('javascript:alert(1)'),
          certid: t('CV-2026-880001'),
          malformedShort: t('tooshort'),
          empty: t(''),
          httpForeign: t('http://attacker.test/verify.php?token=' + tok)
        };
      })()`);
      ok('extract: bare 43-char token', checks.bare === 'token:' + T.valid);
      ok('extract: surrounding whitespace trimmed', checks.spaced === 'token:' + T.valid);
      ok('extract: same-origin verify URL', checks.urlsame === 'token:' + T.valid);
      ok('extract: relative verify URL', checks.urlrelative === 'token:' + T.valid);
      ok('extract: foreign origin rejected', checks.foreign === null);
      ok('extract: same-origin wrong path rejected', checks.wrongpath === null);
      ok('extract: javascript: scheme rejected', checks.javascript === null);
      ok('extract: certificate id accepted', checks.certid === 'certificate_id:CV-2026-880001');
      ok('extract: malformed token rejected', checks.malformedShort === null);
      ok('extract: empty rejected', checks.empty === null);
      ok('extract: http foreign origin rejected', checks.httpForeign === null);
      await closePage(cdp, page);
    }

    // Helper: run an upload-style test on a fresh page.
    async function uploadTest(tabId, selector, btnId, filePath, expect) {
      const page = await newPage(cdp);
      try {
        await navigate(cdp, page.sessionId, `${BASE}/verify.php`);
        await evaluate(cdp, page.sessionId, `document.getElementById(${JSON.stringify(tabId)}).click()`);
        await setFile(cdp, page.sessionId, selector, filePath);
        await evaluate(cdp, page.sessionId, `document.getElementById(${JSON.stringify(btnId)}).click()`);
        const out = await waitOutcome(cdp, page.sessionId);
        if (expect === 'valid') {
          return { ok: out.kind === 'nav' && out.url.includes('token=' + T.valid), out };
        }
        return { ok: out.kind === 'error', out };
      } finally {
        await closePage(cdp, page);
      }
    }

    // ── B. QR image uploads ─────────────────────────────────────────────
    {
      const r = await uploadTest('tab-image', '#qrImageInput', 'qrImageBtn', QR.valid, 'valid');
      ok('image: valid QR navigates to token', r.ok, JSON.stringify(r.out));
      const page = await newPage(cdp);
      await navigate(cdp, page.sessionId, `${BASE}/verify.php?token=${T.valid}`);
      ok('image: resulting verdict is VALID', (await readVerdict(cdp, page.sessionId)) === 'VALID');
      await closePage(cdp, page);
    }
    {
      const r = await uploadTest('tab-image', '#qrImageInput', 'qrImageBtn', QR.bare, 'valid');
      ok('image: bare-token QR navigates to token', r.ok, JSON.stringify(r.out));
    }
    {
      const r = await uploadTest('tab-image', '#qrImageInput', 'qrImageBtn', QR.foreign, 'error');
      ok('image: foreign-origin QR is rejected (no navigation)', r.ok && !/token=/.test(r.out.url), JSON.stringify(r.out));
    }
    {
      const r = await uploadTest('tab-image', '#qrImageInput', 'qrImageBtn', QR.malformed, 'error');
      ok('image: malformed-token QR is rejected', r.ok, JSON.stringify(r.out));
    }
    {
      const r = await uploadTest('tab-image', '#qrImageInput', 'qrImageBtn', QR.noqr, 'error');
      ok('image: valid PNG without a QR shows an error', r.ok, JSON.stringify(r.out));
    }
    {
      const r = await uploadTest('tab-image', '#qrImageInput', 'qrImageBtn', QR.garbage, 'error');
      ok('image: unreadable/corrupted image shows an error', r.ok, JSON.stringify(r.out));
    }

    // ── C. PDF uploads ──────────────────────────────────────────────────
    {
      const r = await uploadTest('tab-pdf', '#pdfInput', 'pdfBtn', PDF.one, 'valid');
      ok('pdf: single-page certificate navigates to token', r.ok, JSON.stringify(r.out));
    }
    {
      const r = await uploadTest('tab-pdf', '#pdfInput', 'pdfBtn', PDF.multi, 'valid');
      ok('pdf: multi-page certificate (QR on page 3) navigates to token', r.ok, JSON.stringify(r.out));
    }
    {
      const r = await uploadTest('tab-pdf', '#pdfInput', 'pdfBtn', PDF.noqr, 'error');
      ok('pdf: multi-page PDF without a QR shows an error', r.ok, JSON.stringify(r.out));
    }
    {
      const r = await uploadTest('tab-pdf', '#pdfInput', 'pdfBtn', PDF.broken, 'error');
      ok('pdf: corrupted PDF shows an error', r.ok, JSON.stringify(r.out));
    }

    // ── D. Manual certificate id ────────────────────────────────────────
    {
      const page = await newPage(cdp);
      try {
        await navigate(cdp, page.sessionId, `${BASE}/verify.php`);
        await evaluate(cdp, page.sessionId, `document.getElementById('tab-id').click()`);
        await evaluate(cdp, page.sessionId, `(() => {
          const i = document.getElementById('certificate_id');
          i.value = ${JSON.stringify(C.valid)};
          i.form.querySelector('button[type=submit]').click();
        })()`);
        const out = await waitOutcome(cdp, page.sessionId);
        ok('manual: valid certificate id verifies', out.kind === 'nav' && out.url.includes('certificate_id=' + C.valid), JSON.stringify(out));
        ok('manual: verdict is VALID', (await readVerdict(cdp, page.sessionId)) === 'VALID');
      } finally { await closePage(cdp, page); }
    }
    {
      // Client-side validation must block a malformed id BEFORE any request.
      const page = await newPage(cdp);
      try {
        await navigate(cdp, page.sessionId, `${BASE}/verify.php`);
        await evaluate(cdp, page.sessionId, `document.getElementById('tab-id').click()`);
        await evaluate(cdp, page.sessionId, `(() => {
          const i = document.getElementById('certificate_id');
          i.value = 'not-a-cert-id';
          i.form.querySelector('button[type=submit]').click();
        })()`);
        await sleep(600);
        const st = await evaluate(cdp, page.sessionId, `(() => {
          const i = document.getElementById('certificate_id');
          const err = i.closest('.form-group').querySelector('.field-error');
          return { url: location.pathname + location.search, invalid: i.getAttribute('aria-invalid'), err: err ? err.textContent : '' };
        })()`);
        ok('manual: malformed id is blocked client-side (no request)',
          !/certificate_id=/.test(st.url) && st.invalid === 'true' && !!st.err, JSON.stringify(st));
      } finally { await closePage(cdp, page); }
    }
    {
      // Bypass client validation to prove the server also rejects it (INVALID).
      const page = await newPage(cdp);
      try {
        await navigate(cdp, page.sessionId, `${BASE}/verify.php`);
        await evaluate(cdp, page.sessionId, `(() => {
          const i = document.getElementById('certificate_id');
          i.value = 'not-a-cert-id';
          i.form.submit();
        })()`);
        await cdp.waitEvent('Page.loadEventFired', page.sessionId, 12000);
        await sleep(200);
        ok('manual: server rejects malformed id with INVALID', (await readVerdict(cdp, page.sessionId)) === 'INVALID');
      } finally { await closePage(cdp, page); }
    }

    // ── E. Direct verification links (all six verdicts) ─────────────────
    {
      const cases = [
        ['VALID', `token=${T.valid}`],
        ['EXPIRED', `token=${T.expired}`],
        ['REVOKED', `token=${T.revoked}`],
        ['SUPERSEDED', `token=${T.superseded}`],
        ['TAMPERED', `token=${T.tampered}`],
        ['INVALID', `token=${T.unknown}`],
      ];
      const page = await newPage(cdp);
      try {
        for (const [want, qs] of cases) {
          await navigate(cdp, page.sessionId, `${BASE}/verify.php?${qs}`);
          const got = await readVerdict(cdp, page.sessionId);
          ok(`direct link: ${want} verdict`, got === want, `got ${got}`);
        }
        // certificate-id direct link
        await navigate(cdp, page.sessionId, `${BASE}/verify.php?certificate_id=${C.valid}`);
        ok('direct link: certificate_id param works', (await readVerdict(cdp, page.sessionId)) === 'VALID');
        // unknown cert id
        await navigate(cdp, page.sessionId, `${BASE}/verify.php?certificate_id=${C.unknown}`);
        ok('direct link: unknown certificate id is INVALID', (await readVerdict(cdp, page.sessionId)) === 'INVALID');
      } finally { await closePage(cdp, page); }
    }

    // ── F. Camera — synthetic MediaStream showing the real QR ───────────
    {
      const buf = readFileSync(normalize(QR.valid)).toString('base64');
      const init = `(() => {
        const DATA = 'data:image/png;base64,${buf}';
        const img = new Image();
        img.src = DATA;
        const ready = new Promise((res) => { img.onload = res; img.onerror = res; });
        const md = navigator.mediaDevices;
        if (md) {
          md.enumerateDevices = () => Promise.resolve([{ deviceId: 'fake', kind: 'videoinput', label: 'fake', groupId: 'fake' }]);
          md.getUserMedia = () => ready.then(() => {
            // Draw the QR well inside the scanner's 250x250 qrbox: a 640x640
            // frame with a 200x200 QR centred, so the box never crops it.
            const c = document.createElement('canvas');
            c.width = 640; c.height = 640;
            const ctx = c.getContext('2d');
            const draw = () => {
              ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, 640, 640);
              ctx.drawImage(img, 220, 220, 200, 200);
            };
            draw(); setInterval(draw, 120);
            return c.captureStream(12);
          });
        }
      })();`;
      const page = await newPage(cdp, { initScript: init });
      try {
        await navigate(cdp, page.sessionId, `${BASE}/verify.php`);
        await evaluate(cdp, page.sessionId, `document.getElementById('tab-camera').click()`);
        await evaluate(cdp, page.sessionId, `document.getElementById('cameraStartBtn').click()`);
        const out = await waitOutcome(cdp, page.sessionId, 25000);
        ok('camera: decodes a live QR frame and verifies',
          out.kind === 'nav' && out.url.includes('token=' + T.valid), JSON.stringify(out));
      } finally { await closePage(cdp, page); }
    }
    {
      // Camera unavailable / permission denied paths must show guidance.
      const init = `(() => {
        const md = navigator.mediaDevices;
        if (md) {
          md.enumerateDevices = () => Promise.resolve([]);
          md.getUserMedia = () => Promise.reject(new DOMException('Permission denied', 'NotAllowedError'));
        }
      })();`;
      const page = await newPage(cdp, { initScript: init });
      try {
        await navigate(cdp, page.sessionId, `${BASE}/verify.php`);
        await evaluate(cdp, page.sessionId, `document.getElementById('tab-camera').click()`);
        await evaluate(cdp, page.sessionId, `document.getElementById('cameraStartBtn').click()`);
        const out = await waitOutcome(cdp, page.sessionId, 12000);
        ok('camera: permission denial shows guidance',
          out.kind === 'error' && /denied|no camera|camera is busy|could not start/i.test(out.status), JSON.stringify(out));
      } finally { await closePage(cdp, page); }
    }

    // ── G. Camera stop control is visible while scanning ────────────────
    {
      // A synthetic stream with NO QR code, so the scanner keeps running and
      // we can observe the start/stop controls instead of navigating away.
      const init = `(() => {
        const md = navigator.mediaDevices;
        if (md) {
          md.enumerateDevices = () => Promise.resolve([{ deviceId: 'fake', kind: 'videoinput', label: 'fake', groupId: 'fake' }]);
          md.getUserMedia = () => Promise.resolve((() => {
            const c = document.createElement('canvas'); c.width = 320; c.height = 320;
            const ctx = c.getContext('2d');
            const draw = () => {
              const g = ctx.createLinearGradient(0, 0, 320, 320);
              g.addColorStop(0, '#ddd'); g.addColorStop(1, '#aaa');
              ctx.fillStyle = g; ctx.fillRect(0, 0, 320, 320);
            };
            draw(); setInterval(draw, 200);
            return c.captureStream(8);
          })());
        }
      })();`;
      const page = await newPage(cdp, { initScript: init });
      try {
        await navigate(cdp, page.sessionId, `${BASE}/verify.php`);
        await evaluate(cdp, page.sessionId, `document.getElementById('tab-camera').click()`);
        await evaluate(cdp, page.sessionId, `document.getElementById('cameraStartBtn').click()`);
        await sleep(2000);
        const vis = await evaluate(cdp, page.sessionId, `(() => {
          const stop = document.getElementById('cameraStopBtn');
          const start = document.getElementById('cameraStartBtn');
          return { stopShown: stop && !stop.hidden, startHidden: start && start.hidden };
        })()`);
        ok('camera: stop control visible while scanning',
          vis.stopShown && vis.startHidden, JSON.stringify(vis));
        // Press stop and confirm the scanner UI is torn down.
        await evaluate(cdp, page.sessionId, `document.getElementById('cameraStopBtn').click()`);
        await sleep(800);
        const after = await evaluate(cdp, page.sessionId, `(() => {
          const stop = document.getElementById('cameraStopBtn');
          const reader = document.getElementById('qrReader');
          return { stopHidden: stop && stop.hidden, readerHidden: reader && reader.hidden };
        })()`);
        ok('camera: stop hides the scanner', after.stopHidden && after.readerHidden, JSON.stringify(after));
      } finally { await closePage(cdp, page); }
    }
  } catch (e) {
    fail++;
    console.log('FAIL verify-ui exception — ' + e.message);
  } finally {
    cdp.ws.close();
    chrome.kill();
    server.kill();
    await sleep(300);
    try { rmSync(userDir, { recursive: true, force: true }); } catch { /* locked */ }
    phpRun(['tests/fixtures/make_verify_fixtures.php', '--clean']);
  }

  console.log(`\nverify-ui summary: ${pass} passed, ${fail} failed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => { console.error('verify-ui fatal:', e.message); process.exit(2); });
