// tests/test_verify_ui.mjs
// End-to-end test of the Smart Verify panel on verify.php in a REAL browser.
//
// Drives Chrome/Edge through the DevTools Protocol (no npm deps; Node >= 21
// provides a global WebSocket) against the isolated test database:
//   A. in-page QR decoding (smart-verify.js): PDF pages rendered by pdf.js
//      (QR on page 1 and on page 3), QR PNG, PDF without QR, corrupt PDF
//   B. upload flow: PDF whose bytes differ from the issued file -> resolved
//      by the browser-decoded QR -> VALID with the "not byte-exact" note
//   C. privacy mode: only hash + QR text are posted (checked in the log)
//   D. PDF without a QR -> INVALID
//   E. shareable GET links (?certificate_id=, ?token=)
//   F. camera button starts / stops the scanner (fake media stream)
//   G. no CSP violations or uncaught exceptions on the page
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
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
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
  ...(OPENSSL_CONF ? { OPENSSL_CONF } : {}),
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

// The page is only meaningful once smart-verify.js and html5-qrcode have run.
// On a slow/() dev server an asset can occasionally miss its first load, so
// poll for the globals and reload a couple of times before giving up.
async function ensureScripts(cdp, sessionId, attempts = 3) {
  const probe = `!!(window.CertiVaultSmartVerify && typeof window.Html5Qrcode === 'function')`;
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

// Poll until the result view (verdict seal) is rendered after a submit.
async function waitVerdict(cdp, sessionId, timeoutMs = 30000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const v = await evaluate(cdp, sessionId, `(() => {
        const seal = document.querySelector('[class*="verdict-seal-"]');
        if (!seal) return null;
        const m = seal.className.match(/verdict-seal-([a-z]+)/);
        return { verdict: m ? m[1].toUpperCase() : '', text: document.body.innerText };
      })()`);
      if (v) return v;
    } catch { /* context swapping during navigation */ }
    await sleep(200);
  }
  return { verdict: 'TIMEOUT', text: '' };
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
    '--disable-extensions', '--mute-audio', ...(process.env.CI ? ['--no-sandbox'] : []),
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

  // Collect CSP violations / uncaught exceptions from every page.
  const pageProblems = [];
  cdp.listeners.set('Runtime.exceptionThrown', [(m) => pageProblems.push('exception: ' + (m.params.exceptionDetails.text || ''))]);
  cdp.listeners.set('Log.entryAdded', [(m) => {
    const t = m.params.entry.text || '';
    if (/Content Security Policy|Refused to/i.test(t)) pageProblems.push('csp: ' + t);
  }]);
  // Fresh limiter window for 127.0.0.1 (many lookups below).
  phpRun(['tests/support/ui_db.php', 'reset-limiter']);

  async function freshPage(init) {
    const page = await newPage(cdp, init ? { initScript: init } : {});
    await cdp.send('Log.enable', {}, page.sessionId);
    await navigate(cdp, page.sessionId, `${BASE}/verify.php`);
    return page;
  }
  async function submitForm(sessionId) {
    await evaluate(cdp, sessionId, `document.querySelector('#smartVerifyForm button[type=submit]').click()`);
    return await waitVerdict(cdp, sessionId);
  }

  try {
    // ── A. In-page decoding ──────────────────────────────────────────
    {
      const page = await freshPage();
      const decode = async (file) => {
        await setFile(cdp, page.sessionId, '#smart_file', file);
        return await evaluate(cdp, page.sessionId,
          `window.CertiVaultSmartVerify.decodeFile(document.getElementById('smart_file').files[0]).then((t) => t, () => 'THREW')`);
      };
      const one = await decode(PDF.one);
      ok('decode: PDF with QR on page 1', typeof one === 'string' && one.includes(T.valid), String(one));
      const multi = await decode(PDF.multi);
      ok('decode: PDF with QR on page 3', typeof multi === 'string' && multi.includes(T.valid), String(multi));
      const png = await decode(QR.valid);
      ok('decode: QR PNG image', typeof png === 'string' && png.includes(T.valid), String(png));
      const none = await decode(PDF.noqr);
      ok('decode: PDF without QR -> null', none === null, String(none));
      const broken = await decode(PDF.broken);
      ok('decode: corrupt PDF -> rejected cleanly (THREW is caught by submit)', broken === null || broken === 'THREW', String(broken));
      await closePage(cdp, page);
    }

    // ── B. Upload flow resolved by the browser-decoded QR ─────────────
    {
      const page = await freshPage();
      await setFile(cdp, page.sessionId, '#smart_file', PDF.one);
      const v = await submitForm(page.sessionId);
      ok('upload PDF (not byte-exact) -> VALID via browser QR', v.verdict === 'VALID', v.verdict);
      ok('upload result warns the copy is not byte-exact', v.text.includes('not a byte-exact copy'));
      await closePage(cdp, page);
    }

    // ── C. Privacy mode: hash + QR text only ──────────────────────────
    {
      const page = await freshPage();
      await evaluate(cdp, page.sessionId, `document.getElementById('privacyHashToggle').click()`);
      const pressed = await evaluate(cdp, page.sessionId, `document.getElementById('privacyHashToggle').getAttribute('aria-pressed')`);
      ok('privacy toggle reports aria-pressed=true', pressed === 'true');
      await setFile(cdp, page.sessionId, '#smart_file', PDF.multi);
      const v = await submitForm(page.sessionId);
      ok('privacy mode PDF -> VALID via browser QR', v.verdict === 'VALID', v.verdict);
      const log = phpRun(['tests/support/ui_db.php', 'last-log']);
      let row = {};
      try { row = JSON.parse(log.stdout || '{}') || {}; } catch { /* keep {} */ }
      ok('privacy mode logged as a hash lookup (file never uploaded)',
        /^[a-f0-9]{64}$/.test(row.query_value || '') && (row.detail || '').includes('privacy hash lookup'), JSON.stringify(row));
      await closePage(cdp, page);
    }

    // ── D. PDF with no QR -> INVALID ──────────────────────────────────
    {
      const page = await freshPage();
      await setFile(cdp, page.sessionId, '#smart_file', PDF.noqr);
      const v = await submitForm(page.sessionId);
      ok('upload PDF without QR -> INVALID', v.verdict === 'INVALID', v.verdict);
      await closePage(cdp, page);
    }

    // ── E. Shareable links ────────────────────────────────────────────
    {
      const page = await newPage(cdp);
      await cdp.send('Page.navigate', { url: `${BASE}/verify.php?certificate_id=${encodeURIComponent(C.valid)}` }, page.sessionId);
      let v = await waitVerdict(cdp, page.sessionId);
      ok('GET ?certificate_id= -> VALID', v.verdict === 'VALID', v.verdict);
      await cdp.send('Page.navigate', { url: `${BASE}/verify.php?token=${T.revoked}` }, page.sessionId);
      await sleep(500);
      v = await waitVerdict(cdp, page.sessionId);
      ok('GET ?token= (revoked) -> REVOKED', v.verdict === 'REVOKED', v.verdict);
      await closePage(cdp, page);
    }

    // ── F. Camera start / stop with a fake stream ─────────────────────
    {
      const init = `(() => {
        const md = navigator.mediaDevices;
        if (md) {
          md.getUserMedia = () => Promise.resolve((() => {
            const c = document.createElement('canvas'); c.width = 320; c.height = 320;
            const ctx = c.getContext('2d');
            const draw = () => { ctx.fillStyle = '#bbb'; ctx.fillRect(0, 0, 320, 320); };
            draw(); setInterval(draw, 200);
            return c.captureStream(8);
          })());
        }
      })();`;
      const page = await freshPage(init);
      await evaluate(cdp, page.sessionId, `document.getElementById('scanQrBtn').click()`);
      await sleep(2000);
      const on = await evaluate(cdp, page.sessionId, `({ shown: !document.getElementById('qrScanner').hidden, btnDisabled: document.getElementById('scanQrBtn').disabled })`);
      ok('camera: scanner shown while running', on.shown && on.btnDisabled, JSON.stringify(on));
      await evaluate(cdp, page.sessionId, `document.getElementById('qrStopBtn').click()`);
      await sleep(900);
      const off = await evaluate(cdp, page.sessionId, `({ hidden: document.getElementById('qrScanner').hidden, btnEnabled: !document.getElementById('scanQrBtn').disabled })`);
      ok('camera: stop hides the scanner', off.hidden && off.btnEnabled, JSON.stringify(off));
      await closePage(cdp, page);
    }

    // ── G. Page hygiene ───────────────────────────────────────────────
    ok('no CSP violations or uncaught exceptions', pageProblems.length === 0, pageProblems.slice(0, 3).join(' | '));
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
