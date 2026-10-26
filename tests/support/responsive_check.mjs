// tests/support/responsive_check.mjs
// Dependency-free responsive-layout audit driven through the Chrome/Edge
// DevTools Protocol (Node >= 21 provides a global WebSocket). For each
// page x viewport it reports horizontal overflow and the elements that
// exceed the viewport, so layout defects can be fixed with evidence.
//
// Usage (public pages):
//   CV_BASE=http://127.0.0.1:8140 CV_PATHS="/index.php,/login.php" \
//   CV_WIDTHS="375,768,1440" node tests/support/responsive_check.mjs
//
// Usage (authenticated pages — logs in through the real form first):
//   CV_LOGIN_USER=admin@x.test CV_LOGIN_PASS=Password1! CV_ASSERT_PATH=1 \
//   CV_PATHS="/admin_dashboard.php" node tests/support/responsive_check.mjs
//
// Exit 0 when no page overflows, 1 otherwise.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import net from 'node:net';

const CANDIDATES = [
  process.env.CV_CHROME,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files/Microsoft/Edge/Application/msedge.exe',
].filter(Boolean);
const chrome = CANDIDATES.find((p) => existsSync(p));
if (!chrome) {
  console.log('SKIP responsive: no Chrome/Edge found.');
  process.exit(0);
}

const BASE = process.env.CV_BASE || 'http://127.0.0.1:8140';
const PATHS = (process.env.CV_PATHS || '/index.php,/login.php').split(',').map((s) => s.trim()).filter(Boolean);
const WIDTHS = (process.env.CV_WIDTHS || '375,768,1440').split(',').map(Number);
const CDP_PORT = Number(process.env.CV_CDP_PORT || 9222);
const LOGIN_USER = process.env.CV_LOGIN_USER || '';
const LOGIN_PASS = process.env.CV_LOGIN_PASS || '';
const ASSERT_PATH = process.env.CV_ASSERT_PATH === '1';
const LABEL = { 375: 'mobile', 768: 'tablet', 1440: 'desktop' };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const safeRm = (dir) => { try { rmSync(dir, { recursive: true, force: true }); } catch { /* locked during shutdown */ } };

async function portFree(port) {
  return await new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(false));
    s.once('listening', () => s.close(() => resolve(true)));
    s.listen(port, '127.0.0.1');
  });
}

class CDP {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.listeners = new Map();
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
      }, 20000);
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

const MEASURE = `(() => {
  const vw = window.innerWidth;
  const de = document.documentElement;
  const sw = Math.max(de.scrollWidth, document.body ? document.body.scrollWidth : 0);
  const offenders = [];
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.width > 0 && r.right > vw + 1 && r.height > 0) {
      if (getComputedStyle(el).position === 'fixed') continue;
      offenders.push({ tag: el.tagName.toLowerCase(), cls: String(el.className || '').slice(0, 50), right: Math.round(r.right), width: Math.round(r.width) });
      if (offenders.length >= 8) break;
    }
  }
  return { path: location.pathname, vw, sw, overflow: sw > vw + 1, offenders };
})()`;

async function newPage(cdp, width) {
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Emulation.setDeviceMetricsOverride',
    { width, height: 900, deviceScaleFactor: 1, mobile: width < 768 }, sessionId);
  return { targetId, sessionId };
}

async function navigate(cdp, sessionId, url) {
  const loaded = cdp.waitEvent('Page.loadEventFired', sessionId, 12000);
  await cdp.send('Page.navigate', { url }, sessionId);
  await loaded;
  await sleep(300);
}

async function evaluate(cdp, sessionId, expression) {
  const { result } = await cdp.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
  return result.value;
}

/** Log in once through the real form; cookies then apply to all tabs. */
async function login(cdp) {
  const { targetId, sessionId } = await newPage(cdp, 1280);
  try {
    await navigate(cdp, sessionId, BASE + '/login.php');
    const submit = `(() => {
      const email = document.querySelector('input[name=email]');
      if (!email) return 'no-form';
      const q = (document.querySelector('.captcha-chip') || {}).textContent || '';
      const m = q.match(/(\\d+)\\s*\\+\\s*(\\d+)/);
      const ans = m ? String(Number(m[1]) + Number(m[2])) : '';
      email.value = ${JSON.stringify(LOGIN_USER)};
      document.querySelector('input[name=password]').value = ${JSON.stringify(LOGIN_PASS)};
      const cap = document.querySelector('input[name=captcha_answer]');
      if (cap) cap.value = ans;
      email.form.querySelector('button[type=submit]').click();
      return 'submitted';
    })()`;
    const r = await evaluate(cdp, sessionId, submit);
    if (r === 'no-form') { console.log('NOTE login: form not found'); return; }
    await cdp.waitEvent('Page.loadEventFired', sessionId, 12000);
    await sleep(400);
    const path = await evaluate(cdp, sessionId, 'location.pathname');
    console.log(path && path.includes('login') ? `NOTE login: still on ${path} (check creds/captcha)` : `NOTE login: authenticated (landed on ${path})`);
  } finally {
    await cdp.send('Target.closeTarget', { targetId }).catch(() => {});
  }
}

async function main() {
  if (!(await portFree(CDP_PORT))) { console.log(`SKIP responsive: CDP port ${CDP_PORT} busy.`); process.exit(0); }
  const userDir = mkdtempSync(join(tmpdir(), 'cv-chrome-'));
  const proc = spawn(chrome, [
    '--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--disable-extensions', '--mute-audio',
    `--remote-debugging-port=${CDP_PORT}`, `--user-data-dir=${userDir}`, 'about:blank',
  ], { stdio: 'ignore' });

  let wsUrl = null;
  for (let i = 0; i < 100 && !wsUrl; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`);
      if (r.ok) wsUrl = (await r.json()).webSocketDebuggerUrl;
    } catch { /* not up yet */ }
    if (!wsUrl) await sleep(150);
  }
  if (!wsUrl) {
    console.log('SKIP responsive: DevTools endpoint did not come up.');
    proc.kill(); safeRm(userDir); process.exit(0);
  }

  const cdp = await CDP.connect(wsUrl);
  let failures = 0;

  if (LOGIN_USER) await login(cdp);

  for (const path of PATHS) {
    const wantPath = path.split('?')[0];
    for (const width of WIDTHS) {
      const { targetId, sessionId } = await newPage(cdp, width);
      try {
        await navigate(cdp, sessionId, BASE + path);
        const m = await evaluate(cdp, sessionId, MEASURE);
        const tag = `${path} @ ${width}px (${LABEL[width] || width})`;
        if (ASSERT_PATH && m.path !== wantPath) {
          failures++;
          console.log(`FAIL ${tag}: redirected to ${m.path} (not authenticated / not allowed)`);
          continue;
        }
        if (m.overflow) {
          failures++;
          console.log(`FAIL ${tag}: scrollWidth ${m.sw} > viewport ${m.vw}`);
          for (const o of m.offenders) console.log(`       -> <${o.tag} class="${o.cls}"> right=${o.right} w=${o.width}`);
        } else {
          console.log(`PASS ${tag}: no horizontal overflow${m.path !== wantPath ? ` (rendered ${m.path})` : ''}`);
        }
      } catch (e) {
        failures++;
        console.log(`FAIL ${path} @ ${width}px: ${e.message}`);
      } finally {
        await cdp.send('Target.closeTarget', { targetId }).catch(() => {});
      }
    }
  }

  console.log(`\nresponsive summary: ${failures === 0 ? 'all viewports fit' : failures + ' overflow/redirect case(s)'}`);
  cdp.ws.close();
  proc.kill();
  await sleep(300);
  safeRm(userDir);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error('responsive checker error:', e.message); process.exit(2); });
