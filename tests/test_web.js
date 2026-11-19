'use strict';

/**
 * Web end-to-end test. Zero dependencies.
 *
 *   node tests/test_web.js
 *
 * Starts the real server on an ephemeral port with a throwaway DATA_DIR, then
 * exercises the real scanner subprocess on real Windows binaries.
 */

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'revscan-web-'));
process.env.DATA_DIR = TMP;
process.env.ADMIN_KEY = 'test-admin-key';
process.env.TRAPKEY_NO_DOTENV = '1';

const config = require('../web/config');
const views = require('../web/views');
const { createServer } = require('../web/server');

function findBinary(name) {
  const candidates = [];
  if (process.env.TRAPKEY_TEST_BINARIES) candidates.push(path.join(process.env.TRAPKEY_TEST_BINARIES, name));
  const winDir = process.env.WINDIR || 'C:\\Windows';
  candidates.push(path.join(winDir, 'System32', name), path.join('/mnt/c/Windows/System32', name));
  return candidates.find((candidate) => fs.existsSync(candidate)) || candidates[candidates.length - 1];
}

const NOTEPAD = findBinary('notepad.exe');
const HOSTNAME = findBinary('hostname.exe');

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

let base = '';
let cookie = '';
let server;
let lastReport = null;

async function call(method, urlPath, { body, headers = {}, raw = false } = {}) {
  const res = await fetch(base + urlPath, {
    method,
    headers: { cookie, ...headers },
    body,
    redirect: 'manual',
  });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie && setCookie.startsWith('tk_session=')) {
    cookie = setCookie.split(';')[0];
  }
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* html */
  }
  return { status: res.status, text, json, headers: res.headers };
}

async function upload(file, mode = 'static', extra = {}) {
  return call('POST', `/api/scan?mode=${mode}`, {
    body: fs.readFileSync(file),
    headers: { 'x-filename': path.basename(file), 'content-type': 'application/octet-stream', ...extra },
  });
}

function stripeSignature(raw, secret, timestamp = Math.floor(Date.now() / 1000)) {
  const digest = crypto.createHmac('sha256', secret).update(`${timestamp}.${raw}`).digest('hex');
  return `t=${timestamp},v1=${digest}`;
}

async function stripeWebhook(payload, { secret = 'whsec_test', timestamp } = {}) {
  const body = JSON.stringify(payload);
  const headers = { 'content-type': 'application/json' };
  if (secret) headers['stripe-signature'] = stripeSignature(body, secret, timestamp);
  return call('POST', '/api/billing/webhook', { body, headers });
}

const skip = (cond, reason) => {
  if (!cond) throw Object.assign(new Error('skip: ' + reason), { skip: true });
};

/* --------------------------------- tests -------------------------------- */

test('health reports the engine present', async () => {
  const r = await call('GET', '/health');
  assert.equal(r.status, 200);
  assert.equal(r.json.data.engine, true);
});

test('landing page renders', async () => {
  const r = await call('GET', '/');
  assert.equal(r.status, 200);
  assert.match(r.text, /AI bẻ được app/);
});

test('scan page renders for anonymous', async () => {
  const r = await call('GET', '/scan');
  assert.match(r.text, /Kéo thả file/);
});

test('compare page renders', async () => {
  const r = await call('GET', '/compare');
  assert.equal(r.status, 200);
  assert.match(r.text, /So sánh trước \/ sau protect/);
});

test('compare API diffs two scan reports without a binary', async () => {
  const before = {
    file: 'a.exe', sha256: 'a'.repeat(64), kind: 'native', size: 100,
    crack_seconds_best: 70, crack_seconds_worst: 210, p_success: 0.35, risk: 21,
    read_budget_tokens: 60000, markers: [],
    findings: [{ id: 'pdb-path', detail: 'PDB path', weight: 15, fix: 'strip' }],
  };
  const after = {
    ...before, file: 'b.exe', sha256: 'b'.repeat(64),
    crack_seconds_best: 85, crack_seconds_worst: 255, p_success: 0.05, risk: 3, findings: [],
  };
  const r = await call('POST', '/api/compare', {
    body: JSON.stringify({ original: before, protected: after }),
    headers: { 'content-type': 'application/json' },
  });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.data.delta.seconds_best, 15);
  assert.equal(r.json.data.verdict, 'better');
  assert.equal(r.json.data.fixed_findings[0].id, 'pdb-path');

  const bad = await call('POST', '/api/compare', {
    body: '{oops',
    headers: { 'content-type': 'application/json' },
  });
  assert.equal(bad.status, 400, bad.text);
  assert.equal(bad.json.error.code, 'BAD_REPORT');
});

test('compare form renders a diff and rejects bad JSON', async () => {
  const before = {
    file: 'a.exe', sha256: 'a'.repeat(64), kind: 'native', size: 100,
    crack_seconds_best: 70, crack_seconds_worst: 210, p_success: 0.35, risk: 21,
    read_budget_tokens: 60000, markers: [],
    findings: [{ id: 'pdb-path', detail: 'PDB path', weight: 15, fix: 'strip' }],
  };
  const after = {
    ...before, file: 'b.exe', sha256: 'b'.repeat(64),
    crack_seconds_best: 85, crack_seconds_worst: 255, p_success: 0.05, risk: 3, findings: [],
  };
  const ok = await call('POST', '/compare', {
    body: new URLSearchParams({
      original: JSON.stringify(before),
      protected: JSON.stringify(after),
    }).toString(),
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  assert.equal(ok.status, 200, ok.text);
  assert.match(ok.text, /Leak đã vá/);
  assert.match(ok.text, /better/);

  const bad = await call('POST', '/compare', {
    body: new URLSearchParams({ original: '{oops', protected: '{}' }).toString(),
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  assert.equal(bad.status, 400);
  assert.match(bad.text, /JSON không hợp lệ/);
});

test('compare timeout is a 504, not a bad-report 400', async () => {
  const script = path.join(TMP, 'slow_cli.py');
  fs.writeFileSync(script, 'import time\ntime.sleep(2)\n');
  const savedCli = config.cli;
  const savedTimeout = config.compareTimeoutMs;
  config.cli = script;
  config.compareTimeoutMs = 100;
  try {
    const before = { crack_seconds_best: 70, p_success: 0.35, findings: [] };
    const after = { crack_seconds_best: 80, p_success: 0.05, findings: [] };
    const r = await call('POST', '/api/compare', {
      body: JSON.stringify({ original: before, protected: after }),
      headers: { 'content-type': 'application/json' },
    });
    assert.equal(r.status, 504, r.text);
    assert.equal(r.json.error.code, 'TIMEOUT');
  } finally {
    config.cli = savedCli;
    config.compareTimeoutMs = savedTimeout;
  }
});

test('static assets are served', async () => {
  const css = await call('GET', '/static/app.css');
  assert.equal(css.status, 200);
  assert.match(css.headers.get('content-type'), /text\/css/);
});

test('anonymous scan returns a summary with a shareable url', async () => {
  skip(fs.existsSync(NOTEPAD), 'no notepad.exe');
  const probe = path.join(TMP, 'anon-license.exe');
  fs.writeFileSync(
    probe,
    Buffer.concat([fs.readFileSync(NOTEPAD), Buffer.from('\nLicense expired: enter your serial key\n')])
  );
  const r = await upload(probe);
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.ok, true);
  assert.match(r.json.data.url, /^\/r\/[a-f0-9]+$/);
  assert.equal(typeof r.json.data.report.crack_seconds_best, 'number');

  const leaks = r.json.data.report.findings.filter((f) => f.weight > 0);
  assert.ok(leaks.length >= 1, 'the probe has at least one leak');
  assert.ok(leaks.length <= 2, 'anonymous response is limited to the top 2 leaks');
  assert.ok(leaks.every((f) => !('fix' in f)), 'no fix text in the anonymous response');
  assert.equal(r.json.data.report.redacted, true);
  assert.equal(
    r.json.data.report.file,
    path.basename(probe),
    'the report must not expose the server upload path'
  );
  lastReport = r.json.data;
});

test('public report is a summary, not the full fix list', async () => {
  skip(lastReport, 'no report');
  const r = await call('GET', lastReport.url);
  assert.equal(r.status, 200);
  assert.match(r.text, /Đăng nhập/); // paywall / CTA
});

test('anonymous daily quota is enforced', async () => {
  skip(fs.existsSync(HOSTNAME), 'no hostname.exe');
  const r = await upload(HOSTNAME);
  assert.equal(r.status, 429);
  assert.equal(r.json.error.code, 'ANON_LIMIT');
});

test('X-Forwarded-For cannot spoof the anonymous quota', async () => {
  skip(fs.existsSync(HOSTNAME), 'no hostname.exe');
  // nginx appends the real peer, so the old "first entry wins" logic let a
  // client supply its own address and scan forever. X-Forwarded-For is now
  // ignored entirely; the anonymous slot is still spent.
  const r = await upload(HOSTNAME, 'static', { 'x-forwarded-for': '203.0.113.9' });
  assert.equal(r.status, 429, r.text);
  assert.equal(r.json.error.code, 'ANON_LIMIT');
});

test('magic link login sets a session cookie', async () => {
  const req = await call('POST', '/api/auth/request?json=1', {
    body: JSON.stringify({ email: 'dev@studio.test' }),
    headers: { 'content-type': 'application/json' },
  });
  assert.equal(req.status, 200);
  const devUrl = req.json.data.devUrl;
  assert.ok(devUrl, 'dev url present without a mailer');
  const verify = await call('GET', devUrl.replace(base, ''));
  assert.equal(verify.status, 303);
  assert.ok(cookie.startsWith('tk_session='));
});

test('magic link is single use', async () => {
  const req = await call('POST', '/api/auth/request?json=1', {
    body: JSON.stringify({ email: 'dev@studio.test' }),
    headers: { 'content-type': 'application/json' },
  });
  const devUrl = req.json.data.devUrl.replace(base, '');
  const first = await call('GET', devUrl);
  assert.equal(first.status, 303);
  const second = await call('GET', devUrl);
  assert.equal(second.status, 400);
});

test('dashboard renders with credits', async () => {
  const r = await call('GET', '/app');
  assert.equal(r.status, 200);
  assert.match(r.text, /static scans còn lại/);
});

test('authenticated scan is stored under the account', async () => {
  skip(fs.existsSync(HOSTNAME), 'no hostname.exe');
  const r = await upload(HOSTNAME);
  assert.equal(r.status, 200, r.text);
  assert.match(r.json.data.url, /^\/app\/scan\/scn_/);
});

test('retention cleanup drops expired auth and stale rows, keeps accounts and fresh scans', async () => {
  const { db } = server.revscan;
  const account = db.prepare("SELECT * FROM accounts WHERE email='dev@studio.test'").get();
  assert.ok(account, 'login test must have created the account');
  const nowMs = Date.now();
  const oldMs = nowMs - (config.retentionDays + 5) * 86_400_000;
  const day = (ms) => new Date(ms).toISOString().slice(0, 10);
  const fresh = db.prepare('SELECT id FROM scans ORDER BY created_at DESC LIMIT 1').get();
  const accountsBefore = db.prepare('SELECT COUNT(*) AS c FROM accounts').get().c;

  db.prepare('INSERT INTO sessions (token_hash, account_id, created_at, expires_at) VALUES (?,?,?,?)').run(
    'retention-expired-session',
    account.id,
    oldMs,
    nowMs - 60_000
  );
  db.prepare(
    'INSERT INTO magic_links (token_hash, email, created_at, expires_at, used) VALUES (?,?,?,?,?)'
  ).run('retention-expired-link', account.email, oldMs, nowMs - 60_000, 0);
  db.prepare(
    'INSERT INTO magic_links (token_hash, email, created_at, expires_at, used) VALUES (?,?,?,?,?)'
  ).run('retention-used-link', account.email, oldMs, nowMs + 60_000, 1);
  db.prepare(
    `INSERT INTO scans (id, account_id, public_id, sha256, filename, size, kind, risk, crack_seconds,
                        p_success, mode, credits_used, ip_hash, report_json, created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).run(
    'scn_retention_old',
    account.id,
    'retentionold',
    'deadbeef',
    'old.exe',
    1,
    'pe',
    10,
    5,
    0.5,
    'static',
    1,
    null,
    '{}',
    oldMs
  );
  db.prepare('INSERT INTO events (id, type, account_id, payload, created_at) VALUES (?,?,?,?,?)').run(
    'evt_retention_old',
    'retention_probe',
    account.id,
    '{}',
    oldMs
  );
  db.prepare('INSERT INTO anon_scans (ip_hash, day, count) VALUES (?,?,?)').run(
    'retention-ip-hash',
    day(nowMs - 3 * 86_400_000),
    7
  );
  db.prepare(
    'INSERT INTO ledger (id, account_id, delta, bucket, reason, ref, created_at) VALUES (?,?,?,?,?,?,?)'
  ).run('led_retention_probe', account.id, 1, 'static', 'retention probe', null, oldMs);

  const counts = server.revscan.cleanup(nowMs);
  assert.ok(counts.sessions >= 1, 'expired session deleted');
  assert.ok(counts.magic_links >= 2, 'expired and used>24h magic links deleted');
  assert.ok(counts.scans >= 1, 'old scan deleted');
  assert.ok(counts.events >= 1, 'old event deleted');
  assert.ok(counts.anon_scans >= 1, 'old anon_scans row deleted');

  assert.equal(
    db.prepare("SELECT COUNT(*) AS c FROM sessions WHERE token_hash='retention-expired-session'").get().c,
    0
  );
  assert.equal(
    db.prepare("SELECT COUNT(*) AS c FROM magic_links WHERE token_hash LIKE 'retention-%'").get().c,
    0
  );
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM scans WHERE id='scn_retention_old'").get().c, 0);
  assert.equal(db.prepare("SELECT COUNT(*) AS c FROM events WHERE id='evt_retention_old'").get().c, 0);
  assert.equal(
    db.prepare("SELECT COUNT(*) AS c FROM anon_scans WHERE ip_hash='retention-ip-hash'").get().c,
    0
  );

  // Only data inside the retention window may be deleted.
  assert.ok(fresh, 'expected a fresh scan from an earlier test');
  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM scans WHERE id=?').get(fresh.id).c, 1);
  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM accounts').get().c, accountsBefore);
  assert.equal(
    db.prepare("SELECT COUNT(*) AS c FROM ledger WHERE id='led_retention_probe'").get().c,
    1,
    'ledger is the billing record and must never be swept'
  );
});

test('same file again is served from cache and costs nothing', async () => {
  const before = (await call('GET', '/app')).text;
  const r = await upload(HOSTNAME);
  assert.equal(r.status, 200);
  assert.equal(r.json.data.cached, true);
  const after = (await call('GET', '/app')).text;
  const grab = (html) => Number(/stat-num">(\d+)<\/div>\s*<div class="stat-label">static/.exec(html)?.[1]);
  assert.equal(grab(before), grab(after), 'credits must not change on a cache hit');

  const { db } = server.revscan;
  const account = db.prepare("SELECT id FROM accounts WHERE email='dev@studio.test'").get();
  const hits = db
    .prepare("SELECT COUNT(*) AS c FROM events WHERE type='cache_hit' AND account_id=?")
    .get(account.id).c;
  assert.ok(hits >= 1, 'a cache hit must leave an events row for the admin metric');
});

test('credits run out after the free allowance', async () => {
  const src = fs.readFileSync(HOSTNAME);
  let sawCreditError = false;
  for (let i = 0; i < 8; i += 1) {
    const tmp = path.join(TMP, `variant_${i}.exe`);
    fs.writeFileSync(tmp, Buffer.concat([src, Buffer.from(`variant-${i}-${Math.random()}`)]));
    const r = await upload(tmp);
    if (r.status === 402) {
      assert.equal(r.json.error.code, 'NO_CREDITS');
      sawCreditError = true;
      break;
    }
    assert.equal(r.status, 200, r.text);
  }
  assert.ok(sawCreditError, 'expected NO_CREDITS');
});

test('free owner sees summary with paywall, paid owner sees full report', async () => {
  const list = await call('GET', '/api/scans');
  assert.equal(list.status, 200);
  const first = list.json.data.scans[0];
  const freeView = await call('GET', `/app/scan/${first.id}`);
  assert.equal(freeView.status, 200);
  assert.match(freeView.text, /link công khai/, 'owner view exposes the share link');

  // Upgrade to Audit Pass and confirm the full report unlocks
  await call('POST', '/api/admin/grant', {
    body: JSON.stringify({ email: 'dev@studio.test', plan: 'audit' }),
    headers: { 'content-type': 'application/json', 'x-admin-key': 'test-admin-key' },
  });
  const paidView = await call('GET', `/app/scan/${first.id}`);
  assert.equal(paidView.status, 200);
  assert.doesNotMatch(paidView.text, /Còn <strong>/, 'paid owner view has no paywall');

  // Restore free for subsequent credit exhaustion test
  await call('POST', '/api/admin/grant', {
    body: JSON.stringify({ email: 'dev@studio.test', plan: 'free' }),
    headers: { 'content-type': 'application/json', 'x-admin-key': 'test-admin-key' },
  });
});

test('other accounts cannot read a scan by id', async () => {
  const list = await call('GET', '/api/scans');
  const scanId = list.json.data.scans[0].id;

  const savedCookie = cookie;
  cookie = '';
  await call('POST', '/api/auth/request?json=1', {
    body: JSON.stringify({ email: 'other@studio.test' }),
    headers: { 'content-type': 'application/json' },
  });
  // second account: request a fresh link and log in
  const req = await call('POST', '/api/auth/request?json=1', {
    body: JSON.stringify({ email: 'other@studio.test' }),
    headers: { 'content-type': 'application/json' },
  });
  await call('GET', req.json.data.devUrl.replace(base, ''));
  const r = await call('GET', `/app/scan/${scanId}`);
  assert.equal(r.status, 404);
  cookie = savedCookie;
});

test('admin can change a plan', async () => {
  const r = await call('POST', '/api/admin/grant', {
    body: JSON.stringify({ email: 'other@studio.test', plan: 'audit' }),
    headers: { 'content-type': 'application/json', 'x-admin-key': 'test-admin-key' },
  });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.data.account.plan, 'audit');
});

test('admin route rejects a wrong key', async () => {
  const r = await call('POST', '/api/admin/grant', {
    body: JSON.stringify({ email: 'other@studio.test', plan: 'annual' }),
    headers: { 'content-type': 'application/json', 'x-admin-key': 'nope' },
  });
  assert.equal(r.status, 401);
});

test('admin page takes the key via POST, not the query string', async () => {
  const form = new URLSearchParams({ key: 'test-admin-key' }).toString();

  const viaQuery = await call('GET', '/app/admin?key=test-admin-key', { headers: { cookie: '' } });
  assert.equal(viaQuery.status, 401, 'a key in the URL must not authorise');

  const post = await call('POST', '/app/admin', {
    body: form,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  assert.equal(post.status, 303);
  const adminCookie = (post.headers.get('set-cookie') || '').split(';')[0];
  assert.match(adminCookie, /^tk_admin=/);
  assert.match(post.headers.get('set-cookie') || '', /HttpOnly/);

  const page = await call('GET', '/app/admin', { headers: { cookie: adminCookie } });
  assert.equal(page.status, 200);
  assert.match(page.text, /Tài khoản/);
});

test('admin page shows recent scans and the real cache-hit count', async () => {
  const form = new URLSearchParams({ key: 'test-admin-key' }).toString();
  const post = await call('POST', '/app/admin', {
    body: form,
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  const adminCookie = (post.headers.get('set-cookie') || '').split(';')[0];

  const page = await call('GET', '/app/admin', { headers: { cookie: adminCookie } });
  assert.equal(page.status, 200);
  assert.match(page.text, /Scan gần đây/, 'the scan table must be rendered');

  const latest = server.revscan.db.prepare('SELECT id FROM scans ORDER BY created_at DESC LIMIT 1').get();
  assert.ok(latest, 'expected at least one scan');
  assert.ok(page.text.includes(latest.id), 'the most recent scan id is listed');

  const hits = server.revscan.db.prepare("SELECT COUNT(*) AS c FROM events WHERE type='cache_hit'").get().c;
  assert.ok(hits >= 1, 'the cache test wrote a cache_hit event');
  const shown = Number(
    /stat-num">(\d+)<\/div>\s*<div class="stat-label">cache hits/.exec(page.text)?.[1]
  );
  assert.equal(shown, hits, 'the stat must count cache_hit events, not anonymous zero-credit scans');
});

test('admin page rejects a wrong key POST', async () => {
  const r = await call('POST', '/app/admin', {
    body: new URLSearchParams({ key: 'nope' }).toString(),
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
  });
  assert.equal(r.status, 401);
});

test('malformed JSON on JSON APIs is a 400, not a 500', async () => {
  // `/api/compare` wraps readJson locally; auth, checkout and admin did not, so
  // they answered 500 INTERNAL for a body the client can fix.
  const cases = [
    ['/api/auth/request?json=1', { 'content-type': 'application/json' }],
    ['/api/billing/checkout', { 'content-type': 'application/json' }],
    ['/api/admin/grant', { 'content-type': 'application/json', 'x-admin-key': 'test-admin-key' }],
  ];
  for (const [url, headers] of cases) {
    const r = await call('POST', url, { body: '{oops', headers });
    assert.equal(r.status, 400, `${url}: ${r.status} ${r.text}`);
    assert.equal(r.json.error.code, 'BAD_JSON', url);
  }
});

test('empty upload is a 400, not a 500', async () => {
  const r = await call('POST', '/api/scan', {
    body: '',
    headers: { 'x-filename': 'app.exe', 'content-type': 'application/octet-stream' },
  });
  assert.equal(r.status, 400, r.text);
  assert.equal(r.json.error.code, 'EMPTY');
});

test('account deletion removes the email from magic links and events', async () => {
  const email = 'erase-me@studio.test';
  const req = await call('POST', '/api/auth/request?json=1', {
    body: JSON.stringify({ email }),
    headers: { 'content-type': 'application/json' },
  });
  assert.equal(req.status, 200, req.text);
  const devUrl = req.json.data.devUrl.replace(base, '');

  const savedCookie = cookie;
  const verify = await call('GET', devUrl);
  assert.equal(verify.status, 303);
  const del = await call('POST', '/api/account/delete');
  assert.equal(del.status, 303);
  cookie = savedCookie;

  const { db } = server.revscan;
  assert.equal(db.prepare('SELECT COUNT(*) AS c FROM accounts WHERE email=?').get(email).c, 0);
  assert.equal(
    db.prepare('SELECT COUNT(*) AS c FROM magic_links WHERE email=?').get(email).c,
    0,
    'pending magic links must not outlive the account'
  );
  assert.equal(
    db.prepare('SELECT COUNT(*) AS c FROM events WHERE payload LIKE ?').get(`%${email}%`).c,
    0,
    'the email must not survive inside an audit payload'
  );
});

test('upload sweeper survives a missing directory and removes old files', async () => {
  const dir = config.uploadsDir;
  fs.mkdirSync(dir, { recursive: true });
  const old = path.join(dir, 'sweep-probe.bin');
  fs.writeFileSync(old, 'x');
  const past = Date.now() - 2 * 3_600_000;
  fs.utimesSync(old, past / 1000, past / 1000);
  server.revscan.sweepUploads(3_600_000);
  assert.equal(fs.existsSync(old), false, 'an upload older than the sweep window is deleted');

  // A deleted/unmounted DATA_DIR used to throw from the interval callback and
  // take the web process down.
  const parked = `${dir}.parked`;
  fs.renameSync(dir, parked);
  try {
    assert.doesNotThrow(() => server.revscan.sweepUploads(3_600_000));
  } finally {
    fs.renameSync(parked, dir);
  }
});

test('invoice-mode checkout records the request instead of failing', async () => {
  const r = await call('POST', '/api/billing/checkout', {
    body: JSON.stringify({ plan: 'audit' }),
    headers: { 'content-type': 'application/json' },
  });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.data.invoice, true);
});

test('stripe webhook refuses unsigned events when no secret is configured', async () => {
  const saved = process.env.STRIPE_WEBHOOK_SECRET;
  delete process.env.STRIPE_WEBHOOK_SECRET;
  try {
    const r = await stripeWebhook(
      { id: 'evt_unsigned', type: 'checkout.session.completed', data: { object: {} } },
      { secret: null }
    );
    assert.equal(r.status, 503, r.text);
    assert.equal(r.json.error.code, 'WEBHOOK_UNCONFIGURED');
  } finally {
    if (saved === undefined) delete process.env.STRIPE_WEBHOOK_SECRET;
    else process.env.STRIPE_WEBHOOK_SECRET = saved;
  }
});

test('stripe webhook rejects a bad signature and a stale timestamp', async () => {
  process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test';
  try {
    const now = Math.floor(Date.now() / 1000);
    const bad = await call('POST', '/api/billing/webhook', {
      body: '{"id":"evt_bad","type":"x"}',
      headers: { 'content-type': 'application/json', 'stripe-signature': `t=${now},v1=deadbeef` },
    });
    assert.equal(bad.status, 400, bad.text);
    assert.equal(bad.json.error.code, 'BAD_SIGNATURE');

    const stale = await stripeWebhook(
      { id: 'evt_stale', type: 'x' },
      { timestamp: now - 3_600 }
    );
    assert.equal(stale.status, 400, stale.text);
    assert.equal(stale.json.error.code, 'BAD_SIGNATURE');
  } finally {
    delete process.env.STRIPE_WEBHOOK_SECRET;
  }
});

test('checkout sends the chosen plan to Stripe metadata (one-time vs subscription)', async () => {
  const savedKey = process.env.STRIPE_SECRET_KEY;
  const savedAudit = process.env.STRIPE_PRICE_AUDIT;
  const savedAnnual = process.env.STRIPE_PRICE_ANNUAL;
  process.env.STRIPE_SECRET_KEY = 'sk_test';
  process.env.STRIPE_PRICE_AUDIT = 'price_audit';
  process.env.STRIPE_PRICE_ANNUAL = 'price_annual';

  const originalFetch = global.fetch;
  let captured = '';
  global.fetch = async (url, opts) => {
    if (String(url).startsWith('https://api.stripe.com/')) {
      captured = String(opts.body || '');
      return { ok: true, json: async () => ({ url: 'https://checkout.stripe.test/session' }) };
    }
    return originalFetch(url, opts);
  };
  try {
    const auditRes = await call('POST', '/api/billing/checkout', {
      body: JSON.stringify({ plan: 'audit' }),
      headers: { 'content-type': 'application/json' },
    });
    assert.equal(auditRes.status, 200, auditRes.text);
    assert.match(captured, /mode=payment/, 'audit pass is a one-time payment');
    assert.match(captured, /metadata%5Bplan%5D=audit/);
    assert.doesNotMatch(captured, /subscription_data/, 'mode=payment must not send subscription_data');

    const r = await call('POST', '/api/billing/checkout', {
      body: JSON.stringify({ plan: 'annual' }),
      headers: { 'content-type': 'application/json' },
    });
    assert.equal(r.status, 200, r.text);
    assert.match(captured, /mode=subscription/);
    assert.match(captured, /metadata%5Bplan%5D=annual/, 'webhook needs the plan');
    assert.match(captured, /metadata%5Baccount_id%5D=acc_/, 'webhook needs the account');
    assert.match(
      captured,
      /subscription_data%5Bmetadata%5D%5Bplan%5D=annual/,
      'cancellation events carry subscription metadata'
    );
  } finally {
    global.fetch = originalFetch;
    if (savedKey === undefined) delete process.env.STRIPE_SECRET_KEY;
    else process.env.STRIPE_SECRET_KEY = savedKey;
    if (savedAudit === undefined) delete process.env.STRIPE_PRICE_AUDIT;
    else process.env.STRIPE_PRICE_AUDIT = savedAudit;
    if (savedAnnual === undefined) delete process.env.STRIPE_PRICE_ANNUAL;
    else process.env.STRIPE_PRICE_ANNUAL = savedAnnual;
  }
});

test('signed checkout applies the chosen plan and cancellation downgrades it', async () => {
  process.env.STRIPE_WEBHOOK_SECRET = 'whsec_checkout';
  try {
    const checkout = {
      id: 'evt_checkout_annual',
      type: 'checkout.session.completed',
      data: {
        object: {
          client_reference_id: null,
          customer_details: { email: 'dev@studio.test' },
          metadata: { plan: 'annual' },
          customer: 'cus_test_1',
          subscription: 'sub_test_1',
        },
      },
    };
    const r = await stripeWebhook(checkout, { secret: 'whsec_checkout' });
    assert.equal(r.status, 200, r.text);
    assert.match((await call('GET', '/app')).text, /gói <strong>Annual CI<\/strong>/);

    const replay = await stripeWebhook(checkout, { secret: 'whsec_checkout' });
    assert.equal(replay.status, 200, replay.text);
    assert.equal(replay.json.data.duplicate, true);

    const cancel = {
      id: 'evt_sub_cancel',
      type: 'customer.subscription.deleted',
      data: { object: { id: 'sub_test_1', status: 'canceled', customer: 'cus_test_1' } },
    };
    const c = await stripeWebhook(cancel, { secret: 'whsec_checkout' });
    assert.equal(c.status, 200, c.text);
    assert.match((await call('GET', '/app')).text, /gói <strong>Free<\/strong>/);
  } finally {
    delete process.env.STRIPE_WEBHOOK_SECRET;
  }
});

test('dev magic link is not exposed in production', async () => {
  const savedNode = process.env.NODE_ENV;
  const savedFlag = process.env.TRAPKEY_DEV_MAILER;
  const savedResend = process.env.RESEND_API_KEY;
  process.env.NODE_ENV = 'production';
  delete process.env.TRAPKEY_DEV_MAILER;
  delete process.env.RESEND_API_KEY;
  try {
    const r = await call('POST', '/api/auth/request?json=1', {
      body: JSON.stringify({ email: 'prod@studio.test' }),
      headers: { 'content-type': 'application/json' },
    });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.data.devUrl, undefined, 'production must not return the login URL');
  } finally {
    if (savedNode === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = savedNode;
    if (savedFlag === undefined) delete process.env.TRAPKEY_DEV_MAILER;
    else process.env.TRAPKEY_DEV_MAILER = savedFlag;
    if (savedResend === undefined) delete process.env.RESEND_API_KEY;
    else process.env.RESEND_API_KEY = savedResend;
  }
});

test('api token authenticates a CI scan', async () => {
  const tokenRes = await call('POST', '/api/api-token');
  assert.equal(tokenRes.status, 200);
  const token = /<pre>(tk_[A-Za-z0-9_-]+)<\/pre>/.exec(tokenRes.text)?.[1];
  assert.ok(token, 'token rendered once');

  const savedCookie = cookie;
  cookie = '';
  const r = await call('POST', '/api/scan?mode=static', {
    body: fs.readFileSync(NOTEPAD),
    headers: {
      'x-filename': 'ci.exe',
      authorization: `Bearer ${token}`,
      'content-type': 'application/octet-stream',
    },
  });
  cookie = savedCookie;
  // notepad was already scanned anonymously, but not by this account -> charged or ok
  assert.ok([200, 402].includes(r.status), r.text);
});

test('AI mode without a configured model is refused with a clear message', async () => {
  skip(fs.existsSync(NOTEPAD), 'no notepad.exe');
  const tmp = path.join(TMP, 'ai-mode.exe');
  fs.writeFileSync(tmp, Buffer.concat([fs.readFileSync(NOTEPAD), Buffer.from('ai-probe')]));
  const r = await upload(tmp, 'ai');
  assert.equal(r.status, 503);
  assert.equal(r.json.error.code, 'AI_UNAVAILABLE');
  assert.match(r.json.error.message, /OPENAI_API_KEY|ANTHROPIC_API_KEY|ollama/);
});

test('scan page disables the AI option when no model is configured', async () => {
  const r = await call('GET', '/scan');
  assert.match(r.text, /value="ai"\s+disabled/);
});

test('AI mode is not served from the static cache', async () => {
  skip(fs.existsSync(HOSTNAME), 'no hostname.exe');

  // Minimal OpenAI-compatible endpoint: returns a "found it" answer so the
  // engine's --ai path completes without network or tokens.
  const stub = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const body = JSON.stringify({
        choices: [{ message: { content: 'FUNCTION: 0x401000\nALGORITHM: xor\nPATCH: jmp' } }],
        usage: { prompt_tokens: 1, completion_tokens: 1 },
      });
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
      res.end(body);
    });
  });
  await new Promise((resolve) => stub.listen(0, '127.0.0.1', resolve));

  const savedBase = process.env.OPENAI_BASE_URL;
  const savedModel = process.env.TRAPKEY_AI_MODEL;
  process.env.OPENAI_BASE_URL = `http://127.0.0.1:${stub.address().port}/v1`;
  process.env.TRAPKEY_AI_MODEL = 'stub';
  try {
    // HOSTNAME was already scanned in static mode by this account: an AI
    // request must run the engine, not return that cached report.
    const r = await upload(HOSTNAME, 'ai');
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.data.cached, false, 'static cache must not answer an AI scan');
    assert.ok(r.json.data.report.measured, 'report carries the measured round');
    assert.equal(typeof r.json.data.report.measured.seconds, 'number');
    assert.equal(r.json.data.report.confidence, 'model+measured');

    // Same mode + same file now hits the cache for free.
    const again = await upload(HOSTNAME, 'ai');
    assert.equal(again.status, 200, again.text);
    assert.equal(again.json.data.cached, true);
  } finally {
    if (savedBase === undefined) delete process.env.OPENAI_BASE_URL;
    else process.env.OPENAI_BASE_URL = savedBase;
    if (savedModel === undefined) delete process.env.TRAPKEY_AI_MODEL;
    else process.env.TRAPKEY_AI_MODEL = savedModel;
    await new Promise((resolve) => stub.close(resolve));
  }
});

test('AI quota errors are reported as AI_QUOTA and refund the credit', async () => {
  skip(fs.existsSync(HOSTNAME), 'no hostname.exe');

  const grant = await call('POST', '/api/admin/grant', {
    body: JSON.stringify({ email: 'dev@studio.test', plan: 'audit' }),
    headers: { 'content-type': 'application/json', 'x-admin-key': 'test-admin-key' },
  });
  assert.equal(grant.status, 200, grant.text);

  const grabAi = (html) =>
    Number(/stat-num">(\d+)<\/div>\s*<div class="stat-label">AI-measured/.exec(html)?.[1]);
  const before = grabAi((await call('GET', '/app')).text);
  assert.ok(before > 0, 'the account needs AI credits for this test');

  // The gateway wraps the upstream Ollama 429 inside a 503; the engine must
  // classify the body, not just the status line.
  const stub = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      const body = JSON.stringify({
        error: { message: '[stub] [429]: weekly usage limit (reset after 2m 30s)' },
      });
      res.writeHead(429, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
      });
      res.end(body);
    });
  });
  await new Promise((resolve) => stub.listen(0, '127.0.0.1', resolve));

  const savedBase = process.env.OPENAI_BASE_URL;
  const savedModel = process.env.TRAPKEY_AI_MODEL;
  process.env.OPENAI_BASE_URL = `http://127.0.0.1:${stub.address().port}/v1`;
  process.env.TRAPKEY_AI_MODEL = 'stub';
  try {
    const tmp = path.join(TMP, `ai-quota-${Date.now()}.exe`);
    fs.writeFileSync(tmp, Buffer.concat([fs.readFileSync(HOSTNAME), Buffer.from('quota-probe')]));
    const r = await upload(tmp, 'ai');
    assert.equal(r.status, 429, r.text);
    assert.equal(r.json.error.code, 'AI_QUOTA');
    assert.match(r.json.error.message, /quota/i);
    assert.match(r.json.error.message, /150s/, 'retry-after is shown to the user');

    const after = grabAi((await call('GET', '/app')).text);
    assert.equal(after, before, 'a failed AI scan must refund the credit');

    // One quota 429 must stop the whole deployment from spawning engines that
    // discover the same 429. The window comes from the provider's retry-after.
    assert.equal(server.revscan.ai.coolingDown(), true);
    assert.ok(server.revscan.ai.until() > Date.now(), 'cooldown has a deadline');
    assert.ok(
      server.revscan.ai.until() <= Date.now() + 3_600_000 + 5_000,
      'a provider-controlled value must not pause AI for more than an hour'
    );

    const page = await call('GET', '/scan');
    assert.match(page.text, /value="ai"\s+disabled/, 'the AI radio is disabled while cooling');
    assert.match(page.text, /AI tạm nghỉ/);

    const blocked = await upload(tmp, 'ai');
    assert.equal(blocked.status, 429, blocked.text);
    assert.equal(blocked.json.error.code, 'AI_COOLDOWN');
    assert.match(blocked.json.error.message, /credit/);
    assert.equal(
      grabAi((await call('GET', '/app')).text),
      before,
      'a request refused by the cooldown must not spend a credit'
    );

    // Reset while the stub provider is still configured: the radio comes back.
    server.revscan.ai.reset();
    assert.equal(server.revscan.ai.coolingDown(), false);
    assert.doesNotMatch((await call('GET', '/scan')).text, /value="ai"\s+disabled/);
  } finally {
    if (savedBase === undefined) delete process.env.OPENAI_BASE_URL;
    else process.env.OPENAI_BASE_URL = savedBase;
    if (savedModel === undefined) delete process.env.TRAPKEY_AI_MODEL;
    else process.env.TRAPKEY_AI_MODEL = savedModel;
    await new Promise((resolve) => stub.close(resolve));
  }
});

test('engine failure does not leak stderr and the credit is refunded', async () => {
  skip(fs.existsSync(HOSTNAME), 'no hostname.exe');

  const grant = await call('POST', '/api/admin/grant', {
    body: JSON.stringify({ email: 'dev@studio.test', plan: 'audit' }),
    headers: { 'content-type': 'application/json', 'x-admin-key': 'test-admin-key' },
  });
  assert.equal(grant.status, 200, grant.text);

  const grab = (html) => Number(/stat-num">(\d+)<\/div>\s*<div class="stat-label">static/.exec(html)?.[1]);
  const before = grab((await call('GET', '/app')).text);

  const savedPython = config.python;
  config.python = 'definitely-not-a-python-binary';
  try {
    const probe = path.join(TMP, 'engine-fail.exe');
    fs.writeFileSync(probe, Buffer.concat([fs.readFileSync(HOSTNAME), Buffer.from('engine-fail')]));
    const r = await upload(probe);
    assert.equal(r.status, 422, r.text);
    assert.equal(r.json.error.code, 'ENGINE');
    assert.equal(r.json.error.message, 'engine could not read this file');
    assert.doesNotMatch(r.text, /Traceback|File "|\/mnt\/|site-packages/);
  } finally {
    config.python = savedPython;
  }

  const after = grab((await call('GET', '/app')).text);
  assert.equal(after, before, 'a failed scan must refund the credit');
});

test('invalid file extension is rejected', async () => {
  const r = await call('POST', '/api/scan', {
    body: Buffer.from('hello'),
    headers: { 'x-filename': 'notes.txt', 'content-type': 'application/octet-stream' },
  });
  assert.equal(r.status, 400);
  assert.equal(r.json.error.code, 'BAD_FILE');
});

test('unknown route is a clean 404', async () => {
  const api = await call('GET', '/api/nope');
  assert.equal(api.status, 404);
  assert.equal(api.json.error.code, 'NOT_FOUND');
  const page = await call('GET', '/nope');
  assert.equal(page.status, 404);
});

test('compare page escapes the measured model', () => {
  const side = (sha, measured = null) => ({
    file: 'App.exe',
    kind: 'dotnet',
    size: 1,
    sha256: sha,
    crack_seconds_best: 70,
    crack_seconds_worst: 140,
    p_success: 0.5,
    risk: 20,
    read_budget_tokens: 10,
    markers: [],
    findings: [],
    measured,
  });
  const result = {
    verdict: 'better',
    original: side('a'.repeat(64), { seconds: 8.5, success: true }),
    protected: side('b'.repeat(64), { seconds: 12, success: true }),
    delta: { seconds_best: 15, seconds_worst: 30, p_success: -0.2, risk: -10 },
    ai: {
      delta_seconds: 3.5,
      // The model comes from an uploaded report JSON, so it is untrusted.
      model: '<img src=x onerror=alert(1)>',
      verdict: 'measured: protected copy took +3.50s longer',
    },
    fixed_findings: [],
    new_findings: [],
    protection_added: [],
    changed_findings: [],
    protection_removed: [],
    notes: [],
  };
  const html = views.comparePage({ result });
  assert.ok(!html.includes('<img src=x'), 'the model must not become markup');
  assert.ok(html.includes('&lt;img src=x'), 'the model is still shown, escaped');
});

test('one-time audit pass expires to free after 30 days without renewing', () => {
  const { db } = server.revscan;
  const credits = require('../web/credits');
  const account = db.prepare("SELECT * FROM accounts WHERE email='other@studio.test'").get();
  assert.ok(account);
  const granted = credits.applyPlan(db, account, 'audit');
  assert.equal(granted.plan, 'audit');
  assert.equal(granted.credits_static, 10);
  assert.equal(granted.credits_ai, 3);

  // Backdate period_start by 31 days -> must revert to free, not reset audit
  db.prepare('UPDATE accounts SET period_start = ? WHERE id = ?').run(Date.now() - 31 * 86_400_000, granted.id);
  const expired = credits.refreshPeriod(db, db.prepare('SELECT * FROM accounts WHERE id = ?').get(granted.id));
  assert.equal(expired.plan, 'free');
  assert.equal(expired.credits_static, config.plans.free.staticCredits);
});

test('crack simulation renders redacted for free and full bytes for paid', () => {
  const report = {
    file: 'App.exe',
    kind: 'dotnet',
    size: 1024,
    risk: 85,
    p_success: 0.95,
    crack_seconds_best: 8,
    crack_seconds: {},
    model_notes: [],
    findings: [
      { id: 'f1', weight: 25, detail: 'd1', fix: 'fix1' },
      { id: 'f2', weight: 15, detail: 'd2', fix: 'fix2' },
      { id: 'f3', weight: 10, detail: 'd3', fix: 'fix3' },
    ],
    crack_simulation: {
      seconds: 8.2,
      model: 'gpt-6-luna',
      success: true,
      patch: {
        strategy: 'patch-branch',
        difficulty: 'TRIVIAL',
        patch_size: 2,
        offset: 0x0006,
        original: '2c05',
        patched: '2d05',
        method: 'LicenseManager::Validate',
        explanation: 'flip brfalse.s to brtrue.s',
        verified: true,
      },
    },
  };

  const summary = views.summaryReport(report);
  assert.equal(summary.findings.filter((f) => f.weight > 0).length, 2);
  assert.equal(summary.crack_simulation.patch.strategy, 'patch-branch');
  assert.equal(summary.crack_simulation.patch.original, undefined);
  assert.equal(summary.crack_simulation.patch.offset, undefined);

  const freeHtml = views.reportView(summary, { full: false, authenticated: true });
  assert.match(freeHtml, /CRACK SIMULATION/);
  assert.match(freeHtml, /patch-branch/);
  assert.match(freeHtml, /Audit Pass \(\$49\)/);
  assert.doesNotMatch(freeHtml, /2c05/);

  const paidHtml = views.reportView(report, { full: true, authenticated: true });
  assert.match(paidHtml, /2c05/);
  assert.match(paidHtml, /2d05/);
  assert.match(paidHtml, /LicenseManager::Validate/);
});

test('language switcher sets tk_lang cookie, renders English, and blocks open redirects', async () => {
  const sw = await call('GET', '/lang/en?next=%2Fpricing');
  assert.equal(sw.status, 303);
  assert.equal(sw.headers.get('location'), '/pricing');
  const langCookie = (sw.headers.get('set-cookie') || '').split(';')[0];
  assert.equal(langCookie, 'tk_lang=en');

  const enPricing = await call('GET', '/pricing', { headers: { cookie: langCookie } });
  assert.equal(enPricing.status, 200);
  assert.match(enPricing.text, /<html lang="en">/);
  assert.match(enPricing.text, /\$49<span> one-time<\/span>/);

  const evil = await call('GET', '/lang/en?next=//evil.test/phish');
  assert.equal(evil.status, 303);
  assert.equal(evil.headers.get('location'), '/');

  const ja = await call('GET', '/lang/ja?next=%2Fpricing');
  assert.equal(ja.status, 303);
  const jaCookie = (ja.headers.get('set-cookie') || '').split(';')[0];
  assert.equal(jaCookie, 'tk_lang=ja');
  const jaPricing = await call('GET', '/pricing', { headers: { cookie: jaCookie } });
  assert.equal(jaPricing.status, 200);
  assert.match(jaPricing.text, /<html lang="ja">/);

  const badLang = await call('GET', '/lang/xx?next=%2F');
  assert.equal(badLang.status, 404);
});

test('interactive demo gallery and /compare?demo=1 work end to end', async () => {
  const d1 = await call('GET', '/demo');
  assert.equal(d1.status, 200);
  assert.match(d1.text, /InvoicePro\.exe/);
  assert.match(d1.text, /CheckLicenseKey/);

  const d2 = await call('GET', '/demo?sample=protected');
  assert.equal(d2.status, 200);
  assert.match(d2.text, /InvoicePro\.protected\.exe/);
  assert.match(d2.text, /decoy-kit/);

  const d3 = await call('GET', '/demo?sample=compare');
  assert.equal(d3.status, 200);
  assert.match(d3.text, /InvoicePro\.protected\.exe/);

  const cmp = await call('GET', '/compare?demo=1');
  assert.equal(cmp.status, 200);
  assert.match(cmp.text, /InvoicePro\.exe/);
  assert.match(cmp.text, /InvoicePro\.protected\.exe/);
});

/* -------------------------------- runner -------------------------------- */
(async () => {
  // This suite uploads far more than 10 files in a minute; the upload rate
  // limit has its own behaviour and is not what these tests exercise.
  config.rate.uploadsPerHour = 10_000;
  server = createServer();
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  config.publicUrl = base; // magic links are generated with PUBLIC_URL

  let failed = 0;
  let skipped = 0;
  for (const t of tests) {
    try {
      await t.fn();
      console.log(`  ok   ${t.name}`);
    } catch (err) {
      if (err.skip) {
        skipped += 1;
        console.log(`  skip ${t.name} (${err.message})`);
      } else {
        failed += 1;
        console.log(`  FAIL ${t.name}`);
        console.log(`       ${err.message}`);
      }
    }
  }

  console.log(`\n${tests.length - failed - skipped} passed, ${failed} failed, ${skipped} skipped`);
  server.close();
  try {
    server.revscan?.db?.close();
  } catch {}
  try {
    fs.rmSync(TMP, { recursive: true, force: true });
  } catch {}
  process.exit(failed ? 1 : 0);
})();
