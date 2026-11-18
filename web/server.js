'use strict';

const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function loadDotEnv(file = path.join(__dirname, '..', '.env')) {
  if (!fs.existsSync(file)) return;
  for (const raw of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || !line.includes('=')) continue;
    const eq = line.indexOf('=');
    const key = line.slice(0, eq).trim();
    const val = line.slice(eq + 1).trim().replace(/^['"]|['"]$/g, '');
    if (key && val && process.env[key] === undefined) {
      process.env[key] = val;
    }
  }
}

// Load root .env before requiring config.js when running as the standalone server.
if (require.main === module) loadDotEnv();

const config = require('./config');
const demo = require('./demo');
const dbModule = require('./db');
const auth = require('./auth');
const credits = require('./credits');
const { runEngine, runCompareReports, receiveUpload, sha256File } = require('./scanjob');
const views = require('./views');
const i18n = require('./i18n');

const { open, tx, id, now, ledger, event, cleanup: cleanupDb } = dbModule;

/* ------------------------------- helpers ------------------------------- */

const MIME = {
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function send(res, status, body, headers = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body));
  res.writeHead(status, {
    'content-length': buf.length,
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'same-origin',
    ...headers,
  });
  res.end(buf);
}

const html = (res, body, status = 200) =>
  send(res, status, body, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });

const json = (res, status, payload) =>
  send(res, status, JSON.stringify(payload), {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });

const ok = (res, data, status = 200) => json(res, status, { ok: true, data });
const fail = (res, status, code, message) => json(res, status, { ok: false, error: { code, message } });

const redirect = (res, location, cookies = []) => {
  const headers = { location };
  if (cookies.length) headers['set-cookie'] = cookies;
  send(res, 303, '', headers);
};

function readBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    let size = 0;
    let settled = false;
    const chunks = [];
    const fail = (err) => {
      if (settled) return;
      settled = true;
      chunks.length = 0;
      reject(err);
      // Drain instead of destroying the socket: the handler still needs to
      // send a clean 413. Memory is bounded by `limit`.
      req.resume();
    };
    req.on('data', (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size > limit) return fail(Object.assign(new Error('body too large'), { code: 'TOO_LARGE' }));
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks));
    });
    req.on('error', fail);
  });
}

async function readJson(req) {
  const raw = (await readBody(req)).toString('utf8').trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch {
    throw Object.assign(new Error('invalid JSON'), { code: 'BAD_JSON' });
  }
}

async function readForm(req, limit = 64 * 1024) {
  const raw = (await readBody(req, limit)).toString('utf8');
  return new URLSearchParams(raw);
}

/**
 * Only a reverse proxy on the same machine (or a private network) may tell us
 * the client address. Taking the first X-Forwarded-For entry let any client
 * spoof its IP: nginx appends the real peer, so the attacker-controlled value
 * stayed first. The nginx config writes the real peer into X-Real-IP.
 */
function isTrustedProxy(address) {
  if (!address) return false;
  const addr = address.replace(/^::ffff:/i, '');
  if (addr === '::1' || addr === '127.0.0.1') return true;
  const octets = addr.split('.').map(Number);
  if (octets.length === 4 && octets.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
    if (octets[0] === 10) return true;
    if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
    if (octets[0] === 192 && octets[1] === 168) return true;
    if (octets[0] === 169 && octets[1] === 254) return true;
  }
  return /^f[cd][0-9a-f]{2}:/i.test(addr);
}

function clientIp(req) {
  const peer = req.socket.remoteAddress || '';
  if (isTrustedProxy(peer)) {
    const real = String(req.headers['x-real-ip'] || '').trim();
    if (net.isIP(real)) return real;
  }
  return peer || 'unknown';
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

function makeLimiter() {
  const buckets = new Map();
  return function allow(key, limit, windowMs) {
    const t = Date.now();
    let b = buckets.get(key);
    if (!b || t - b.start >= windowMs) {
      b = { start: t, count: 0 };
      buckets.set(key, b);
    }
    b.count += 1;
    if (buckets.size > 20_000) {
      for (const [k, v] of buckets) if (t - v.start >= windowMs) buckets.delete(k);
    }
    return b.count <= limit;
  };
}

/* -------------------------------- mail -------------------------------- */

async function sendMagicLink(email, token) {
  const url = `${config.publicUrl}/auth/verify?token=${encodeURIComponent(token)}`;
  const text = `Đăng nhập TrapKey:\n\n${url}\n\nLink dùng một lần, hết hạn sau ${config.magicLinkMinutes} phút.`;

  if (process.env.RESEND_API_KEY) {
    try {
      await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${process.env.RESEND_API_KEY}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          from: process.env.MAIL_FROM || 'TrapKey <login@trapkey.dev>',
          to: [email],
          subject: 'Link đăng nhập TrapKey',
          text,
        }),
      });
      return { delivered: 'resend', url };
    } catch {
      /* fall through to outbox */
    }
  }

  fs.mkdirSync(config.outboxDir, { recursive: true });
  const file = path.join(config.outboxDir, `${Date.now()}_${email.replace(/[^a-z0-9]/gi, '_')}.txt`);
  fs.writeFileSync(file, text);
  return { delivered: 'outbox', file, url };
}

/* ------------------------------- billing ------------------------------- */

async function createCheckout(account, planId) {
  const plan = config.plans[planId];
  if (!plan || plan.id === 'free') {
    throw Object.assign(new Error('invalid plan'), { code: 'BAD_PLAN' });
  }
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) {
    return {
      invoice: true,
      message:
        'Đã ghi nhận yêu cầu nâng cấp. Thanh toán đang ở chế độ hoá đơn — chúng tôi sẽ gửi email trong 24h.',
    };
  }
  const body = new URLSearchParams({
    mode: plan.oneTime ? 'payment' : 'subscription',
    'line_items[0][price]': process.env[`STRIPE_PRICE_${planId.toUpperCase()}`] || '',
    'line_items[0][quantity]': '1',
    customer_email: account.email,
    client_reference_id: account.id,
    success_url: `${config.publicUrl}/app?upgraded=1`,
    cancel_url: `${config.publicUrl}/pricing`,
    // The webhook cannot see line items unless the session is expanded, and it
    // must not guess: without this every subscription (including Annual CI)
    // became the default plan.
    'metadata[plan]': plan.id,
    'metadata[account_id]': account.id,
  });
  if (!plan.oneTime) {
    // Stripe rejects subscription_data when mode=payment (one-time Audit Pass).
    // For recurring subscriptions, copy metadata onto the subscription so
    // later cancellation events can find the account too.
    body.set('subscription_data[metadata][plan]', plan.id);
    body.set('subscription_data[metadata][account_id]', account.id);
  }
  if (!body.get('line_items[0][price]')) {
    throw Object.assign(new Error('missing STRIPE_PRICE_' + planId.toUpperCase()), { code: 'CONFIG' });
  }
  const res = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST',
    headers: { authorization: `Bearer ${key}`, 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  const payload = await res.json();
  if (!res.ok) throw Object.assign(new Error(payload.error?.message || 'stripe error'), { code: 'STRIPE' });
  return { url: payload.url };
}

/** The plan was written by our own checkout call and the event is signed. */
function planFromSession(session) {
  const candidate = String(session?.metadata?.plan || '');
  if (candidate && candidate !== 'free' && config.plans[candidate]) return candidate;
  // Sessions without metadata: Audit Pass is the safer default than granting
  // Annual CI, which is the most expensive plan.
  return 'audit';
}

function accountForSubscription(db, subscription) {
  const id = subscription?.id ? String(subscription.id) : '';
  const metaId = subscription?.metadata?.account_id ? String(subscription.metadata.account_id) : '';
  const customer = typeof subscription?.customer === 'string' ? subscription.customer : '';
  return (
    (id && db.prepare('SELECT * FROM accounts WHERE stripe_subscription_id = ?').get(id)) ||
    (metaId && db.prepare('SELECT * FROM accounts WHERE id = ?').get(metaId)) ||
    (customer && db.prepare('SELECT * FROM accounts WHERE stripe_customer_id = ?').get(customer)) ||
    null
  );
}

function verifyStripeSignature(payload, header, secret, toleranceSeconds = 300) {
  let timestamp = null;
  const signatures = [];
  for (const part of String(header || '').split(',')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === 't') timestamp = value;
    else if (key === 'v1') signatures.push(value);
  }
  // Stripe rotates secrets and may sign with more than one; accept any match.
  if (!timestamp || !signatures.length) return false;
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > toleranceSeconds) return false;
  const expected = crypto.createHmac('sha256', secret).update(`${timestamp}.${payload}`).digest('hex');
  return signatures.some((signature) => safeEqual(expected, signature));
}

/* -------------------------------- AI errors ----------------------------- */

function aiFailureMessage(err) {
  const retry = Number(err.retryAfter);
  const wait = Number.isFinite(retry) && retry > 0 ? ` Thử lại sau ${retry}s.` : '';
  switch (err.code) {
    case 'AI_QUOTA':
      return `AI provider tạm hết quota.${wait || ' Thử lại sau vài phút.'}`;
    case 'AI_AUTH':
      return 'AI provider từ chối key (hết hạn hoặc không hợp lệ).';
    case 'AI_MODEL':
      return 'Model AI không còn khả dụng; cập nhật TRAPKEY_AI_MODEL.';
    case 'AI_CONFIG':
      return 'AI chưa được cấu hình.';
    case 'AI_EMPTY':
      return 'Model AI không trả nội dung; tăng TRAPKEY_AI_MAX_TOKENS.';
    case 'AI_PROVIDER':
      return `AI provider đang lỗi.${wait || ' Thử lại sau.'}`;
    default:
      return 'Không kết nối được AI provider.';
  }
}

/* -------------------------------- AI cooldown --------------------------- */

/**
 * Module-level, not per-request: an exhausted provider quota is a property of
 * the deployment, not of one client. Without this every upload kept spawning an
 * engine process that spent 20s to discover the same 429.
 */
const AI_COOLDOWN_FALLBACK_SECONDS = 300;
let aiCoolUntil = 0;

const aiCoolingDown = (at = Date.now()) => aiCoolUntil > at;
const aiCooldownSeconds = (at = Date.now()) =>
  aiCoolUntil > at ? Math.ceil((aiCoolUntil - at) / 1000) : 0;

function startAiCooldown(seconds) {
  const raw = Number(seconds);
  // A provider-controlled value must not disable AI for days because of a
  // malformed `reset after` string. One hour is the operator-friendly ceiling.
  const wait = Math.min(
    3_600,
    Number.isFinite(raw) && raw > 0 ? raw : AI_COOLDOWN_FALLBACK_SECONDS
  );
  aiCoolUntil = Date.now() + wait * 1000;
  return aiCoolUntil;
}

const resetAiCooldown = () => {
  aiCoolUntil = 0;
};

async function runReportComparison(original, protectedReport) {
  fs.mkdirSync(config.tmpDir, { recursive: true, mode: 0o700 });
  const tag = crypto.randomBytes(8).toString('hex');
  const before = path.join(config.tmpDir, `cmp_${tag}_before.json`);
  const after = path.join(config.tmpDir, `cmp_${tag}_after.json`);
  fs.writeFileSync(before, JSON.stringify(original), { mode: 0o600 });
  fs.writeFileSync(after, JSON.stringify(protectedReport), { mode: 0o600 });
  try {
    return await runCompareReports(before, after);
  } finally {
    await Promise.all([
      fs.promises.rm(before, { force: true }),
      fs.promises.rm(after, { force: true }),
    ]).catch(() => {});
  }
}

/* -------------------------------- server ______________________________ */

function createServer(options = {}) {
  const db = open(options.dbFile || config.dbFile);
  const allow = makeLimiter();

  for (const dir of [config.tmpDir, config.uploadsDir, config.outboxDir]) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // A crash mid-scan can leave an upload behind. Sweeping only at boot meant a
  // long-running process kept that file forever.
  const sweepOldUploads = (maxAgeMs = 3_600_000) => {
    for (const dir of [config.uploadsDir, config.tmpDir]) {
      let names = [];
      try {
        names = fs.readdirSync(dir);
      } catch {
        // A deleted/unmounted data dir must not throw from a timer callback and
        // take the whole web process down.
        continue;
      }
      for (const name of names) {
        const file = path.join(dir, name);
        try {
          if (Date.now() - fs.statSync(file).mtimeMs > maxAgeMs) fs.rmSync(file, { force: true });
        } catch {
          /* ignore */
        }
      }
    }
  };
  sweepOldUploads();
  const sweeper = setInterval(sweepOldUploads, 15 * 60_000);
  sweeper.unref();

  // Retention is a privacy promise, not just housekeeping, so it runs at boot
  // (a process that was down for a week must catch up) and every 6h.
  const runCleanup = (stamp = Date.now()) => {
    try {
      const removed = cleanupDb(db, stamp);
      const parts = Object.entries(removed)
        .filter(([, count]) => count > 0)
        .map(([table, count]) => `${table}=${count}`);
      if (parts.length) console.log(`[trapkey-web] retention cleanup: ${parts.join(' ')}`);
      return removed;
    } catch (err) {
      // A broken sweep must not kill the web process; the next tick retries.
      console.error(`[trapkey-web] retention cleanup failed: ${err.message}`);
      return {};
    }
  };
  runCleanup();
  const retention = setInterval(runCleanup, 6 * 3_600_000);
  retention.unref();

  if (!config.devMagicLink()) {
    console.warn(
      '[trapkey-web] production without RESEND_API_KEY: magic links are written to the outbox and cannot be delivered'
    );
  }

  const routes = [];
  const route = (method, pattern, handler, opts = {}) => routes.push({ method, pattern, handler, ...opts });

  /* ------------------------------ public ------------------------------ */

  route('GET', /^\/lang\/([a-z]{2})$/, (ctx, params) => {
    const code = String(params[0] || '').toLowerCase();
    if (!i18n.SUPPORTED.has(code)) {
      return html(ctx.res, views.notFound({ lang: ctx.lang, currentPath: ctx.currentPath }), 404);
    }
    const lang = i18n.normalizeLang(code);
    const rawNext = String(ctx.url.searchParams.get('next') || '/');
    const safeNext = rawNext.startsWith('/') && !rawNext.startsWith('//') && !rawNext.includes('\\') ? rawNext : '/';
    const attrs = [`tk_lang=${lang}`, 'Path=/', 'SameSite=Lax', 'Max-Age=31536000'];
    if (config.tls) attrs.push('Secure');
    redirect(ctx.res, safeNext, [attrs.join('; ')]);
  });

  route('GET', /^\/$/, (ctx) => html(ctx.res, views.landing({ lang: ctx.lang, currentPath: ctx.currentPath })));

  route('GET', /^\/demo$/, async (ctx) => {
    const sample = String(ctx.url.searchParams.get('sample') || 'dotnet').toLowerCase();
    let compareResult = null;
    if (sample === 'compare') {
      try {
        compareResult = await runReportComparison(
          demo.getSample('dotnet', ctx.lang),
          demo.getSample('protected', ctx.lang)
        );
      } catch {
        compareResult = demo.getCompareFallback(ctx.lang);
      }
    }
    html(
      ctx.res,
      views.demoPage({
        sample,
        compareResult,
        account: ctx.account,
        lang: ctx.lang,
        currentPath: ctx.currentPath,
      })
    );
  });

  route('GET', /^\/scan$/, (ctx) => {
    const ipHash = auth.hash(clientIp(ctx.req));
    const day = new Date().toISOString().slice(0, 10);
    const row = db.prepare('SELECT count FROM anon_scans WHERE ip_hash=? AND day=?').get(ipHash, day);
    const left = Math.max(0, config.anonymousPerDay - Number(row?.count || 0));
    const cooldown = aiCooldownSeconds();
    html(
      ctx.res,
      views.scanPage({
        account: ctx.account,
        anonymousLeft: left,
        // The radio is enabled only when a model exists *and* the provider is
        // not cooling down; showing "chưa cấu hình model" would be a lie.
        aiAvailable: config.aiAvailable() && !aiCoolingDown(),
        aiCooldownSeconds: cooldown,
        lang: ctx.lang,
        currentPath: ctx.currentPath,
      })
    );
  });

  route('GET', /^\/compare$/, async (ctx) => {
    if (ctx.url.searchParams.get('demo') === '1') {
      const orig = demo.getSample('dotnet', ctx.lang);
      const prot = demo.getSample('protected', ctx.lang);
      const originalText = JSON.stringify(orig, null, 2);
      const protectedText = JSON.stringify(prot, null, 2);
      let result = null;
      try {
        result = await runReportComparison(orig, prot);
      } catch {
        result = demo.getCompareFallback(ctx.lang);
      }
      return html(
        ctx.res,
        views.comparePage({
          result,
          originalText,
          protectedText,
          account: ctx.account,
          lang: ctx.lang,
          currentPath: ctx.currentPath,
        })
      );
    }
    html(ctx.res, views.comparePage({ account: ctx.account, lang: ctx.lang, currentPath: ctx.currentPath }));
  });

  route('POST', /^\/compare$/, async (ctx) => {
    const ipHash = auth.hash(clientIp(ctx.req));
    if (!allow(`compare:${ipHash}`, config.rate.comparesPerHour, 3_600_000)) {
      return html(ctx.res, views.comparePage({ error: 'Quá nhiều lần so sánh, thử lại sau.', account: ctx.account, lang: ctx.lang, currentPath: ctx.currentPath }), 429);
    }

    const form = await readForm(ctx.req, 512 * 1024);
    const originalText = String(form.get('original') || '');
    const protectedText = String(form.get('protected') || '');
    const keep = (text) => (text.length > 20_000 ? '' : text);
    if (!originalText.trim() || !protectedText.trim()) {
      return html(
        ctx.res,
        views.comparePage({
          error: 'Cần cả báo cáo trước và sau (JSON từ scan.py --json).',
          originalText: keep(originalText),
          protectedText: keep(protectedText),
          account: ctx.account,
          lang: ctx.lang,
          currentPath: ctx.currentPath,
        }),
        400
      );
    }

    let original;
    let protectedReport;
    try {
      original = JSON.parse(originalText);
      protectedReport = JSON.parse(protectedText);
      const result = await runReportComparison(original, protectedReport);
      return html(ctx.res, views.comparePage({ result, account: ctx.account, lang: ctx.lang, currentPath: ctx.currentPath }));
    } catch (err) {
      if (err.code === 'BUSY') {
        return html(ctx.res, views.comparePage({ error: 'Server đang bận, thử lại sau vài giây.', account: ctx.account, lang: ctx.lang, currentPath: ctx.currentPath }), 503);
      }
      if (err.code === 'TIMEOUT') {
        return html(
          ctx.res,
          views.comparePage({ error: 'So sánh quá lâu, thử lại sau. Báo cáo vẫn hợp lệ.', account: ctx.account, lang: ctx.lang, currentPath: ctx.currentPath }),
          504
        );
      }
      if (err.code === 'OUTPUT') {
        return html(
          ctx.res,
          views.comparePage({ error: 'Báo cáo quá lớn để xử lý.', account: ctx.account, lang: ctx.lang, currentPath: ctx.currentPath }),
          502
        );
      }
      if (err.code === 'COMPARE' || err instanceof SyntaxError) {
        console.error(`[compare] rejected report: ${String(err.message).slice(0, 200)}`);
        return html(
          ctx.res,
          views.comparePage({
            error: 'Báo cáo JSON không hợp lệ. Dùng đúng output của scan.py --json.',
            originalText: keep(originalText),
            protectedText: keep(protectedText),
            account: ctx.account,
            lang: ctx.lang,
            currentPath: ctx.currentPath,
          }),
          400
        );
      }
      throw err;
    }
  });

  route('POST', /^\/api\/compare$/, async (ctx) => {
    const ipHash = auth.hash(clientIp(ctx.req));
    if (!allow(`compare:${ipHash}`, config.rate.comparesPerHour, 3_600_000)) {
      return fail(ctx.res, 429, 'RATE_LIMITED', 'quá nhiều lần so sánh');
    }
    let body;
    try {
      body = await readJson(ctx.req);
    } catch (err) {
      if (err.code === 'BAD_JSON') {
        return fail(ctx.res, 400, 'BAD_REPORT', 'body phải là JSON {original, protected}');
      }
      if (err.code === 'TOO_LARGE') {
        return fail(ctx.res, 413, 'TOO_LARGE', 'body quá lớn');
      }
      throw err;
    }
    if (
      !body ||
      !body.original ||
      !body.protected ||
      typeof body.original !== 'object' ||
      typeof body.protected !== 'object'
    ) {
      return fail(ctx.res, 400, 'BAD_REPORT', 'cần {original, protected} là hai report JSON');
    }
    try {
      const result = await runReportComparison(body.original, body.protected);
      return ok(ctx.res, result);
    } catch (err) {
      if (err.code === 'BUSY') return fail(ctx.res, 503, 'BUSY', 'server đang bận');
      if (err.code === 'TIMEOUT') {
        return fail(ctx.res, 504, 'TIMEOUT', 'so sánh quá lâu, thử lại sau');
      }
      if (err.code === 'OUTPUT') {
        return fail(ctx.res, 502, 'OUTPUT', 'report quá lớn để xử lý');
      }
      if (err.code === 'COMPARE') {
        console.error(`[compare] rejected report: ${String(err.message).slice(0, 200)}`);
        return fail(ctx.res, 400, 'BAD_REPORT', 'report JSON không hợp lệ');
      }
      throw err;
    }
  });

  route('GET', /^\/pricing$/, (ctx) =>
    html(ctx.res, views.pricingPage({ account: ctx.account, lang: ctx.lang, currentPath: ctx.currentPath }))
  );
  route('GET', /^\/legal\/privacy$/, (ctx) =>
    html(ctx.res, views.privacyPage({ account: ctx.account, lang: ctx.lang, currentPath: ctx.currentPath }))
  );

  route('GET', /^\/docs\/calibration$/, (ctx) => {
    const file = path.join(config.root, 'docs', 'CALIBRATION.md');
    const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : 'not found';
    html(
      ctx.res,
      views.layout({
        title: 'Calibration',
        account: ctx.account,
        lang: ctx.lang,
        currentPath: ctx.currentPath,
        body: `<section class="panel prose"><h1>Calibration</h1><pre>${views.esc(text)}</pre></section>`,
      })
    );
  });

  route('GET', /^\/health$/, (ctx) => {
    const engine = fs.existsSync(config.engine);
    ok(ctx.res, { status: engine ? 'ok' : 'degraded', engine, db: true, time: new Date().toISOString() });
  });

  route('GET', /^\/static\/([a-z0-9._-]+)$/i, (ctx, params) => {
    const file = path.join(__dirname, 'static', path.basename(params[0]));
    if (!fs.existsSync(file)) return send(ctx.res, 404, 'not found');
    const ext = path.extname(file);
    send(ctx.res, 200, fs.readFileSync(file), {
      'content-type': MIME[ext] || 'application/octet-stream',
      'cache-control': ctx.url.searchParams.get('v') ? 'public, max-age=31536000, immutable' : 'no-cache',
    });
  });

  /* ------------------------------- auth ------------------------------- */

  route('POST', /^\/api\/auth\/request$/, async (ctx) => {
    const isJson = String(ctx.req.headers['content-type'] || '').includes('application/json');
    const payload = isJson ? await readJson(ctx.req) : null;
    const form = isJson ? null : await readForm(ctx.req);
    const email = String((isJson ? payload.email : form.get('email')) || '').toLowerCase().trim();
    const wantsJson = isJson || ctx.url.searchParams.get('json') === '1';

    const okShape = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
    if (!okShape) {
      return wantsJson ? fail(ctx.res, 400, 'BAD_EMAIL', 'email không hợp lệ') : redirect(ctx.res, '/login?error=bad-email');
    }
    if (!allow(`magic:${email}`, config.rate.magicLinksPerHour, 3_600_000)) {
      return wantsJson ? fail(ctx.res, 429, 'RATE_LIMITED', 'quá nhiều yêu cầu') : redirect(ctx.res, '/login?error=rate');
    }

    const { token } = auth.requestMagicLink(db, email);
    const delivery = await sendMagicLink(email, token);
    event(db, 'magic_link', null, { email, delivered: delivery.delivered });

    if (wantsJson) {
      // Never in production: this URL is a working login for any email address.
      const data = { sent: true, delivered: delivery.delivered };
      if (config.devMagicLink()) data.devUrl = delivery.url;
      return ok(ctx.res, data);
    }
    redirect(ctx.res, '/login?sent=1');
  });

  route('GET', /^\/auth\/verify$/, (ctx) => {
    const email = auth.consumeMagicLink(db, ctx.url.searchParams.get('token'));
    if (!email) {
      return html(
        ctx.res,
        views.errorPage('Link không hợp lệ hoặc đã hết hạn.', { lang: ctx.lang, currentPath: ctx.currentPath }),
        400
      );
    }
    const account = auth.ensureAccount(db, email);
    const session = auth.createSession(db, account.id);
    event(db, 'login', account.id, { email });
    redirect(ctx.res, '/app', [session.cookie]);
  });

  route('POST', /^\/api\/auth\/logout$/, (ctx) => {
    auth.destroySession(db, ctx.req.headers.cookie);
    redirect(ctx.res, '/', [auth.clearCookie()]);
  });

  route('GET', /^\/login$/, (ctx) => {
    html(
      ctx.res,
      views.loginPage({
        sent: ctx.url.searchParams.get('sent') === '1',
        error: ctx.url.searchParams.get('error') === 'rate' ? i18n.t(ctx.lang, 'loginRateError') : null,
        lang: ctx.lang,
        currentPath: ctx.currentPath,
      })
    );
  });

  /* -------------------------------- app ------------------------------- */

  route(
    'GET',
    /^\/app$/,
    (ctx) => {
      if (!ctx.account) return redirect(ctx.res, '/login');
      const scans = db
        .prepare('SELECT * FROM scans WHERE account_id=? ORDER BY created_at DESC LIMIT 30')
        .all(ctx.account.id);
      html(ctx.res, views.dashboard({ account: ctx.account, scans, lang: ctx.lang, currentPath: ctx.currentPath }));
    },
    { auth: true }
  );

  route(
    'GET',
    /^\/app\/scan\/([a-z0-9_]+)$/,
    (ctx, params) => {
      if (!ctx.account) return redirect(ctx.res, '/login');
      const scan = db.prepare('SELECT * FROM scans WHERE id=? AND account_id=?').get(params[0], ctx.account.id);
      if (!scan) return html(ctx.res, views.notFound({ account: ctx.account, lang: ctx.lang, currentPath: ctx.currentPath }), 404);
      const report = JSON.parse(scan.report_json);
      const isPaid = credits.isPaidAccount(ctx.account);
      html(
        ctx.res,
        views.layout({
          title: 'Report',
          account: ctx.account,
          active: 'app',
          lang: ctx.lang,
          currentPath: ctx.currentPath,
          body: views.reportView(report, {
            full: isPaid,
            authenticated: true,
            filename: scan.filename,
            shareUrl: `${config.publicUrl}/r/${scan.public_id}`,
            lang: ctx.lang,
          }),
        })
      );
    },
    { auth: true }
  );

  route(
    'GET',
    /^\/app\/settings$/,
    (ctx) => {
      if (!ctx.account) return redirect(ctx.res, '/login');
      html(ctx.res, views.settingsPage({ account: ctx.account, lang: ctx.lang, currentPath: ctx.currentPath }));
    },
    { auth: true }
  );

  const adminCookie = () => {
    const attrs = [
      `tk_admin=${encodeURIComponent(config.adminKey)}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      'Max-Age=3600',
    ];
    if (config.tls) attrs.push('Secure');
    return attrs.join('; ');
  };
  const adminForm = `<section class="panel"><h1>Admin</h1><p class="muted">Cần admin key.</p>
    <form method="post" action="/app/admin"><label>Admin key<input name="key" type="password" autocomplete="current-password"></label>
    <button class="btn">Vào</button></form></section>`;

  // The key is accepted in a POST body (or the x-admin-key header) and swapped
  // for an HttpOnly cookie. It used to travel in the query string, where it
  // ends up in access logs, browser history and referrers.
  route('POST', /^\/app\/admin$/, async (ctx) => {
    const form = await readForm(ctx.req);
    const key = form.get('key') || ctx.req.headers['x-admin-key'] || '';
    if (!safeEqual(key, config.adminKey)) {
      return html(ctx.res, views.layout({ title: 'Admin', body: adminForm }), 401);
    }
    redirect(ctx.res, '/app/admin', [adminCookie()]);
  });

  route('GET', /^\/app\/admin$/, (ctx) => {
    const cookies = auth.parseCookies(ctx.req.headers.cookie);
    const authorised = safeEqual(cookies.tk_admin || '', config.adminKey);

    if (!authorised) {
      return html(ctx.res, views.layout({ title: 'Admin', body: adminForm }), 401);
    }

    const accounts = db.prepare('SELECT * FROM accounts ORDER BY created_at DESC LIMIT 200').all();
    const accountCount = db.prepare('SELECT COUNT(*) AS c FROM accounts').get().c;
    const scans = db.prepare('SELECT COUNT(*) AS c FROM scans').get().c;
    const scans24h = db.prepare('SELECT COUNT(*) AS c FROM scans WHERE created_at > ?').get(now() - 86_400_000).c;
    const aiScans = db.prepare("SELECT COUNT(*) AS c FROM scans WHERE mode='ai'").get().c;
    // `credits_used = 0` used to stand in for "cache hit", but every anonymous
    // scan has 0 credits too, so the number measured the wrong thing entirely.
    // A real cache hit is now an event written by the authenticated cache path.
    const cacheHits = db.prepare("SELECT COUNT(*) AS c FROM events WHERE type='cache_hit'").get().c;
    const recent = db
      .prepare(
        `SELECT id, public_id, filename, risk, crack_seconds, mode, credits_used, created_at
         FROM scans ORDER BY created_at DESC LIMIT 50`
      )
      .all();
    const body = views.adminPage({
      accounts,
      scans: recent,
      stats: { accounts: accountCount, scans, scans24h, aiScans, cacheHits },
      lang: ctx.lang,
      currentPath: ctx.currentPath,
    });
    // This page lists customer emails and recent scan ids; never let a proxy
    // or browser serve a stale copy.
    send(ctx.res, 200, body, {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
    });
  });

  route(
    'POST',
    /^\/api\/api-token$/,
    (ctx) => {
      if (!ctx.account) return redirect(ctx.res, '/login');
      const { token } = auth.rotateApiToken(db, ctx.account.id);
      event(db, 'api_token_rotated', ctx.account.id, {});
      html(
        ctx.res,
        views.settingsPage({
          account: ctx.account,
          apiTokenHint: token,
          lang: ctx.lang,
          currentPath: ctx.currentPath,
        })
      );
    },
    { auth: true }
  );

  route(
    'POST',
    /^\/api\/account\/delete$/,
    (ctx) => {
      if (!ctx.account) return redirect(ctx.res, '/login');
      const email = ctx.account.email;
      tx(db, () => {
        db.prepare('DELETE FROM scans WHERE account_id=?').run(ctx.account.id);
        db.prepare('DELETE FROM sessions WHERE account_id=?').run(ctx.account.id);
        db.prepare('DELETE FROM ledger WHERE account_id=?').run(ctx.account.id);
        // Magic links are keyed by email, not account id, and login events were
        // written with a null account. Leaving them behind meant "delete my
        // account" kept the address in two places. Scrub the payloads (events
        // stay as an anonymous audit trail) and drop the pending links.
        db.prepare('DELETE FROM magic_links WHERE email=?').run(email);
        const stale = db.prepare('SELECT id, payload FROM events WHERE payload LIKE ?').all(`%${email}%`);
        const scrub = db.prepare("UPDATE events SET payload='{}' WHERE id=?");
        for (const row of stale) {
          if (String(row.payload).includes(email)) scrub.run(row.id);
        }
        db.prepare('DELETE FROM accounts WHERE id=?').run(ctx.account.id);
        event(db, 'account_deleted', null, {});
      });
      redirect(ctx.res, '/', [auth.clearCookie()]);
    },
    { auth: true }
  );

  /* ------------------------------- scan ------------------------------- */

  route('POST', /^\/api\/scan$/, async (ctx) => {
    const mode = ctx.url.searchParams.get('mode') === 'ai' ? 'ai' : 'static';
    const filename = String(ctx.req.headers['x-filename'] || 'upload.bin').slice(0, 120);
    const ext = path.extname(filename).toLowerCase();

    if (!config.allowedExt.has(ext)) {
      return fail(ctx.res, 400, 'BAD_FILE', 'chỉ nhận .exe, .dll, .bin, .sys');
    }

    // Fail before the client uploads 200MB to a mode we cannot serve.
    if (mode === 'ai' && !config.aiAvailable()) {
      return fail(
        ctx.res,
        503,
        'AI_UNAVAILABLE',
        'chế độ AI chưa cấu hình. Đặt OPENAI_API_KEY, ANTHROPIC_API_KEY, ' +
          'OLLAMA_API_KEY (Ollama Cloud) hoặc TRAPKEY_AI_PROVIDER=ollama để dùng model local.'
      );
    }

    // Same reason as above, but transient: a quota 429 from the provider must
    // not be re-discovered once per upload. Checked before `receiveUpload`, so
    // a cooling request costs no disk, no engine process and no credit.
    if (mode === 'ai' && aiCoolingDown()) {
      return fail(
        ctx.res,
        429,
        'AI_COOLDOWN',
        `AI provider vừa hết quota, đang tạm nghỉ ${aiCooldownSeconds()}s. ` +
          'Thử lại sau — credit không bị trừ.'
      );
    }

    const ipHash = auth.hash(clientIp(ctx.req));
    if (!allow(`upload:${ipHash}`, config.rate.uploadsPerHour, 3_600_000)) {
      return fail(ctx.res, 429, 'RATE_LIMITED', 'quá nhiều upload, thử lại sau');
    }

    // Reserve the anonymous slot before streaming the body. The check used to
    // run after the upload, so an out-of-quota client could still push 150MB
    // per request to disk. A failed scan gives the slot back in `finally`.
    let anonymousReserved = false;
    if (!ctx.account) {
      const quota = credits.allowAnonymous(db, ipHash);
      if (!quota.ok) {
        return fail(
          ctx.res,
          429,
          'ANON_LIMIT',
          `khách vãng lai được ${quota.limit} lượt/ngày. Đăng nhập để scan thêm.`
        );
      }
      anonymousReserved = true;
    }

    let upload = null;
    let committed = false;
    try {
      upload = await receiveUpload(ctx.req);
      const sha256 = await sha256File(upload.path);

      // Cache: same account, same file, same mode, within the window -> free.
      // `mode` is part of the key: without it an AI request was served the
      // static report from an earlier scan (and charged nothing).
      if (ctx.account) {
        const cached = db
          .prepare(
            'SELECT * FROM scans WHERE account_id=? AND sha256=? AND mode=? AND created_at > ? ORDER BY created_at DESC LIMIT 1'
          )
          .get(ctx.account.id, sha256, mode, now() - config.cacheHours * 3_600_000);
        if (cached) {
          committed = true;
          // Audit trail for the admin "cache hits" stat. Without an event the
          // only signal was `credits_used = 0`, which anonymous scans share.
          event(db, 'cache_hit', ctx.account.id, { sha256, mode, scan_id: cached.id });
          const cachedReport = JSON.parse(cached.report_json);
          const isPaid = credits.isPaidAccount(ctx.account);
          return ok(ctx.res, {
            id: cached.id,
            url: `/app/scan/${cached.id}`,
            publicId: cached.public_id,
            cached: true,
            report: isPaid ? cachedReport : views.summaryReport(cachedReport),
          });
        }
      }

      const scanId = id('scn');

      if (ctx.account) {
        // Keep the spend row linked to the scan id so a refund is auditable.
        const spent = credits.spend(db, ctx.account, mode, scanId);
        if (!spent.ok) {
          return fail(ctx.res, 402, 'NO_CREDITS', `hết credit ${mode}. Nâng cấp gói hoặc chờ reset.`);
        }
      }

      let report;
      try {
        report = await runEngine(upload.path, { mode });
      } catch (err) {
        if (ctx.account) credits.refund(db, ctx.account, mode, scanId, `scan failed: ${err.code || 'error'}`);
        if (String(err.code || '').startsWith('AI_')) {
          // Keep the provider body in the server log, not in the response:
          // it can contain account names and upstream URLs.
          console.error(`[scan ${scanId}] ${err.code}: ${String(err.message).slice(0, 300)}`);
          // A provider quota error applies to everyone, so stop spawning
          // engines for AI until it clears. `retryAfter` is what the provider
          // told us; fall back to 5 minutes when it said nothing.
          if (err.code === 'AI_QUOTA') startAiCooldown(err.retryAfter);
          return fail(
            ctx.res,
            err.code === 'AI_QUOTA' ? 429 : 503,
            err.code,
            aiFailureMessage(err)
          );
        }
        if (err.code === 'BUSY') {
          return fail(ctx.res, 503, 'BUSY', 'server đang scan nhiều file, thử lại sau vài giây');
        }
        if (err.code === 'ENGINE') {
          // stderr includes a Python traceback and absolute paths; keep it in
          // the server log, never in an HTTP response.
          console.error(`[scan ${scanId}] engine failed: ${String(err.message).split('\n').slice(0, 4).join(' | ')}`);
          return fail(ctx.res, 422, 'ENGINE', 'engine could not read this file');
        }
        return fail(
          ctx.res,
          err.code === 'TIMEOUT' ? 504 : 422,
          err.code || 'ENGINE',
          err.message || 'engine error'
        );
      }

      // `scan.py` reports the path it was given, which on the server is a temp
      // upload path. Do not publish server internals in a shared JSON report.
      report.file = path.basename(filename) || path.basename(String(report.file || 'upload.bin'));

      const publicId = crypto.randomBytes(6).toString('hex');
      db.prepare(
        `INSERT INTO scans (id, account_id, public_id, sha256, filename, size, kind, risk,
                            crack_seconds, p_success, mode, credits_used, ip_hash, report_json, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
      ).run(
        scanId,
        ctx.account ? ctx.account.id : null,
        publicId,
        sha256,
        filename,
        upload.size,
        report.kind,
        report.risk,
        report.crack_seconds_best,
        report.p_success,
        mode,
        ctx.account ? 1 : 0,
        ipHash,
        JSON.stringify(report),
        now()
      );
      committed = true;

      const isPaid = credits.isPaidAccount(ctx.account);
      return ok(ctx.res, {
        id: scanId,
        publicId,
        url: ctx.account ? `/app/scan/${scanId}` : `/r/${publicId}`,
        cached: false,
        // Paid plans get the full report + patch bytes; free and anonymous get the summary.
        report: isPaid ? report : views.summaryReport(report),
      });
    } finally {
      if (upload) upload.cleanup();
      if (anonymousReserved && !committed) credits.refundAnonymous(db, ipHash);
    }
  });

  /* ----------------------------- public report ------------------------ */

  route('GET', /^\/r\/([a-f0-9]+)$/, (ctx, params) => {
    const scan = db.prepare('SELECT * FROM scans WHERE public_id=?').get(params[0]);
    if (!scan) return html(ctx.res, views.notFound({ account: ctx.account, lang: ctx.lang, currentPath: ctx.currentPath }), 404);
    const isOwner = ctx.account && scan.account_id === ctx.account.id;
    const isPaid = isOwner && credits.isPaidAccount(ctx.account);
    const report = JSON.parse(scan.report_json);
    const body = views.reportView(report, {
      full: isPaid,
      authenticated: Boolean(ctx.account),
      filename: views.redact(scan.filename),
      lang: ctx.lang,
    });
    html(
      ctx.res,
      views.layout({ title: 'Report', body, account: ctx.account, active: 'scan', lang: ctx.lang, currentPath: ctx.currentPath })
    );
  });

  /* -------------------------------- api ------------------------------- */

  route(
    'GET',
    /^\/api\/scans$/,
    (ctx) => {
      if (!ctx.account) return fail(ctx.res, 401, 'UNAUTHORIZED', 'login required');
      const rows = db
        .prepare(
          'SELECT id, public_id, filename, kind, risk, crack_seconds, p_success, mode, created_at FROM scans WHERE account_id=? ORDER BY created_at DESC LIMIT 50'
        )
        .all(ctx.account.id);
      ok(ctx.res, { scans: rows });
    },
    { auth: true }
  );

  route(
    'GET',
    /^\/api\/report\/([a-z0-9_]+)$/,
    (ctx, params) => {
      if (!ctx.account) return fail(ctx.res, 401, 'UNAUTHORIZED', 'login required');
      const scan = db.prepare('SELECT * FROM scans WHERE id=? AND account_id=?').get(params[0], ctx.account.id);
      if (!scan) return fail(ctx.res, 404, 'NOT_FOUND', 'no such scan');
      const raw = JSON.parse(scan.report_json);
      const isPaid = credits.isPaidAccount(ctx.account);
      ok(ctx.res, {
        scan: { ...scan, report_json: undefined },
        report: isPaid ? raw : views.summaryReport(raw),
      });
    },
    { auth: true }
  );

  /* ------------------------------ billing ----------------------------- */

  route(
    'POST',
    /^\/api\/billing\/checkout$/,
    async (ctx) => {
      if (!ctx.account) return fail(ctx.res, 401, 'UNAUTHORIZED', 'login required');
      const body = await readJson(ctx.req);
      try {
        const result = await createCheckout(ctx.account, String(body.plan || ''));
        event(db, 'checkout_started', ctx.account.id, { plan: body.plan, invoice: !!result.invoice });
        return ok(ctx.res, result);
      } catch (err) {
        return fail(ctx.res, 400, err.code || 'CHECKOUT', err.message);
      }
    },
    { auth: true }
  );

  route('POST', /^\/api\/billing\/webhook$/, async (ctx) => {
    // Not `if (secret)`: a deployment that set only STRIPE_SECRET_KEY would
    // accept unsigned events, and anyone could grant themselves a plan. The
    // endpoint is closed until the operator configures the signing secret.
    const secret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!secret) {
      return fail(
        ctx.res,
        503,
        'WEBHOOK_UNCONFIGURED',
        'STRIPE_WEBHOOK_SECRET is not set; refusing unsigned webhook events'
      );
    }

    const raw = await readBody(ctx.req, 256 * 1024);
    const body = raw.toString('utf8');
    if (!verifyStripeSignature(body, ctx.req.headers['stripe-signature'], secret)) {
      return fail(ctx.res, 400, 'BAD_SIGNATURE', 'signature mismatch');
    }

    let payload;
    try {
      payload = JSON.parse(body);
    } catch {
      return fail(ctx.res, 400, 'BAD_JSON', 'invalid payload');
    }

    const eventId = String(payload.id || `manual_${Date.now()}`);
    const seen = db.prepare('SELECT id FROM events WHERE id=?').get(eventId);
    if (seen) return ok(ctx.res, { duplicate: true }); // idempotent

    let account = null;
    let detail = {};

    if (payload.type === 'checkout.session.completed') {
      const session = payload.data?.object || {};
      const accountId = String(session.metadata?.account_id || session.client_reference_id || '');
      const email = String(session.customer_details?.email || '').toLowerCase();
      account =
        (accountId && db.prepare('SELECT * FROM accounts WHERE id=?').get(accountId)) ||
        (email && db.prepare('SELECT * FROM accounts WHERE email=?').get(email)) ||
        null;

      if (account) {
        const plan = planFromSession(session);
        credits.applyPlan(db, account, plan);
        db.prepare(
          'UPDATE accounts SET stripe_customer_id=?, stripe_subscription_id=? WHERE id=?'
        ).run(
          session.customer ? String(session.customer) : null,
          session.subscription ? String(session.subscription) : null,
          account.id
        );
        detail = { plan };
      }
    } else if (
      payload.type === 'customer.subscription.deleted' ||
      (payload.type === 'customer.subscription.updated' &&
        ['canceled', 'unpaid', 'incomplete_expired'].includes(
          String(payload.data?.object?.status || '')
        ))
    ) {
      const subscription = payload.data?.object || {};
      account = accountForSubscription(db, subscription);
      if (account) {
        const wasPaid = account.plan !== 'free';
        if (wasPaid) credits.applyPlan(db, account, 'free');
        db.prepare('UPDATE accounts SET stripe_subscription_id=NULL WHERE id=?').run(account.id);
        detail = { plan: 'free', cancelled: true };
      }
    }

    // INSERT OR IGNORE: two deliveries of the same event must not turn a
    // handled event into a 500 after the plan was already applied.
    db.prepare(
      'INSERT OR IGNORE INTO events (id, type, account_id, payload, created_at) VALUES (?,?,?,?,?)'
    ).run(eventId, String(payload.type || 'unknown'), account ? account.id : null, JSON.stringify(detail), now());

    ok(ctx.res, { received: true });
  });

  /* ------------------------------- admin ------------------------------ */

  route('POST', /^\/api\/admin\/grant$/, async (ctx) => {
    if (!safeEqual(ctx.req.headers['x-admin-key'] || '', config.adminKey)) {
      return fail(ctx.res, 401, 'UNAUTHORIZED', 'invalid admin key');
    }
    const body = await readJson(ctx.req);
    const email = String(body.email || '').toLowerCase();
    const plan = String(body.plan || 'free');
    const account = db.prepare('SELECT * FROM accounts WHERE email=?').get(email);
    if (!account) return fail(ctx.res, 404, 'NOT_FOUND', 'account not found');
    const updated = credits.applyPlan(db, account, plan);
    event(db, 'admin_grant', updated.id, { plan });
    ok(ctx.res, { account: { email: updated.email, plan: updated.plan } });
  });

  /* ------------------------------ dispatch ---------------------------- */

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname.replace(/\/+$/, '') || '/';
    const lang = i18n.langFromRequest(url, req.headers.cookie, auth.parseCookies);

    try {
      if (!allow(`req:${auth.hash(clientIp(req))}`, config.rate.requestsPerMinute, 60_000)) {
        return pathname.startsWith('/api/')
          ? fail(res, 429, 'RATE_LIMITED', 'too many requests')
          : send(res, 429, 'too many requests');
      }

      const matched = [];
      for (const r of routes) {
        if (r.method !== req.method) continue;
        const m = pathname.match(r.pattern);
        if (m) matched.push({ route: r, params: m.slice(1) });
      }
      if (!matched.length) {
        return pathname.startsWith('/api/')
          ? fail(res, 404, 'NOT_FOUND', 'no such route')
          : html(res, views.notFound({ lang, currentPath: pathname }), 404);
      }
      const { route: r, params } = matched[0];

      let account = auth.accountFromSession(db, req.headers.cookie);
      if (!account) account = auth.accountFromApiToken(db, req.headers.authorization);
      if (account) account = credits.refreshPeriod(db, account);

      const ctx = { req, res, url, account, lang, currentPath: pathname };
      return await r.handler(ctx, params.map(decodeURIComponent));
    } catch (err) {
      if (err.code === 'TOO_LARGE') {
        return pathname.startsWith('/api/')
          ? fail(res, 413, 'TOO_LARGE', 'file quá lớn')
          : send(res, 413, 'too large');
      }
      // `readJson` throws this from routes that do not wrap it locally (auth,
      // checkout, admin grant). Without this mapping a malformed body was a
      // 500 INTERNAL, which tells the client the server broke instead of its
      // request.
      if (err.code === 'BAD_JSON') {
        return pathname.startsWith('/api/')
          ? fail(res, 400, 'BAD_JSON', 'body phải là JSON hợp lệ')
          : send(res, 400, 'bad JSON');
      }
      // An empty body or a client that vanished mid-upload is bad input, not
      // an internal error. The scan route has already refunded the quota.
      if (err.code === 'EMPTY' || err.code === 'UPLOAD') {
        return pathname.startsWith('/api/')
          ? fail(res, 400, err.code, err.message || 'upload không hợp lệ')
          : send(res, 400, err.message || 'upload không hợp lệ');
      }
      console.error('[trapkey-web]', err);
      if (res.headersSent) return res.end();
      return pathname.startsWith('/api/')
        ? fail(res, 500, 'INTERNAL', 'internal error')
        : html(res, views.errorPage(lang === 'en' ? 'Internal error.' : 'Lỗi hệ thống.', { lang, currentPath: pathname }), 500);
    }
  });

  server.trapkey = {
    db,
    config,
    cleanup: (stamp) => runCleanup(stamp),
    sweepUploads: (maxAgeMs) => sweepOldUploads(maxAgeMs),
    ai: {
      reset: resetAiCooldown,
      coolingDown: aiCoolingDown,
      until: () => aiCoolUntil,
    },
  };
  return server;
}

module.exports = { createServer };

if (require.main === module) {
  const server = createServer();
  server.listen(config.port, config.host, () => {
    console.log('');
    console.log('  TrapKey web');
    console.log(`  url   : http://${config.host === '0.0.0.0' ? '127.0.0.1' : config.host}:${config.port}`);
    console.log(`  data  : ${config.dataDir}`);
    console.log(`  admin : /app/admin  (key: ADMIN_KEY or ${path.join(config.dataDir, 'admin.key')})`);
    console.log('');
  });
}
