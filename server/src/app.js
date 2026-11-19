'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { openStore } = require('./store');
const {
  newProductKeys,
  signToken,
  verifyToken,
  randomKey,
  normalizeKey,
  timingSafeEqualStr,
  id,
} = require('./crypto');

const MAX_BODY = 64 * 1024;
const DEFAULT_TOKEN_TTL_DAYS = 7;

/* ------------------------------- helpers ------------------------------- */

function json(res, status, payload) {
  const body = Buffer.from(JSON.stringify(payload));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': body.length,
    'cache-control': 'no-store',
  });
  res.end(body);
}

const ok = (res, data, status = 200) => json(res, status, { ok: true, data });
const fail = (res, status, code, message) =>
  json(res, status, { ok: false, error: { code, message } });

function badRequest(res, message) {
  return fail(res, 400, 'BAD_REQUEST', message);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(Object.assign(new Error('body too large'), { code: 'PAYLOAD_TOO_LARGE' }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      if (!raw) return resolve({});
      try {
        const parsed = JSON.parse(raw);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return reject(Object.assign(new Error('body must be an object'), { code: 'BAD_REQUEST' }));
        }
        resolve(parsed);
      } catch {
        reject(Object.assign(new Error('invalid JSON'), { code: 'BAD_REQUEST' }));
      }
    });
    req.on('error', reject);
  });
}

function clampInt(value, fallback, min, max) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function keyStatus(key, now = Date.now()) {
  if (key.revokedAt) return 'revoked';
  if (key.expiresAt && key.expiresAt <= now) return 'expired';
  return 'active';
}

function publicKeyView(key, now) {
  return {
    key: key.key,
    productId: key.productId,
    createdAt: new Date(key.createdAt).toISOString(),
    expiresAt: key.expiresAt ? new Date(key.expiresAt).toISOString() : null,
    days: key.days,
    seats: key.seats,
    features: key.features,
    note: key.note || '',
    status: keyStatus(key, now),
    revokedAt: key.revokedAt ? new Date(key.revokedAt).toISOString() : null,
    revokeReason: key.revokeReason || null,
  };
}

/* ---------------------------- rate limiting ---------------------------- */

function makeRateLimiter() {
  const buckets = new Map();
  return function allow(ip, limit) {
    const now = Date.now();
    const windowMs = 60_000;
    let b = buckets.get(ip);
    if (!b || now - b.start >= windowMs) {
      b = { start: now, count: 0 };
      buckets.set(ip, b);
    }
    b.count += 1;
    if (buckets.size > 10_000) {
      for (const [k, v] of buckets) if (now - v.start >= windowMs) buckets.delete(k);
    }
    return b.count <= limit;
  };
}

/* ------------------------------- app ------------------------------- */

function createApp(options = {}) {
  const dataFile =
    options.dataFile || process.env.TRAPKEY_DATA || path.join(__dirname, '..', 'data', 'data.json');
  const store = openStore(dataFile);
  const adminKey = resolveAdminKey(path.dirname(store.file), options.adminKey);
  const allow = makeRateLimiter();

  const productById = (pid) => store.db.products.find((p) => p.id === pid) || null;
  const keyRecord = (raw) => {
    const normalized = normalizeKey(raw);
    return (
      store.db.keys.find((k) => k.key === normalized) ||
      store.db.keys.find((k) => k.key === String(raw).toUpperCase()) ||
      null
    );
  };
  const activeActivations = (keyStr) =>
    store.db.activations.filter((a) => a.key === keyStr && a.status === 'active');

  const routes = [];
  const route = (method, pattern, handler, opts = {}) =>
    routes.push({ method, pattern, handler, admin: !!opts.admin });

  route('GET', /^\/health$/, async (req, res) => {
    ok(res, {
      status: 'ok',
      time: new Date().toISOString(),
      products: store.db.products.length,
      keys: store.db.keys.length,
    });
  });

  /* ---------------- admin: products ---------------- */

  route(
    'POST',
    /^\/v1\/products$/,
    async (req, res, body) => {
      const name = String(body.name || '').trim();
      if (!name) return badRequest(res, 'name is required');
      if (name.length > 80) return badRequest(res, 'name too long');
      const keys = newProductKeys();
      const product = {
        id: id('prd'),
        name,
        createdAt: Date.now(),
        publicKeyPem: keys.publicKeyPem,
        privateKeyPem: keys.privateKeyPem,
        verifyKey: keys.verifyKey,
        tokenTtlDays: clampInt(body.tokenTtlDays, DEFAULT_TOKEN_TTL_DAYS, 1, 30),
      };
      store.db.products.push(product);
      store.save();
      return ok(res, productView(product), 201);
    },
    { admin: true }
  );

  route(
    'GET',
    /^\/v1\/products$/,
    async (req, res) => ok(res, store.db.products.map(productView)),
    { admin: true }
  );

  /* ---------------- admin: keys ---------------- */

  route(
    'POST',
    /^\/v1\/keys$/,
    async (req, res, body) => {
      const product = productById(String(body.productId || ''));
      if (!product) return fail(res, 404, 'NOT_FOUND', 'unknown productId');

      const count = clampInt(body.count, 1, 1, 500);
      const days = clampInt(body.days, 365, 1, 3650);
      const seats = clampInt(body.seats, 1, 1, 50);
      const features = Array.isArray(body.features)
        ? body.features.map((f) => String(f).slice(0, 24)).slice(0, 16)
        : [];

      const created = [];
      for (let i = 0; i < count; i += 1) {
        const record = {
          key: randomKey(),
          productId: product.id,
          createdAt: Date.now(),
          days,
          expiresAt: Date.now() + days * 86_400_000,
          seats,
          features,
          note: String(body.note || '').slice(0, 120),
          revokedAt: null,
          revokeReason: null,
        };
        store.db.keys.push(record);
        created.push(record.key);
      }
      store.save();
      return ok(res, { created, keys: created }, 201);
    },
    { admin: true }
  );

  route(
    'GET',
    /^\/v1\/keys$/,
    async (req, res, body, url) => {
      const productId = url.searchParams.get('productId');
      const status = url.searchParams.get('status');
      const limit = clampInt(url.searchParams.get('limit'), 200, 1, 1000);
      const now = Date.now();
      let rows = store.db.keys;
      if (productId) rows = rows.filter((k) => k.productId === productId);
      if (status) rows = rows.filter((k) => keyStatus(k, now) === status);
      return ok(res, rows.slice(-limit).map((k) => publicKeyView(k, now)).reverse());
    },
    { admin: true }
  );

  route(
    'POST',
    /^\/v1\/keys\/([^/]+)\/revoke$/,
    async (req, res, body, url, params) => {
      const record = keyRecord(params[0]);
      if (!record) return fail(res, 404, 'KEY_NOT_FOUND', 'key not found');
      record.revokedAt = record.revokedAt || Date.now();
      record.revokeReason = String(body.reason || '').slice(0, 200) || 'revoked by admin';
      for (const a of activeActivations(record.key)) a.status = 'revoked';
      store.save();
      return ok(res, publicKeyView(record));
    },
    { admin: true }
  );

  route(
    'POST',
    /^\/v1\/keys\/([^/]+)\/extend$/,
    async (req, res, body, url, params) => {
      const record = keyRecord(params[0]);
      if (!record) return fail(res, 404, 'KEY_NOT_FOUND', 'key not found');
      const days = clampInt(body.days, 0, 1, 3650);
      if (!days) return badRequest(res, 'days must be >= 1');
      const base = Math.max(record.expiresAt || Date.now(), Date.now());
      record.expiresAt = base + days * 86_400_000;
      record.days = (record.days || 0) + days;
      store.save();
      return ok(res, publicKeyView(record));
    },
    { admin: true }
  );

  route(
    'GET',
    /^\/v1\/activations$/,
    async (req, res, body, url) => {
      const key = url.searchParams.get('key');
      const productId = url.searchParams.get('productId');
      let rows = store.db.activations;
      if (key) rows = rows.filter((a) => a.key === normalizeKey(key));
      if (productId) rows = rows.filter((a) => a.productId === productId);
      return ok(
        res,
        rows
          .slice(-200)
          .map((a) => ({ ...a, createdAt: new Date(a.createdAt).toISOString() }))
          .reverse()
      );
    },
    { admin: true }
  );

  /* ---------------- public: licensing ---------------- */

  route('POST', /^\/v1\/activate$/, async (req, res, body) => {
    const product = productById(String(body.productId || ''));
    if (!product) return fail(res, 404, 'NOT_FOUND', 'unknown productId');

    const hwid = String(body.hwid || '')
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');
    if (hwid.length < 8 || hwid.length > 128) return badRequest(res, 'hwid is required');

    const record = keyRecord(body.key);
    if (!record) return fail(res, 404, 'KEY_NOT_FOUND', 'key not found');
    if (record.productId !== product.id) {
      return fail(res, 403, 'KEY_PRODUCT_MISMATCH', 'key does not belong to this product');
    }
    if (keyStatus(record) === 'revoked') {
      return fail(res, 403, 'KEY_REVOKED', 'key has been revoked');
    }
    if (keyStatus(record) === 'expired') {
      return fail(res, 403, 'KEY_EXPIRED', 'key has expired');
    }

    let activation = activeActivations(record.key).find((a) => a.hwid === hwid);
    if (!activation) {
      if (activeActivations(record.key).length >= record.seats) {
        return fail(res, 409, 'SEAT_LIMIT', `all ${record.seats} seat(s) are in use`);
      }
      activation = {
        id: id('act'),
        key: record.key,
        productId: record.productId,
        hwid,
        createdAt: Date.now(),
        lastSeenAt: Date.now(),
        appVersion: String(body.appVersion || '').slice(0, 32),
        status: 'active',
      };
      store.db.activations.push(activation);
    } else {
      activation.lastSeenAt = Date.now();
    }

    const claims = buildClaims(product, record, hwid);
    store.save();
    return ok(res, {
      license: signToken(claims, product.privateKeyPem),
      claims,
      serverTime: new Date().toISOString(),
    });
  });

  route('POST', /^\/v1\/validate$/, async (req, res, body) => {
    const license = body.license;
    const hwid = String(body.hwid || '')
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');
    if (!license) return badRequest(res, 'license is required');

    // Peek at claims (unverified) only to find the product; never trust it.
    const pid = peekProductId(license);
    const product = pid ? productById(pid) : null;
    if (!product) return fail(res, 400, 'BAD_REQUEST', 'unknown product in license');

    const verified = verifyToken(license, product.publicKeyPem);
    if (!verified.ok) return ok(res, { valid: false, reason: verified.reason });
    const claims = verified.claims;
    if (claims.exp * 1000 <= Date.now()) return ok(res, { valid: false, reason: 'EXPIRED' });
    if (hwid && claims.hwid !== hwid) return ok(res, { valid: false, reason: 'HWID_MISMATCH' });

    const record = keyRecord(claims.key);
    if (!record) return ok(res, { valid: false, reason: 'KEY_NOT_FOUND' });
    if (keyStatus(record) !== 'active') return ok(res, { valid: false, reason: 'KEY_REVOKED' });

    const activation = activeActivations(record.key).find((a) => a.hwid === claims.hwid);
    if (!activation) return ok(res, { valid: false, reason: 'DEACTIVATED' });
    activation.lastSeenAt = Date.now();
    store.save();

    // Slide the token forward so a long-lived install picks up new expiry dates.
    return ok(res, { valid: true, claims, refreshed: signToken(buildClaims(product, record, claims.hwid), product.privateKeyPem) });
  });

  route('POST', /^\/v1\/deactivate$/, async (req, res, body) => {
    const record = keyRecord(body.key);
    if (!record) return fail(res, 404, 'KEY_NOT_FOUND', 'key not found');
    const hwid = String(body.hwid || '')
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '');
    let released = 0;
    for (const a of activeActivations(record.key)) {
      if (!hwid || a.hwid === hwid) {
        a.status = 'deactivated';
        released += 1;
      }
    }
    store.save();
    return ok(res, { released });
  });

  /* ---------------- static admin UI ---------------- */

  const publicDir = path.join(__dirname, '..', 'public');
  route('GET', /^\/$/, async (req, res) => {
    const file = path.join(publicDir, 'index.html');
    if (!fs.existsSync(file)) return fail(res, 500, 'NO_UI', 'public/index.html missing');
    const html = fs.readFileSync(file);
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'content-length': html.length,
    });
    res.end(html);
  });

  /* ---------------- dispatch ---------------- */

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const pathname = url.pathname.replace(/\/+$/, '') || '/';
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?';

    try {
      const candidates = routes.filter((r) => r.method === req.method);
      let matched = null;
      let params = null;
      for (const r of candidates) {
        const m = pathname.match(r.pattern);
        if (m) {
          matched = r;
          params = m.slice(1).map(decodeURIComponent);
          break;
        }
      }
      if (!matched) return fail(res, 404, 'NOT_FOUND', 'no such route');

      if (!allow(ip, matched.admin ? 300 : 60)) {
        return fail(res, 429, 'RATE_LIMITED', 'too many requests');
      }

      if (matched.admin) {
        const given = req.headers['x-admin-key'] || '';
        if (!timingSafeEqualStr(given, adminKey)) {
          return fail(res, 401, 'UNAUTHORIZED', 'invalid x-admin-key');
        }
      }

      let body = {};
      if (req.method === 'POST') {
        try {
          body = await readBody(req);
        } catch (err) {
          if (err.code === 'PAYLOAD_TOO_LARGE') {
            return fail(res, 413, 'PAYLOAD_TOO_LARGE', 'body exceeds 64KB');
          }
          return badRequest(res, err.message);
        }
      }

      return await matched.handler(req, res, body, url, params);
    } catch (err) {
      console.error('[revscan] unhandled:', err);
      if (!res.headersSent) return fail(res, 500, 'INTERNAL', 'internal error');
      return res.end();
    }
  });

  server.revscan = { store, adminKey, dataFile: store.file };
  return server;
}

/* ------------------------------ utilities ------------------------------ */

function productView(p) {
  return {
    id: p.id,
    name: p.name,
    createdAt: new Date(p.createdAt).toISOString(),
    tokenTtlDays: p.tokenTtlDays,
    verifyKey: p.verifyKey,
    publicKeyPem: p.publicKeyPem,
  };
}

function buildClaims(product, record, hwid) {
  const now = Date.now();
  const ttlMs = product.tokenTtlDays * 86_400_000;
  const exp = Math.floor(Math.min(record.expiresAt || Infinity, now + ttlMs) / 1000);
  return {
    v: 1,
    pid: product.id,
    key: record.key,
    hwid,
    seats: record.seats,
    exp,
    iat: Math.floor(now / 1000),
    feat: record.features || [],
    tid: crypto.randomBytes(4).toString('hex'),
  };
}

function peekProductId(license) {
  try {
    const head = String(license).split('.')[0];
    const claims = JSON.parse(Buffer.from(head, 'base64url').toString('utf8'));
    return typeof claims.pid === 'string' ? claims.pid : null;
  } catch {
    return null;
  }
}

function resolveAdminKey(dir, override) {
  if (override) return override;
  if (process.env.TRAPKEY_ADMIN_KEY) return process.env.TRAPKEY_ADMIN_KEY;
  const file = path.join(dir, 'admin.key');
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
  const generated = crypto.randomBytes(24).toString('hex');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, generated, { mode: 0o600 });
  return generated;
}

module.exports = { createApp };
