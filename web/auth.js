'use strict';

const crypto = require('node:crypto');

const config = require('./config');
const { id, now, tx } = require('./db');

const hash = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

function randomToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim();
    if (!key) continue;
    out[key] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

function sessionCookie(value, maxAgeSeconds) {
  const attrs = [
    `tk_session=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (config.tls) attrs.push('Secure');
  return attrs.join('; ');
}

const clearCookie = () => sessionCookie('', 0);

function createSession(db, accountId) {
  const raw = randomToken();
  const createdAt = now();
  const expiresAt = createdAt + config.sessionDays * 86_400_000;
  db.prepare(
    'INSERT INTO sessions (token_hash, account_id, created_at, expires_at) VALUES (?,?,?,?)'
  ).run(hash(raw), accountId, createdAt, expiresAt);
  return { raw, maxAge: config.sessionDays * 86_400, cookie: sessionCookie(raw, config.sessionDays * 86_400) };
}

function destroySession(db, cookieHeader) {
  const raw = parseCookies(cookieHeader).tk_session;
  if (raw) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hash(raw));
}

function accountFromSession(db, cookieHeader) {
  const raw = parseCookies(cookieHeader).tk_session;
  if (!raw) return null;
  const tokenHash = hash(raw);
  const row = db
    .prepare(
      `SELECT a.* FROM sessions s JOIN accounts a ON a.id = s.account_id
       WHERE s.token_hash = ? AND s.expires_at > ?`
    )
    .get(tokenHash, now());
  return row || null;
}

function accountFromApiToken(db, authorization) {
  const match = /^Bearer\s+(.+)$/i.exec(String(authorization || ''));
  if (!match) return null;
  return db.prepare('SELECT * FROM accounts WHERE api_token_hash = ?').get(hash(match[1])) || null;
}

function requestMagicLink(db, email) {
  const raw = randomToken();
  const createdAt = now();
  const expiresAt = createdAt + config.magicLinkMinutes * 60_000;
  db.prepare(
    'INSERT INTO magic_links (token_hash, email, created_at, expires_at, used) VALUES (?,?,?,?,0)'
  ).run(hash(raw), String(email).toLowerCase(), createdAt, expiresAt);
  return { token: raw, expiresAt };
}

function consumeMagicLink(db, token) {
  if (!token) return null;
  const tokenHash = hash(token);
  // Single-use must be enforced by the UPDATE, not by a SELECT followed by an
  // UPDATE: two concurrent requests could both read `used = 0` and both log in.
  return tx(db, () => {
    const res = db
      .prepare('UPDATE magic_links SET used = 1 WHERE token_hash = ? AND used = 0 AND expires_at > ?')
      .run(tokenHash, now());
    if (!res.changes) return null;
    const row = db.prepare('SELECT email FROM magic_links WHERE token_hash = ?').get(tokenHash);
    return row ? row.email : null;
  });
}

function ensureAccount(db, email, plan = 'free') {
  const normalised = String(email).toLowerCase().trim();
  const existing = db.prepare('SELECT * FROM accounts WHERE email = ?').get(normalised);
  if (existing) return existing;

  const planConfig = config.plans[plan] || config.plans.free;
  const row = {
    id: id('acc'),
    email: normalised,
    plan: planConfig.id,
    credits_static: planConfig.staticCredits,
    credits_ai: planConfig.aiCredits,
    period_start: now(),
    api_token_hash: null,
    is_admin: 0,
    created_at: now(),
  };
  db.prepare(
    `INSERT INTO accounts (id, email, plan, credits_static, credits_ai, period_start, is_admin, created_at)
     VALUES (?,?,?,?,?,?,?,?)`
  ).run(
    row.id,
    row.email,
    row.plan,
    row.credits_static,
    row.credits_ai,
    row.period_start,
    row.is_admin,
    row.created_at
  );
  return row;
}

function rotateApiToken(db, accountId) {
  const raw = 'tk_' + crypto.randomBytes(24).toString('base64url');
  db.prepare('UPDATE accounts SET api_token_hash = ? WHERE id = ?').run(hash(raw), accountId);
  return { token: raw, hint: raw.slice(0, 10) };
}

module.exports = {
  hash,
  parseCookies,
  sessionCookie,
  clearCookie,
  createSession,
  destroySession,
  accountFromSession,
  accountFromApiToken,
  requestMagicLink,
  consumeMagicLink,
  ensureAccount,
  rotateApiToken,
};
