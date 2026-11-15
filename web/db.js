'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const config = require('./config');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS accounts (
  id             TEXT PRIMARY KEY,
  email          TEXT UNIQUE NOT NULL,
  plan           TEXT NOT NULL DEFAULT 'free',
  credits_static INTEGER NOT NULL DEFAULT 5,
  credits_ai     INTEGER NOT NULL DEFAULT 1,
  period_start   INTEGER NOT NULL,
  api_token_hash TEXT,
  is_admin       INTEGER NOT NULL DEFAULT 0,
  created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS magic_links (
  token_hash TEXT PRIMARY KEY,
  email      TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scans (
  id            TEXT PRIMARY KEY,
  account_id    TEXT,
  public_id     TEXT UNIQUE NOT NULL,
  sha256        TEXT NOT NULL,
  filename      TEXT NOT NULL,
  size          INTEGER NOT NULL,
  kind          TEXT,
  risk          INTEGER,
  crack_seconds REAL,
  p_success     REAL,
  mode          TEXT NOT NULL,
  credits_used  INTEGER NOT NULL DEFAULT 0,
  ip_hash       TEXT,
  report_json   TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_account ON scans(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_sha ON scans(sha256, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);

CREATE TABLE IF NOT EXISTS ledger (
  id         TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  delta      INTEGER NOT NULL,
  bucket     TEXT NOT NULL,
  reason     TEXT NOT NULL,
  ref        TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_account ON ledger(account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS anon_scans (
  ip_hash TEXT NOT NULL,
  day     TEXT NOT NULL,
  count   INTEGER NOT NULL,
  PRIMARY KEY (ip_hash, day)
);

CREATE TABLE IF NOT EXISTS events (
  id         TEXT PRIMARY KEY,
  type       TEXT NOT NULL,
  account_id TEXT,
  payload    TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_magic_expires ON magic_links(expires_at);
CREATE INDEX IF NOT EXISTS idx_anon_day ON anon_scans(day);

CREATE TABLE IF NOT EXISTS rate_limits (
  key   TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  start INTEGER NOT NULL
);
`;

// Columns added after the first release. CREATE TABLE IF NOT EXISTS does not
// alter an existing database, so a plain schema bump would break every deploy
// that already has data. Keep this list append-only.
const ACCOUNT_COLUMNS = {
  stripe_customer_id: 'TEXT',
  stripe_subscription_id: 'TEXT',
};

function migrate(db) {
  const existing = new Set(
    db.prepare("SELECT name FROM pragma_table_info('accounts')").all().map((row) => row.name)
  );
  for (const [name, type] of Object.entries(ACCOUNT_COLUMNS)) {
    if (!existing.has(name)) db.exec(`ALTER TABLE accounts ADD COLUMN ${name} ${type}`);
  }
  db.exec('CREATE INDEX IF NOT EXISTS idx_accounts_sub ON accounts(stripe_subscription_id);');
}

function open(file = config.dbFile) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(SCHEMA);
  migrate(db);
  return db;
}

const id = (prefix) => `${prefix}_${crypto.randomBytes(6).toString('hex')}`;
const now = () => Date.now();

function tx(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const out = fn();
    db.exec('COMMIT');
    return out;
  } catch (err) {
    try {
      db.exec('ROLLBACK');
    } catch {
      /* ignore */
    }
    throw err;
  }
}

function ledger(db, accountId, delta, bucket, reason, ref = null) {
  db.prepare(
    'INSERT INTO ledger (id, account_id, delta, bucket, reason, ref, created_at) VALUES (?,?,?,?,?,?,?)'
  ).run(id('led'), accountId, delta, bucket, reason, ref, now());
}

function event(db, type, accountId, payload) {
  db.prepare('INSERT INTO events (id, type, account_id, payload, created_at) VALUES (?,?,?,?,?)').run(
    id('evt'),
    type,
    accountId || null,
    JSON.stringify(payload || {}),
    now()
  );
}

/**
 * Retention sweep.
 *
 * Dead auth rows are pure attack surface (a stolen used magic link or expired
 * session is still a row someone can replay against), so they go immediately.
 * Scan reports and audit events have a public retention window because they
 * contain sha256 hashes, IP hashes and the customer's report. Accounts and
 * ledger rows are never touched: they are the billing record.
 *
 * `nowMs` is injectable so the sweep is testable without waiting 180 days.
 */
function cleanup(db, nowMs = now()) {
  const retentionMs = config.retentionDays * 86_400_000;
  // `day` is a UTC YYYY-MM-DD string, so lexicographic comparison is the
  // correct (and index-friendly) way to age rows out.
  const anonCutoff = new Date(nowMs - 2 * 86_400_000).toISOString().slice(0, 10);
  const run = (sql, ...params) => Number(db.prepare(sql).run(...params).changes || 0);
  return tx(db, () => ({
    sessions: run('DELETE FROM sessions WHERE expires_at < ?', nowMs),
    magic_links: run(
      'DELETE FROM magic_links WHERE expires_at < ? OR (used = 1 AND created_at < ?)',
      nowMs,
      nowMs - 86_400_000
    ),
    scans: run('DELETE FROM scans WHERE created_at < ?', nowMs - retentionMs),
    events: run('DELETE FROM events WHERE created_at < ?', nowMs - retentionMs),
    anon_scans: run('DELETE FROM anon_scans WHERE day < ?', anonCutoff),
  }));
}

module.exports = { open, tx, id, now, ledger, event, cleanup };
