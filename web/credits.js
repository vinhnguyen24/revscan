'use strict';

const config = require('./config');
const { ledger, now, tx } = require('./db');

const PERIOD_MS = 30 * 86_400_000;

function bucketFor(mode) {
  return mode === 'ai' ? 'ai' : 'static';
}

function creditField(mode) {
  return mode === 'ai' ? 'credits_ai' : 'credits_static';
}

/** Monthly reset. Runs on every authenticated request; cheap and idempotent. */
function refreshPeriod(db, account) {
  if (!account || now() - account.period_start < PERIOD_MS) return account;
  const plan = config.plans[account.plan] || config.plans.free;
  return tx(db, () => {
    db.prepare(
      'UPDATE accounts SET credits_static = ?, credits_ai = ?, period_start = ? WHERE id = ?'
    ).run(plan.staticCredits, plan.aiCredits, now(), account.id);
    ledger(db, account.id, plan.staticCredits, 'static', 'period reset', null);
    ledger(db, account.id, plan.aiCredits, 'ai', 'period reset', null);
    return db.prepare('SELECT * FROM accounts WHERE id = ?').get(account.id);
  });
}

function remaining(account, mode) {
  return Number(account[creditField(mode)] || 0);
}

function spend(db, account, mode, ref) {
  const field = creditField(mode);
  const bucket = bucketFor(mode);
  return tx(db, () => {
    const current = db.prepare(`SELECT ${field} AS c FROM accounts WHERE id = ?`).get(account.id);
    if (!current || current.c <= 0) return { ok: false, code: 'NO_CREDITS' };
    db.prepare(`UPDATE accounts SET ${field} = ${field} - 1 WHERE id = ?`).run(account.id);
    ledger(db, account.id, -1, bucket, `scan ${mode}`, ref);
    return { ok: true };
  });
}

function refund(db, account, mode, ref, reason = 'scan failed') {
  const field = creditField(mode);
  const bucket = bucketFor(mode);
  return tx(db, () => {
    db.prepare(`UPDATE accounts SET ${field} = ${field} + 1 WHERE id = ?`).run(account.id);
    ledger(db, account.id, +1, bucket, reason, ref);
  });
}

/** Anonymous quota: N scans per IP per UTC day. */
function allowAnonymous(db, ipHash, limit = config.anonymousPerDay) {
  const day = new Date().toISOString().slice(0, 10);
  return tx(db, () => {
    const row = db.prepare('SELECT count FROM anon_scans WHERE ip_hash = ? AND day = ?').get(ipHash, day);
    if (!row) {
      db.prepare('INSERT INTO anon_scans (ip_hash, day, count) VALUES (?,?,1)').run(ipHash, day);
      return { ok: true, used: 1, limit };
    }
    if (row.count >= limit) return { ok: false, used: row.count, limit };
    db.prepare('UPDATE anon_scans SET count = count + 1 WHERE ip_hash = ? AND day = ?').run(ipHash, day);
    return { ok: true, used: row.count + 1, limit };
  });
}

/**
 * Give back an anonymous slot when the scan never produced a report (engine
 * error, timeout, aborted upload). The slot is reserved before the body is
 * streamed, otherwise a 150MB upload succeeds before the quota check rejects it.
 */
function refundAnonymous(db, ipHash, limit = config.anonymousPerDay) {
  const day = new Date().toISOString().slice(0, 10);
  return tx(db, () => {
    const row = db.prepare('SELECT count FROM anon_scans WHERE ip_hash = ? AND day = ?').get(ipHash, day);
    if (!row || row.count <= 0) return;
    if (row.count <= 1) {
      db.prepare('DELETE FROM anon_scans WHERE ip_hash = ? AND day = ?').run(ipHash, day);
    } else {
      db.prepare('UPDATE anon_scans SET count = count - 1 WHERE ip_hash = ? AND day = ?').run(ipHash, day);
    }
  });
}

/** Apply a plan change: new limits immediately, credits topped up to the plan allowance. */
function applyPlan(db, account, planId) {
  const plan = config.plans[planId] || config.plans.free;
  return tx(db, () => {
    db.prepare('UPDATE accounts SET plan = ?, credits_static = ?, credits_ai = ?, period_start = ? WHERE id = ?').run(
      plan.id,
      plan.staticCredits,
      plan.aiCredits,
      now(),
      account.id
    );
    ledger(db, account.id, plan.staticCredits, 'static', `plan ${plan.id}`, null);
    ledger(db, account.id, plan.aiCredits, 'ai', `plan ${plan.id}`, null);
    return db.prepare('SELECT * FROM accounts WHERE id = ?').get(account.id);
  });
}

module.exports = {
  refreshPeriod,
  remaining,
  spend,
  refund,
  allowAnonymous,
  refundAnonymous,
  applyPlan,
  bucketFor,
};
