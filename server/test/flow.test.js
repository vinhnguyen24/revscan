'use strict';

/**
 * End-to-end test of the whole licensing flow, against a throwaway store.
 * Run: node test/flow.test.js
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createApp } = require('../src/app');
const { verifyToken } = require('../src/crypto');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trapkey-'));
const server = createApp({
  dataFile: path.join(tmpDir, 'data.json'),
  adminKey: 'test-admin-key',
});
const ADMIN = { 'content-type': 'application/json', 'x-admin-key': 'test-admin-key' };
const OPEN = { 'content-type': 'application/json' };
const HWID = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';

let base = '';

async function call(method, p, body, headers = OPEN) {
  const res = await fetch(base + p, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

/* --------------------------------- tests -------------------------------- */

test('health', async () => {
  const r = await call('GET', '/health');
  assert.equal(r.status, 200);
  assert.equal(r.json.data.status, 'ok');
});

test('admin routes reject missing/wrong key', async () => {
  const no = await call('GET', '/v1/products', undefined, OPEN);
  assert.equal(no.status, 401);
  assert.equal(no.json.error.code, 'UNAUTHORIZED');
  const wrong = await call('GET', '/v1/products', undefined, { ...OPEN, 'x-admin-key': 'nope' });
  assert.equal(wrong.status, 401);
});

let product;
let key;
let license;

test('create product exposes verifyKey and hides private key', async () => {
  const r = await call('POST', '/v1/products', { name: 'Demo App' }, ADMIN);
  assert.equal(r.status, 201);
  product = r.json.data;
  assert.match(product.id, /^prd_/);
  assert.ok(product.verifyKey.n.length > 100);
  assert.equal(product.verifyKey.e, '010001');
  assert.equal(product.privateKeyPem, undefined, 'private key must never leave the server');
});

test('issue keys', async () => {
  const r = await call('POST', '/v1/keys', { productId: product.id, count: 2, days: 30, seats: 1 }, ADMIN);
  assert.equal(r.status, 201);
  assert.equal(r.json.data.created.length, 2);
  key = r.json.data.created[0];
  assert.match(key, /^TK(-[0-9A-Z]{5}){4}$/);
});

test('unknown key is rejected', async () => {
  const r = await call('POST', '/v1/activate', { key: 'TK-AAAAA-AAAAA-AAAAA-AAAAA', productId: product.id, hwid: HWID });
  assert.equal(r.status, 404);
  assert.equal(r.json.error.code, 'KEY_NOT_FOUND');
});

test('activate returns a signed token that verifies with the public key', async () => {
  const r = await call('POST', '/v1/activate', { key: key.toLowerCase(), productId: product.id, hwid: HWID, appVersion: '1.0.0' });
  assert.equal(r.status, 200);
  license = r.json.data.license;
  assert.ok(license.includes('.'));

  const v = verifyToken(license, product.publicKeyPem);
  assert.equal(v.ok, true, 'signature must verify');
  assert.equal(v.claims.hwid, HWID);
  assert.equal(v.claims.pid, product.id);
  const ttl = v.claims.exp - v.claims.iat;
  assert.ok(ttl <= 7 * 86400 + 5, 'token TTL is clamped to 7d');
});

test('seat limit blocks a second machine', async () => {
  const r = await call('POST', '/v1/activate', { key, productId: product.id, hwid: 'ffffffffffffffffffffffffffffffff' });
  assert.equal(r.status, 409);
  assert.equal(r.json.error.code, 'SEAT_LIMIT');
});

test('same machine re-activates without consuming a seat', async () => {
  const r = await call('POST', '/v1/activate', { key, productId: product.id, hwid: HWID });
  assert.equal(r.status, 200);
});

test('validate accepts the token and refreshes it', async () => {
  const r = await call('POST', '/v1/validate', { license, hwid: HWID });
  assert.equal(r.json.data.valid, true);
  assert.ok(r.json.data.refreshed);
});

test('validate rejects a tampered token', async () => {
  const [body, sig] = license.split('.');
  const claims = JSON.parse(Buffer.from(body, 'base64url').toString());
  claims.seats = 99;
  const forged = Buffer.from(JSON.stringify(claims)).toString('base64url') + '.' + sig;
  const r = await call('POST', '/v1/validate', { license: forged, hwid: HWID });
  assert.equal(r.json.data.valid, false);
  assert.equal(r.json.data.reason, 'BAD_SIGNATURE');
});

test('validate rejects a different machine', async () => {
  const r = await call('POST', '/v1/validate', { license, hwid: 'ffffffffffffffffffffffffffffffff' });
  assert.equal(r.json.data.reason, 'HWID_MISMATCH');
});

test('revoke kills the key immediately on validate', async () => {
  const r = await call('POST', `/v1/keys/${key}/revoke`, { reason: 'chargeback' }, ADMIN);
  assert.equal(r.status, 200);
  assert.equal(r.json.data.status, 'revoked');

  const v = await call('POST', '/v1/validate', { license, hwid: HWID });
  assert.equal(v.json.data.valid, false);
  assert.equal(v.json.data.reason, 'KEY_REVOKED');

  const a = await call('POST', '/v1/activate', { key, productId: product.id, hwid: HWID });
  assert.equal(a.status, 403);
  assert.equal(a.json.error.code, 'KEY_REVOKED');
});

test('extend pushes expiry out', async () => {
  const r = await call('POST', `/v1/keys/${key}/extend`, { days: 30 }, ADMIN);
  assert.equal(r.status, 200);
  assert.equal(r.json.data.days, 60);
});

test('deactivate releases the seat', async () => {
  // Fresh key: the first one was revoked above, so it has no active seats left.
  const issued = await call('POST', '/v1/keys', { productId: product.id, days: 30, seats: 1 }, ADMIN);
  const key2 = issued.json.data.created[0];
  const hwid2 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';

  const act = await call('POST', '/v1/activate', { key: key2, productId: product.id, hwid: hwid2 });
  assert.equal(act.status, 200);
  const lic2 = act.json.data.license;

  const d = await call('POST', '/v1/deactivate', { key: key2, hwid: hwid2 });
  assert.equal(d.json.data.released, 1);

  const v = await call('POST', '/v1/validate', { license: lic2, hwid: hwid2 });
  assert.equal(v.json.data.valid, false);
  assert.equal(v.json.data.reason, 'DEACTIVATED');

  // Seat is free again for a different machine.
  const again = await call('POST', '/v1/activate', { key: key2, productId: product.id, hwid: 'cccccccccccccccccccccccccccccccc' });
  assert.equal(again.status, 200);
});

test('malformed body is 400, not 500', async () => {
  const res = await fetch(base + '/v1/activate', {
    method: 'POST',
    headers: OPEN,
    body: '{not json',
  });
  assert.equal(res.status, 400);
});

test('admin UI is served', async () => {
  const res = await fetch(base + '/');
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.ok(html.includes('TrapKey'));
});

/* ------------------------------- runner -------------------------------- */

(async () => {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;

  let failed = 0;
  for (const t of tests) {
    try {
      await t.fn();
      console.log(`  ok   ${t.name}`);
    } catch (err) {
      failed += 1;
      console.log(`  FAIL ${t.name}`);
      console.log(`       ${err.message}`);
    }
  }

  console.log(`\n${tests.length - failed}/${tests.length} passed`);
  server.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
  process.exit(failed ? 1 : 0);
})();
