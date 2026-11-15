'use strict';

const crypto = require('node:crypto');

// Crockford base32: no I, L, O, U (avoids 1/l/O/0 and accidental profanity).
const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

const b64u = (buf) => Buffer.from(buf).toString('base64url');

/**
 * Product signing key.
 *
 * RSA-2048 / PKCS#1 v1.5 / SHA-256 rather than Ed25519 on purpose: Windows CNG
 * (bcrypt.dll) verifies RSA natively, so the C++ SDK needs no crypto library.
 */
function newProductKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
  return {
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
    // This is what the vendor embeds in their app.
    // n: base64url modulus (JWK), e: hex exponent ("010001") so C++ can embed it literally.
    verifyKey: { n: jwk.N || jwk.n, e: Buffer.from(jwk.e, 'base64url').toString('hex') },
  };
}

function signToken(claims, privateKeyPem) {
  const body = b64u(Buffer.from(JSON.stringify(claims), 'utf8'));
  const sig = crypto.sign('sha256', Buffer.from(body, 'utf8'), privateKeyPem);
  return `${body}.${b64u(sig)}`;
}

function verifyToken(token, publicKeyPem) {
  if (typeof token !== 'string') return { ok: false, reason: 'MALFORMED' };
  const dot = token.indexOf('.');
  if (dot < 1 || dot === token.length - 1) return { ok: false, reason: 'MALFORMED' };
  const body = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  let valid = false;
  try {
    valid = crypto.verify(
      'sha256',
      Buffer.from(body, 'utf8'),
      publicKeyPem,
      Buffer.from(sig, 'base64url')
    );
  } catch {
    return { ok: false, reason: 'MALFORMED' };
  }
  if (!valid) return { ok: false, reason: 'BAD_SIGNATURE' };
  try {
    return { ok: true, claims: JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) };
  } catch {
    return { ok: false, reason: 'MALFORMED' };
  }
}

function randomKey() {
  const bytes = crypto.randomBytes(20);
  let out = '';
  for (const b of bytes) out += B32[b & 31]; // bias-free: 256 % 32 === 0
  return 'TK-' + out.match(/.{5}/g).join('-');
}

function normalizeKey(input) {
  if (typeof input !== 'string') return '';
  const cleaned = input.toUpperCase().replace(/[^A-Z0-9]/g, '');
  const mapped = cleaned
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1')
    .replace(/U/g, 'V');
  if (mapped.length !== 20) return cleaned; // let the lookup fail with the raw value
  return 'TK-' + mapped.match(/.{5}/g).join('-');
}

function hwidFrom(guid, productId) {
  return crypto
    .createHash('sha256')
    .update(`${String(guid).toLowerCase()}:${productId}`)
    .digest('hex')
    .slice(0, 32);
}

function timingSafeEqualStr(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(4).toString('hex')}`;
}

module.exports = {
  b64u,
  newProductKeys,
  signToken,
  verifyToken,
  randomKey,
  normalizeKey,
  hwidFrom,
  timingSafeEqualStr,
  id,
};
