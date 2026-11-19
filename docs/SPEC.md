# RevScan — Technical Spec (v0.1)

Status: MVP, implemented. Everything below matches `server/`, `cli/`, `sdk/cpp/`.

---

## 1. Product definition

A vendor integrates three things:

1. **SDK** (`RevScan.dll` or static lib) — 3 functions:
   ```c
   TK_Init(productId, verifyKeyN, verifyKeyE);   // once at startup
   TK_IsLicensed();                              // every protected feature gate
   TK_Activate(key);                             // one-time, from a dialog
   ```
2. **CLI at build time** — `revscan protect vendor.exe --level 2` (post-build, no source needed).
3. **Server** — issues keys, tracks activations, revokes.

The vendor's customer never sees a login page. They paste a key, the app binds to their
machine, done.

---

## 2. Data model

```
Product   { id, name, createdAt, publicKeyPem, privateKeyPem, verifyKey:{n,e} }
Key       { key, productId, createdAt, expiresAt, seats, days, features[], note,
            status: active|revoked|expired, revokedAt, revokeReason }
Activation{ id, key, productId, hwid, createdAt, lastSeenAt, appVersion, iphint, status }
```

`Key.status` is derived on read: `revoked` wins, then `expiresAt < now` → `expired`, else
`active`.

Seats are enforced at activation time: `count(activations where key=X and status=active) < seats`.

---

## 3. Key format

```
TK-XXXXX-XXXXX-XXXXX-XXXXX
```

20 Crockford-base32 chars (alphabet `0-9 A-Z` minus `I L O U`), 100 bits from
`crypto.randomBytes(20)` with `byte & 31` (bias-free because 256 % 32 = 0).
Normalization accepts lowercase and maps `O→0`, `I/L→1`.

---

## 4. License token

```
license = base64url(claims_json) + "." + base64url(RSASSA-PKCS1-v1_5-SHA256(claims_b64))
```

Claims:

```json
{
  "v": 1,
  "pid": "prd_ab12cd",
  "key": "TK-ABCDE-FGHJK-MNPQR-STVWX",
  "hwid": "a3f1…(32 hex)",
  "seats": 1,
  "exp": 1798761600,
  "iat": 1767225600,
  "feat": ["pro"],
  "tid": "z9y8x7"
}
```

**Why RSA and not Ed25519.** Ed25519 is smaller and faster, but Windows CNG has no
Ed25519 provider, so the SDK would need libsodium/monocypher linked in. RSA-2048 is
verifiable with `BCryptImportKeyPair(BCRYPT_RSAPUBLIC_BLOB)` +
`BCryptVerifySignature(BCRYPT_PAD_PKCS1, SHA-256)` — no dependency, ships with Windows.
Trade-off: 256-byte signatures instead of 64. Acceptable inside a license blob.

**Why not HMAC.** A symmetric secret embedded in the binary is extractable; anyone who
finds it mints their own keys. Asymmetric means the binary only holds a public key.

`exp` is clamped to `min(key.expiresAt, now + tokenTtlDays)`. Default TTL 7 days. This is
what makes revocation eventually consistent: after revoke, the app refuses on the next
refresh, and a stale token dies within 7 days.

---

## 5. Offline verification

Client-side algorithm (C++ SDK):

```
1. Split token on "."
2. BCryptVerifySignature(SHA256, claims_b64, sig, productPublicKey)  -> reject if invalid
3. claims.exp > now                                                   -> reject if expired
4. claims.hwid == TK_Hwid()                                           -> reject if mismatch
5. claims.pid == embedded productId                                   -> reject if mismatch
```

No network. No clock-server. A machine without internet keeps working until `exp`.
The app may call `POST /v1/validate` on startup when online to pick up revocations early.

---

## 6. HWID

```c
guid = RegRead(HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid)   // primary
guid = read(%APPDATA%\RevScan\hwid.txt)                            // fallback
guid = random(32) and persist                                      // last resort
hwid = lowercase(hex(sha256(guid + ":" + productId))[0..32])
```

- Braces stripped (`{…}` spoofers).
- SHA-256 comes from CNG — still no dependencies.
- Hashing per product prevents cross-vendor correlation of a machine.
- `%APPDATA%` fallback survives registry cleaners; a cloned VM image shares the guid, which
  is a known limitation of every MachineGuid-based scheme (documented, not hidden).

---

## 7. Endpoints

All responses: `{ ok: true, data }` or `{ ok: false, error: { code, message } }`.

| Method | Path | Auth | Body / Query |
|---|---|---|---|
| POST | `/v1/activate` | — | `{ key, productId, hwid, appVersion? }` |
| POST | `/v1/validate` | — | `{ license, hwid }` |
| POST | `/v1/deactivate` | — | `{ key, hwid }` |
| POST | `/v1/products` | admin | `{ name }` |
| GET | `/v1/products` | admin | — |
| POST | `/v1/keys` | admin | `{ productId, count=1, days=365, seats=1, features=[], note? }` |
| GET | `/v1/keys` | admin | `?productId&status&limit` |
| POST | `/v1/keys/:key/revoke` | admin | `{ reason }` |
| POST | `/v1/keys/:key/extend` | admin | `{ days }` |
| GET | `/v1/activations` | admin | `?key` or `?productId` |
| GET | `/health` | — | — |

Error codes: `BAD_REQUEST`, `UNAUTHORIZED`, `NOT_FOUND`, `KEY_NOT_FOUND`, `KEY_REVOKED`,
`KEY_EXPIRED`, `SEAT_LIMIT`, `HWID_MISMATCH`, `RATE_LIMITED`, `PAYLOAD_TOO_LARGE`.

Rate limits (in-memory, per IP): non-admin 60 req/min, admin 300 req/min. Replace with
Redis before multi-instance deployment.

---

## 8. `revscan protect` — what it actually changes

Operates on a PE file after linking; source is not required.

**Level 1 — AI deception traps.** Appends a `.tkdata` blob containing indirect
prompt-injection strings (prepend / decoy target / append), chunked under Ghidra's 2048-char
truncation limit. Goal: an AI agent that reads the binary's strings reports a benign
program (e.g. "this is a CRC benchmark tool") and stops looking.

**Level 2 — traps + string hiding.** Traps are XOR-encoded with a key derived from the
file hash, preceded by a `TK2` marker, and split into scattered chunks so `strings` output
no longer shows readable license literals. The scorer knows how to decode them.

**Injection strategy (never breaks execution):**

```
1. Prefer slack: last section's [VirtualSize, SizeOfRawData) — bytes the loader never maps.
   Requires all-zero bytes there; writes nothing structural.
2. Otherwise add a new section: append at FileAlignment, VirtualAddress = align(SizeOfImage),
   Characteristics = INITIALIZED_DATA | READ, bump NumberOfSections and SizeOfImage.
3. If the section header table is full (common for linker-tight .NET assemblies), append the
   blob as an overlay at EOF. No header change, never mapped into memory.
```

The payload is **not referenced by code**, so it cannot alter control flow. It exists to be
seen by `strings` / decompiler string tables — which is exactly the surface AI agents read.

> Honest scope: this is string-layer defence. Control-flow flattening and VM protection are
> roadmap items (v2), not shipped features.

---

## 9. `scan.py` — the sales artifact (see docs/CALIBRATION.md for the full model)

Static analysis, no LLM call required, runs in <1s:

| Signal | Weight | Why it matters |
|---|---|---|
| License/serial/key/trial/activation literals | up to −20 | names the thing to attack |
| Key-shaped strings matching the vendor's own prefix | −15 | gives the attacker the format |
| Prompt-injection trap strings present | +10 (bonus) | deception active |
| Base64 blob ≥ 200 chars | −8 | often the license blob itself |
| Symbol / PDB path leaked | −10 | maps code to source |
| `license`, `verify`, `activate` function names in exports | −8 | hands over the entry point |
| No packer, rich header present, high string density | −10 | trivial to start |

The shipped scanner (`scanner/`) goes further than this list: it parses `.NET`
metadata (method count, names, IL bytes) and `.pdata` (exact native function
count), then converts the read budget into seconds:

```
seconds = tool_time + read_budget / prefill_rate + rounds * 1200 / decode_rate
```

Output is JSON (`--json`) so it can run in CI: `--min-seconds 60` fails the build
when an agent is expected to crack the binary in under a minute.

---

## 10. Threat model

| Attacker | Capability | Mitigation | Residual risk |
|---|---|---|---|
| Casual user | shares key with a friend | HWID bind, seat limit | seat recycle via VM clone |
| Key reseller | buys 1 key, sells 100 | seats + revoke + short TTL | until TTL expires |
| Static patcher | flips `TK_IsLicensed` return | score flags it; v2 adds integrity self-check | **accepted in v1** |
| AI RE agent | reads strings, decompiles, writes a keygen | traps + string hiding | determined agent wins; we raise cost & time |
| Server breach | steals DB | private keys on disk ⇒ rotate per product; store encrypted in v2 | **open item** |

The product is priced as *friction*, not *impossibility*. Any claim of "uncrackable" is a lie
and we do not make it.

---

## 11. Deployment

```
node server/src/index.js          # PORT, TRAPKEY_DATA, TRAPKEY_ADMIN_KEY
```

- Data: single JSON file (atomic write via tmp+rename). Swap `server/src/store.js` for
  Mongo/Postgres when you need multi-instance.
- TLS: put behind nginx/Caddy as usual; the server never terminates TLS itself.
- Backups: copy `server/data/data.json` + `server/data/keypair.pem`.

---

## 12. Open items before charging money

1. Encrypt product private keys at rest (currently plaintext JSON) — use a KMS or at minimum
   AES-GCM with `TRAPKEY_MASTER_KEY`.
2. Persist rate-limit counters (Redis) if you run >1 instance.
3. Verify the C++ SDK compiles under MSVC x64 and add a CI job on `windows-latest`.
4. Integrity self-check in the SDK (detect patched `TK_IsLicensed`).
5. Self-host distribution (Docker image + license server white-label).
