# Web plan — RevScan SaaS

Status: approved plan, implemented in `web/`. Every milestone below has an
acceptance check that can be run.

---

## 1. What the web is (and is not)

**Is:** the funnel and the dashboard for one product — *"how long until an AI
agent cracks my app?"*

**Is not:** a license-key store. The license server (`server/`) stays as an
optional add-on and is not linked from the marketing pages.

```
landing ──▶ /scan (no account) ──▶ full report (needs email) ──▶ /app dashboard
                                        │
                                        └──▶ upgrade ──▶ Stripe / invoice
```

## 2. Pages

| Route | Auth | Purpose | Acceptance |
|---|---|---|---|
| `/` | — | hero + live score of a sample binary + CTA | loads < 100ms, one number visible above the fold |
| `/scan` | — | drop a file, get score | returns a report in < 15s for a 5MB binary |
| `/r/:publicId` | — | shareable report | works logged out, filename redacted |
| `/compare` | — | diff before/after from two `scan.py --json` reports | no binary upload; protect runs locally |
| `/pricing` | — | 3 plans + FAQ | prices match `web/config.js` |
| `/login` | — | email → magic link | link lands in outbox (dev) or email (prod) |
| `/auth/verify` | token | sets session cookie | cookie is httpOnly + SameSite=Lax |
| `/app` | user | credits, recent scans, plan | shows remaining credits and monthly reset date |
| `/app/scan/:id` | owner | full report + fixes + CI snippet | the exact same JSON as `scan.py --json` |
| `/app/settings` | user | API token for CI, delete account | token can be revoked |
| `/app/admin` | admin key | accounts, grant credits, force plan | every action written to `events` |

## 3. Data model (SQLite, `node:sqlite`, no npm deps)

```sql
accounts(id TEXT PK, email TEXT UNIQUE, plan TEXT, credits_static INT, credits_ai INT,
         period_start INT, api_token_hash TEXT, is_admin INT, created_at INT)
sessions(token_hash TEXT PK, account_id TEXT, created_at INT, expires_at INT)
magic_links(token_hash TEXT PK, email TEXT, created_at INT, expires_at INT, used INT)
scans(id TEXT PK, account_id TEXT NULL, public_id TEXT UNIQUE, sha256 TEXT, filename TEXT,
      size INT, kind TEXT, risk INT, crack_seconds REAL, p_success REAL,
      mode TEXT, credits_used INT, ip_hash TEXT, report_json TEXT, created_at INT)
ledger(id TEXT PK, account_id TEXT, delta INT, bucket TEXT, reason TEXT, ref TEXT, created_at INT)
anon_scans(ip_hash TEXT, day TEXT, count INT, PRIMARY KEY(ip_hash, day))
events(id TEXT PK, type TEXT, account_id TEXT NULL, payload TEXT, created_at INT)
```

Indexes on `scans(account_id, created_at)`, `scans(sha256)`, `ledger(account_id)`.

## 4. API

All JSON, `{ok:true,data}` / `{ok:false,error:{code,message}}`.

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/scan` | optional | body = raw file bytes, `x-filename` header, `?mode=static\|ai` |
| POST | `/api/compare` | — | `{original, protected}` = two `scan.py --json` reports; no binary |
| GET | `/api/scans` | user | last 50, own scans only |
| GET | `/api/report/:id` | owner | 404 for others (no information leak) |
| POST | `/api/auth/request` | — | always answers 200 (no account enumeration) |
| GET | `/auth/verify?token=` | — | 302 to `/app` |
| POST | `/api/auth/logout` | user | clears cookie |
| POST | `/api/api-token` | user | rotate CI token, returned once |
| POST | `/api/billing/checkout` | user | Stripe session or `{invoice:true}` fallback |
| POST | `/api/billing/webhook` | provider sig | idempotent by event id |
| POST | `/api/admin/grant` | admin key | `{email, plan, static, ai}` |
| GET | `/health` | — | db + engine check |

## 5. Credits

One unit = one scan. Two buckets, because they cost different things:

| | static | ai |
|---|---|---|
| Free account | 5 / month | 1 / month |
| Pro $29 | 200 / month | 25 / month |
| Team $99 | 2000 / month | 100 / month (5 seats) |
| Anonymous | 1 / day / IP | — |

Rules (all enforced in `web/credits.js`):

1. Charged **before** the scan runs, refunded automatically on engine error/timeout.
2. Same `sha256` scanned by the same account within 24h → **free** (cached report).
3. Anonymous scans return a summary only (risk + 3 findings); the full report needs an account.
4. Credits reset on the monthly anniversary of `period_start`; no rollover.
5. Every change writes to `ledger` so support can answer "where did my credit go".

## 6. Security & privacy

- **The uploaded binary is deleted immediately after the scan**, success or failure.
  Only `sha256`, size, and the JSON report are kept. Stated on `/scan` and in `/legal/privacy`.
- `/compare` accepts **report JSON only**, never a binary: the customer runs
  `protect`/`scan.py` locally and uploads the two reports. This preserves the
  local-protect invariant while still giving a web diff.
- 150 MB upload cap, extension allowlist (`exe dll bin sys`), streaming write to a temp dir,
  `fsync`-free unlink after.
- Engine runs as a subprocess with a 60s timeout and no network access needed, `--json` only.
- Session cookie: HMAC-signed, `httpOnly`, `SameSite=Lax`, `Secure` when `TRAPKEY_TLS=1`.
- Magic links: single use, 15 min TTL, token stored hashed.
- Rate limits: 10 uploads/hour/IP, 3 magic links/hour/email, 120 req/min general.
  The client IP is `X-Real-IP` set by our nginx (only trusted when the peer is a
  loopback/private address); the app ignores client-supplied `X-Forwarded-For`.
- Anonymous quota is reserved **before** the upload body is streamed and refunded
  if the scan fails. Concurrent engine processes are capped
  (`MAX_CONCURRENT_SCANS`, default 4) and excess requests get a retryable 503.
- The dev magic link (`devUrl` in the JSON response) is only returned outside
  production, or with an explicit `TRAPKEY_DEV_MAILER=1`.
- Retention sweep runs at boot and every 6h: expired sessions, expired/used
  magic links, scans and events older than `TRAPKEY_RETENTION_DAYS` (default 180,
  minimum 7), and anonymous quota rows older than 2 days. Accounts and `ledger`
  are never deleted. Because `events` is also the webhook idempotency store, the
  retention floor must stay above the provider retry window (Stripe retries for
  ~72h); a webhook captured and replayed later is still rejected by the ±300s
  signature timestamp check.
- AI quota cooldown is global and capped at 1h, even if the provider returns a
  larger `reset after` value. Static scans are never blocked by it.
- Admin routes require `x-admin-key` compared with `timingSafeEqual`.
- No third-party JS, no fonts from CDNs, no analytics by default.

## 7. Billing

Two modes, chosen by env:

- `STRIPE_SECRET_KEY` + `STRIPE_WEBHOOK_SECRET` present → real Checkout Session.
- absent → **invoice mode**: checkout returns `{invoice:true}`, an event is recorded, and an
  admin grants the plan manually (`/api/admin/grant`). This lets the site ship before the
  Stripe account is ready, with no dead links.

The webhook returns 503 until `STRIPE_WEBHOOK_SECRET` is set: accepting unsigned
events meant anyone could POST a fake `checkout.session.completed` and grant
themselves Team. Signatures are checked with a 5-minute timestamp window. The plan
travels in `metadata.plan` (set by our own checkout call) plus
`subscription_data.metadata`; the account id and Stripe customer/subscription ids
are stored on the account so `customer.subscription.deleted` downgrades it to
Free. Webhook handling is idempotent (`events.id` = provider event id).

## 8. Deployment

```
web/server.js            node, zero deps, listens on 127.0.0.1:7200
systemd unit             deploy/revscan-web.service
nginx                    deploy/nginx.conf  (TLS terminated outside, no app TLS)
data                     DATA_DIR (sqlite + outbox), backed up daily
```

Env: `PORT HOST DATA_DIR TRAPKEY_TLS PUBLIC_URL ADMIN_KEY STRIPE_SECRET_KEY
STRIPE_WEBHOOK_SECRET RESEND_API_KEY`.

## 9. Milestones

| # | Milestone | Acceptance |
|---|---|---|
| M1 | DB + accounts + magic link | login round-trip works, token single-use |
| M2 | Upload + scan + cache | 5MB binary scanned in < 15s, second upload is free |
| M3 | Report page + public share | logged-out `/r/:id` shows redacted filename |
| M4 | Credits + ledger | 6th free scan is refused with a clear message; ledger explains why |
| M5 | Billing invoice mode + Stripe stub | upgrade changes plan and credits |
| M6 | Admin console | grant credits, force plan, audit rows written |
| M7 | CI token + docs | `curl` with token scans from CI |
| M8 | Deploy artifacts | systemd + nginx files present and syntactically valid |

## 10. Decisions (so they are not re-litigated)

- **No framework, no build step.** One `node` process, server-rendered HTML, ~40KB CSS.
  A security product that ships a 4MB JS bundle is a bad joke; also keeps deploy to `git pull`.
- **SQLite over JSON store.** Multi-tenant data with money attached needs transactions;
  `node:sqlite` is built in, no dependency.
- **Python engine via subprocess.** It is already written and tested; isolating it means an
  engine crash cannot take the web down, and the timeout is enforceable.
- **Anonymous scans are cheap and public.** They are the marketing. The account is for history,
  full reports, CI tokens and paid credits.
