'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'web-data'));

let adminKey = process.env.ADMIN_KEY;
if (!adminKey) {
  const file = path.join(DATA_DIR, 'admin.key');
  if (fs.existsSync(file)) {
    adminKey = fs.readFileSync(file, 'utf8').trim();
  } else {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    adminKey = crypto.randomBytes(24).toString('hex');
    fs.writeFileSync(file, adminKey, { mode: 0o600 });
  }
}

const plans = {
  free: {
    id: 'free',
    label: 'Free',
    price: 0,
    staticCredits: 5,
    aiCredits: 1,
    seats: 1,
    features: ['5 static scans / month', '1 AI-simulated scan / month', 'shareable reports'],
  },
  pro: {
    id: 'pro',
    label: 'Pro',
    price: 29,
    staticCredits: 200,
    aiCredits: 25,
    seats: 1,
    features: ['200 static scans / month', '25 AI-measured scans', 'CI token', 'full fix list'],
  },
  team: {
    id: 'team',
    label: 'Team',
    price: 99,
    staticCredits: 2000,
    aiCredits: 100,
    seats: 5,
    features: ['2000 static scans / month', '100 AI-measured scans', '5 seats', 'priority support'],
  },
};

function aiAvailable() {
  return Boolean(
    process.env.OPENAI_API_KEY ||
      process.env.LLM_API_KEY ||
      process.env.ANTHROPIC_API_KEY ||
      process.env.GEMINI_API_KEY ||
      process.env.GOOGLE_API_KEY ||
      process.env.OLLAMA_API_KEY ||
      process.env.OPENAI_BASE_URL ||
      (process.env.TRAPKEY_AI_PROVIDER || '').toLowerCase() === 'ollama'
  );
}

/**
 * May the API return the magic-link URL in its response?
 *
 * That convenience is a full authentication bypass: anyone who can POST an
 * email address would receive a valid login link. It is only safe on a
 * developer machine, so production requires an explicit opt-in.
 */
function devMagicLink() {
  if (process.env.RESEND_API_KEY) return false;
  const flag = String(process.env.TRAPKEY_DEV_MAILER || '').toLowerCase();
  if (flag === '1' || flag === 'true') return true;
  if (flag === '0' || flag === 'false') return false;
  return process.env.NODE_ENV !== 'production';
}

module.exports = {
  aiAvailable,
  devMagicLink,
  root: ROOT,
  dataDir: DATA_DIR,
  dbFile: path.join(DATA_DIR, 'trapkey.sqlite'),
  outboxDir: path.join(DATA_DIR, 'outbox'),
  tmpDir: path.join(DATA_DIR, 'tmp'),
  uploadsDir: path.join(DATA_DIR, 'uploads'),

  port: Number(process.env.PORT || 7200),
  host: process.env.HOST || '127.0.0.1',
  publicUrl: (process.env.PUBLIC_URL || `http://127.0.0.1:${process.env.PORT || 7200}`).replace(/\/$/, ''),
  tls: process.env.TRAPKEY_TLS === '1',

  adminKey,
  plans,

  maxUpload: 150 * 1024 * 1024,
  allowedExt: new Set(['.exe', '.dll', '.bin', '.sys']),
  scanTimeoutMs: Number(process.env.SCAN_TIMEOUT_MS || 60_000),
  compareTimeoutMs: Number(process.env.COMPARE_TIMEOUT_MS || 30_000),
  // One Python process per scan. Without a cap a burst of uploads turns into a
  // CPU/memory pile-up; excess requests get a retryable 503 instead.
  maxConcurrentScans: Math.max(1, Number(process.env.MAX_CONCURRENT_SCANS || 4)),

  engine: path.join(ROOT, 'scan.py'),
  cli: path.join(ROOT, 'cli', 'trapkey.py'),
  // Windows installs `python.exe`; most Unix images only have `python3`.
  python: process.env.PYTHON || (process.platform === 'win32' ? 'python' : 'python3'),

  rate: {
    uploadsPerHour: 10,
    magicLinksPerHour: 3,
    requestsPerMinute: 120,
    // Report-vs-report comparison is CPU-light and uploads no binary.
    comparesPerHour: 30,
  },

  sessionDays: 30,
  magicLinkMinutes: 15,
  cacheHours: 24,
  anonymousPerDay: 1,
  // Reports are the product, so scans survive far longer than sessions. The
  // cap exists because `scans` also carries sha256 + IP hash + full reports,
  // which is personal data we have no reason to keep forever.
  // Keep at least a week: 1 day would undercut the webhook retry/idempotency
  // window (Stripe retries for ~72h) and could re-apply a delayed event.
  retentionDays: Math.max(7, Number(process.env.TRAPKEY_RETENTION_DAYS || 180) || 180),
};
