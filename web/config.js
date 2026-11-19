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
    billing: 'month',
    periodDays: 30,
    oneTime: false,
    fullReport: false,
    staticCredits: 5,
    aiCredits: 3,
    seats: 1,
    features: [
      '5 static scans / tháng',
      '3 AI crack simulations / tháng (tóm tắt)',
      'Shareable reports',
    ],
    featuresEn: [
      '5 static scans / month',
      '3 AI crack simulations / month (summary)',
      'Shareable reports',
    ],
  },
  audit: {
    id: 'audit',
    label: 'Audit Pass',
    price: 49,
    billing: 'one_time',
    periodDays: 30,
    oneTime: true,
    fullReport: true,
    staticCredits: 10,
    aiCredits: 3,
    seats: 1,
    features: [
      '10 static scans (hiệu lực 30 ngày)',
      '3 AI crack simulations (full patch bytes)',
      'Full fix list + Decoy Kit',
      'Mua đứt 1 lần — không tự gia hạn',
    ],
    featuresEn: [
      '10 static scans (30-day pass)',
      '3 AI crack simulations (full patch bytes)',
      'Full fix list + Decoy Kit',
      'One-time purchase — no auto-renewal',
    ],
  },
  annual: {
    id: 'annual',
    label: 'Annual CI',
    price: 199,
    billing: 'year',
    periodDays: 365,
    oneTime: false,
    fullReport: true,
    unlimitedStatic: true,
    staticCredits: 999999,
    aiCredits: 50,
    seats: 1,
    features: [
      'Unlimited static scans / năm',
      '50 AI crack simulations / năm',
      'CI token & CI badge',
      'Full fix list + Decoy Kit',
    ],
    featuresEn: [
      'Unlimited static scans / year',
      '50 AI crack simulations / year',
      'CI token & CI badge',
      'Full fix list + Decoy Kit',
    ],
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
  dbFile: path.join(DATA_DIR, 'revscan.sqlite'),
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
  cli: path.join(ROOT, 'cli', 'revscan.py'),
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
