'use strict';

/**
 * Unit tests for web pricing config, report redaction, and HTML rendering.
 * Runs on Node 16+ without requiring node:sqlite.
 *
 *   node tests/test_web_views.js
 */

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'trapkey-views-'));
process.env.DATA_DIR = TMP;
process.env.ADMIN_KEY = 'test-admin-key';

const config = require('../web/config');
const views = require('../web/views');
const i18n = require('../web/i18n');

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

function sampleReport() {
  return {
    file: 'App.exe',
    sha256: 'a'.repeat(64),
    size: 20480,
    kind: 'dotnet',
    risk: 88,
    p_success: 0.95,
    crack_seconds_best: 8.2,
    crack_seconds_worst: 24.0,
    crack_seconds: {
      'cloud-fast': { label: 'Claude/GPT class (API)', seconds: 8.2 },
    },
    read_budget_tokens: 14000,
    rounds: 1.8,
    tool_seconds: 2.0,
    confidence: 'model+measured',
    model_notes: ['named licence functions (2)'],
    measured: {
      seconds: 3.2,
      model: 'gpt-6-luna',
      success: true,
      output_sample: 'FUNCTION: LicenseManager::Validate\nSECRET',
    },
    findings: [
      { id: 'named-functions', weight: 25, detail: 'CheckLicense', fix: 'rename it' },
      { id: 'dotnet-readable', weight: 15, detail: 'readable IL', fix: 'obfuscate it' },
      { id: 'pdb-path', weight: 15, detail: 'C:\\src\\app.pdb', fix: 'strip pdb' },
      { id: 'anti-debug', weight: -8, detail: 'IsDebuggerPresent', fix: 'keep it' },
    ],
    crack_simulation: {
      seconds: 8.2,
      model: 'gpt-6-luna',
      success: true,
      output_sample: 'STRATEGY: patch-branch\nOFFSET: 0x0006',
      patch: {
        strategy: 'patch-branch',
        offset: 6,
        original: '2c05',
        patched: '2d05',
        patch_size: 2,
        explanation: 'flip brfalse.s to brtrue.s',
        confidence: 'high',
        verified: true,
        verify_reason: 'bytes match',
        method: 'LicenseManager::Validate',
        difficulty: 'TRIVIAL',
      },
    },
  };
}

test('plans match pricing pivot (Free / Audit Pass $49 / Annual CI $199)', () => {
  assert.deepEqual(Object.keys(config.plans), ['free', 'audit', 'annual']);

  assert.equal(config.plans.free.price, 0);
  assert.equal(config.plans.free.staticCredits, 5);
  assert.equal(config.plans.free.aiCredits, 3);
  assert.equal(config.plans.free.fullReport, false);

  assert.equal(config.plans.audit.price, 49);
  assert.equal(config.plans.audit.oneTime, true);
  assert.equal(config.plans.audit.periodDays, 30);
  assert.equal(config.plans.audit.staticCredits, 10);
  assert.equal(config.plans.audit.aiCredits, 3);
  assert.equal(config.plans.audit.fullReport, true);

  assert.equal(config.plans.annual.price, 199);
  assert.equal(config.plans.annual.oneTime, false);
  assert.equal(config.plans.annual.periodDays, 365);
  assert.equal(config.plans.annual.unlimitedStatic, true);
  assert.equal(config.plans.annual.aiCredits, 50);
  assert.equal(config.plans.annual.fullReport, true);
});

test('summaryReport caps leaks to 2, strips fixes, and hides crack patch bytes', () => {
  const red = views.summaryReport(sampleReport());
  const leaks = red.findings.filter((f) => f.weight > 0);
  const guards = red.findings.filter((f) => f.weight <= 0);

  assert.equal(red.redacted, true);
  assert.equal(leaks.length, 2);
  assert.equal(guards.length, 1);
  assert.ok(red.findings.every((f) => !('fix' in f)));

  assert.equal(red.measured.output_sample, undefined);
  assert.equal(red.crack_simulation.redacted, true);
  assert.equal(red.crack_simulation.output_sample, undefined);
  assert.equal(red.crack_simulation.patch.strategy, 'patch-branch');
  assert.equal(red.crack_simulation.patch.difficulty, 'TRIVIAL');
  assert.equal(red.crack_simulation.patch.patch_size, 2);
  assert.equal(red.crack_simulation.patch.original, undefined);
  assert.equal(red.crack_simulation.patch.patched, undefined);
  assert.equal(red.crack_simulation.patch.offset, undefined);
  assert.equal(red.crack_simulation.patch.method, undefined);
  assert.equal(red.crack_simulation.patch.explanation, undefined);
});

test('reportView hides patch bytes for free/anon and renders them for paid', () => {
  const full = sampleReport();
  const summary = views.summaryReport(full);

  const freeHtml = views.reportView(summary, { full: false, authenticated: true });
  assert.match(freeHtml, /CRACK SIMULATION/);
  assert.match(freeHtml, /patch-branch/);
  assert.match(freeHtml, /TRIVIAL/);
  assert.match(freeHtml, /Audit Pass \(\$49\)/);
  assert.match(freeHtml, /Còn <strong>1<\/strong> phát hiện nữa/);
  assert.doesNotMatch(freeHtml, /2c05/);
  assert.doesNotMatch(freeHtml, /LicenseManager::Validate/);
  assert.doesNotMatch(freeHtml, /Đăng nhập<\/a>/);

  const anonHtml = views.reportView(summary, { full: false, authenticated: false });
  assert.match(anonHtml, /Đăng nhập/);
  assert.match(anonHtml, /Audit Pass \(\$49\)/);
  assert.doesNotMatch(anonHtml, /2c05/);

  const paidHtml = views.reportView(full, { full: true, authenticated: true });
  assert.match(paidHtml, /CRACK SIMULATION — gpt-6-luna, 8\.2s/);
  assert.match(paidHtml, /LicenseManager::Validate/);
  assert.match(paidHtml, /offset 0x0006: 2c05 → 2d05/);
  assert.match(paidHtml, /flip brfalse\.s to brtrue\.s/);
  assert.doesNotMatch(paidHtml, /Còn <strong>/);
});

test('reportView escapes XSS inside crack simulation fields', () => {
  const r = sampleReport();
  r.crack_simulation.model = '<script>alert(1)</script>';
  r.crack_simulation.patch.method = '<img src=x onerror=alert(1)>';
  r.crack_simulation.patch.explanation = '<b>bad</b>';
  const html = views.reportView(r, { full: true, authenticated: true });
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(!html.includes('<img src=x'));
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(html.includes('&lt;img src=x'));
});

test('pricingPage renders Free, Audit Pass ($49 one-time), Annual CI ($199/year), and Consulting', () => {
  const html = views.pricingPage({ account: { plan: 'free' } });
  assert.match(html, /Audit Pass/);
  assert.match(html, /\$49<span> mua đứt<\/span>/);
  assert.match(html, /Annual CI/);
  assert.match(html, /\$199<span>\/năm<\/span>/);
  assert.match(html, /Consulting — \$500–2,000\/lần/);
  assert.match(html, /data-checkout="audit"/);
  assert.match(html, /data-checkout="annual"/);
  assert.doesNotMatch(html, /\/tháng<\/span>/);
});

test('dashboard renders infinity for Annual CI static credits and expiry label for Audit Pass', () => {
  const auditHtml = views.dashboard({
    account: {
      email: 'a@test.dev',
      plan: 'audit',
      credits_static: 10,
      credits_ai: 3,
      period_start: Date.now(),
    },
    scans: [],
  });
  assert.match(auditHtml, /hết hạn gói/);
  assert.match(auditHtml, /gói <strong>Audit Pass<\/strong>/);

  const annualHtml = views.dashboard({
    account: {
      email: 'b@test.dev',
      plan: 'annual',
      credits_static: 999999,
      credits_ai: 50,
      period_start: Date.now(),
    },
    scans: [],
  });
  assert.match(annualHtml, /stat-num">∞<\/div>/);
  assert.match(annualHtml, /reset tiếp theo/);
});

test('adminPage renders audit and annual grant buttons', () => {
  const html = views.adminPage({
    accounts: [{ email: 'x@y.z', plan: 'free', credits_static: 5, credits_ai: 3, created_at: Date.now() }],
    scans: [],
    stats: { accounts: 1, scans: 0, scans24h: 0, aiScans: 0, cacheHits: 0 },
  });
  assert.match(html, /data-plan="audit"/);
  assert.match(html, /data-plan="annual"/);
  assert.doesNotMatch(html, /data-plan="pro"/);
  assert.doesNotMatch(html, /data-plan="team"/);
});

test('high-tech UI has zero emojis and zero CSS gradients', () => {
  const css = fs.readFileSync(path.join(__dirname, '..', 'web', 'static', 'app.css'), 'utf8');
  assert.doesNotMatch(css, /gradient\s*\(/i, 'CSS must contain zero gradients');

  const viewsSrc = fs.readFileSync(path.join(__dirname, '..', 'web', 'views.js'), 'utf8');
  const forbidden = /[⚡⚠️❌🔒🔴🟠🟢🜂⇪✓✗]/u;
  assert.doesNotMatch(viewsSrc, forbidden, 'views.js must contain zero emojis');

  const pages = [
    views.landing({ lang: 'vi' }),
    views.landing({ lang: 'en' }),
    views.reportView(sampleReport(), { full: true, authenticated: true, lang: 'en' }),
    views.reportView(views.summaryReport(sampleReport()), { full: false, authenticated: false, lang: 'vi' }),
    views.pricingPage({ account: null, lang: 'en' }),
    views.dashboard({
      account: { email: 'a@b.c', plan: 'free', credits_static: 5, credits_ai: 3, period_start: Date.now() },
      scans: [{ id: 'scn_1', filename: 'app.exe', kind: 'dotnet', risk: 85, crack_seconds: 10, created_at: Date.now() }],
      lang: 'en',
    }),
  ];
  for (const html of pages) {
    assert.doesNotMatch(html, forbidden);
  }
});

test('multilanguage (vi + en) switches copy and renders language toggle', () => {
  assert.equal(i18n.normalizeLang('EN-us'), 'en');
  assert.equal(i18n.normalizeLang('vi'), 'vi');
  assert.equal(i18n.normalizeLang('unknown'), 'vi');

  const parseCookies = (h) => ({ tk_lang: h.includes('tk_lang=en') ? 'en' : 'vi' });
  assert.equal(
    i18n.langFromRequest(new URL('http://x/pricing?lang=en'), '', parseCookies),
    'en'
  );
  assert.equal(
    i18n.langFromRequest(new URL('http://x/pricing'), 'tk_lang=en', parseCookies),
    'en'
  );
  assert.equal(
    i18n.langFromRequest(new URL('http://x/pricing'), '', parseCookies),
    'vi'
  );

  const enLanding = views.landing({ lang: 'en', currentPath: '/' });
  assert.match(enLanding, /<html lang="en">/);
  assert.match(enLanding, /See how fast AI cracks/);
  assert.match(enLanding, /href="\/lang\/vi\?next=%2F"/);
  assert.match(enLanding, /href="\/lang\/en\?next=%2F" class="active"/);

  const enPricing = views.pricingPage({ account: null, lang: 'en', currentPath: '/pricing' });
  assert.match(enPricing, /\$49<span> one-time<\/span>/);
  assert.match(enPricing, /\$199<span>\/year<\/span>/);
  assert.match(enPricing, /10 static scans \(30-day pass\)/);

  const enReport = views.reportView(views.summaryReport(sampleReport()), {
    full: false,
    authenticated: true,
    lang: 'en',
  });
  assert.match(enReport, /<span class="tag lock">LOCKED<\/span> Unlock target method/);
  assert.match(enReport, /Upgrade to <a href="\/pricing">Audit Pass/);
});

test('supports 10-15 languages and renders all 12 cleanly', () => {
  assert.ok(Array.isArray(i18n.LANGUAGES));
  assert.ok(i18n.LANGUAGES.length >= 10 && i18n.LANGUAGES.length <= 15, `expected 10-15 languages, got ${i18n.LANGUAGES.length}`);
  assert.equal(i18n.LANGUAGES.length, 12);

  for (const item of i18n.LANGUAGES) {
    assert.equal(i18n.normalizeLang(item.code), item.code);
    const land = views.landing({ lang: item.code, currentPath: '/' });
    assert.match(land, new RegExp(`<html lang="${item.code}">`));
    assert.match(land, /id="taglineReveal"/);
    assert.match(land, /class="reveal-word"/);
    const price = views.pricingPage({ account: null, lang: item.code, currentPath: '/pricing' });
    assert.match(price, /\$49/);
    assert.match(price, /\$199/);
    const feats = i18n.planFeatures(item.code, 'audit', []);
    assert.ok(Array.isArray(feats) && feats.length >= 3, `missing audit features for ${item.code}`);
  }
});

test('ai-design-skills rules: flat dark surfaces, no 1-sided card borders, no italics/800+, no alert(), structural UI present', () => {
  const css = fs.readFileSync(path.join(__dirname, '..', 'web', 'static', 'app.css'), 'utf8');
  assert.doesNotMatch(css, /font-style\s*:\s*italic/i);
  assert.doesNotMatch(css, /font-weight\s*:\s*(800|900)\b/);

  // Ensure card components do not use single-sided borders.
  const cardSelectorRe = /\.(card|finding|crack-sim|card-soft|plan|preview-card)\b[^{]*\{([^}]*)\}/g;
  let m;
  while ((m = cardSelectorRe.exec(css)) !== null) {
    assert.doesNotMatch(
      m[2],
      /\bborder-(top|right|bottom|left)\s*:/,
      `Single-sided border found in .${m[1]} rule`
    );
  }

  const viewsSrc = fs.readFileSync(path.join(__dirname, '..', 'web', 'views.js'), 'utf8');
  assert.doesNotMatch(viewsSrc, /\b(?:window\.)?alert\s*\(/);

  const html = views.landing({ lang: 'en', currentPath: '/' });
  assert.match(html, /class="skip-link"/);
  assert.match(html, /id="taglineReveal"/);
  assert.match(html, /class="reveal-word"/);
  assert.match(html, /class="lang-menu"/);
  assert.match(html, /class="mobile-drawer"/);
  const pricingHtml = views.pricingPage({ account: null, lang: 'en', currentPath: '/pricing' });
  assert.match(pricingHtml, /id="checkoutNotice"/);
});

test('landing interactive preview switcher and demoPage render all 4 scenarios cleanly', () => {
  const land = views.landing({ lang: 'vi', currentPath: '/' });
  assert.match(land, /data-demo-tab="before"/);
  assert.match(land, /data-demo-tab="after"/);
  assert.match(land, /href="\/demo"/);

  for (const sample of ['dotnet', 'native', 'protected', 'compare']) {
    const html = views.demoPage({ sample, lang: 'vi', currentPath: `/demo?sample=${sample}` });
    assert.match(html, /class="demo-banner"/);
    assert.match(html, /class="demo-tabs"/);
  }

  const enDemo = views.demoPage({ sample: 'dotnet', lang: 'en', currentPath: '/demo' });
  assert.match(enDemo, /Frontier AI \(API\)/);
  assert.doesNotMatch(enDemo, /AI mạnh nhất/);
});

let failed = 0;
for (const t of tests) {
  try {
    t.fn();
    console.log(`  ok   ${t.name}`);
  } catch (err) {
    failed += 1;
    console.log(`  FAIL ${t.name}`);
    console.log(`       ${err.stack || err.message}`);
  }
}

try {
  fs.rmSync(TMP, { recursive: true, force: true });
} catch {}

console.log(`\n${tests.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
