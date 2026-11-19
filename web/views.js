'use strict';

const fs = require('node:fs');
const path = require('node:path');
const config = require('./config');
const demo = require('./demo');
const { LANGUAGES, normalizeLang, planFeatures, t } = require('./i18n');

/* ------------------------------- helpers ------------------------------- */

function assetUrl(name) {
  try {
    const st = fs.statSync(path.join(__dirname, 'static', name));
    return `/static/${name}?v=${Math.floor(st.mtimeMs).toString(36)}`;
  } catch {
    return `/static/${name}`;
  }
}

const esc = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));

function duration(seconds, lang = 'vi') {
  const s = Number(seconds) || 0;
  if (s < 90) return `${Math.round(s)}s`;
  if (s < 3600) return `${(s / 60).toFixed(1)} ${t(lang, 'minUnit')}`;
  return `${(s / 3600).toFixed(1)} ${t(lang, 'hrUnit')}`;
}

const verdict = (p) => (p >= 0.8 ? 'likely' : p >= 0.5 ? 'possible' : 'unlikely');
const riskClass = (risk) => (risk >= 70 ? 'bad' : risk >= 40 ? 'warn' : 'ok');
const redact = (name) => {
  const base = String(name || 'file');
  const dot = base.lastIndexOf('.');
  const stem = dot > 0 ? base.slice(0, dot) : base;
  const ext = dot > 0 ? base.slice(dot) : '';
  return `${stem.slice(0, 2)}***${ext}`;
};

const FAVICON =
  "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>" +
  "<rect width='32' height='32' rx='6' fill='%23000000'/>" +
  "<rect x='4' y='4' width='24' height='24' rx='4' fill='none' stroke='%23ffffff' stroke-width='2'/>" +
  "<rect x='12' y='12' width='8' height='8' rx='1' fill='%23ffffff'/></svg>";

// Clean Phosphor-style stroke icons (no Material Icons, no emojis)
const ICON_UPLOAD =
  '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M12 16V4M12 4l-4.5 4.5M12 4l4.5 4.5M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg>';

const ICON_GLOBE =
  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>';

const ICON_MENU =
  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="1.75" stroke-linecap="round" aria-hidden="true">' +
  '<line class="line line-1" x1="4" y1="8" x2="20" y2="8"/>' +
  '<line class="line line-2" x1="4" y1="12" x2="20" y2="12"/>' +
  '<line class="line line-3" x1="4" y1="16" x2="20" y2="16"/></svg>';

const ICON_THEME =
  '<svg class="theme-sun" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>' +
  '<svg class="theme-moon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

/* ------------------------------- layout -------------------------------- */

function layout({
  title,
  body,
  account,
  active = '',
  bodyClass = '',
  lang = 'vi',
  currentPath = '/',
}) {
  const L = normalizeLang(lang);
  const nav = [
    ['/demo', t(L, 'navDemo'), 'demo'],
    ['/scan', t(L, 'navScan'), 'scan'],
    ['/compare', t(L, 'navCompare'), 'compare'],
    ['/pricing', t(L, 'navPricing'), 'pricing'],
  ];
  const navHtml = nav
    .map(
      ([href, label, key]) =>
        `<a href="${href}" class="${active === key ? 'active' : ''}">${esc(label)}</a>`
    )
    .join('');

  const authHref = account ? '/app' : '/login';
  const authLabel = account ? t(L, 'navDashboard') : t(L, 'navLogin');

  const safePath = currentPath && currentPath.startsWith('/') ? currentPath : '/';
  const next = encodeURIComponent(safePath);
  const activeLang = LANGUAGES.find((item) => item.code === L) || LANGUAGES[0];
  const langLinks = LANGUAGES.map(
    (item) =>
      `<a href="/lang/${item.code}?next=${next}" class="${item.code === L ? 'active' : ''}">` +
      `<span>${esc(item.label)}</span><span class="code">${esc(item.short)}</span></a>`
  ).join('');

  const langMenu = `<details class="lang-menu">
    <summary aria-label="Language">${ICON_GLOBE}<span>${esc(activeLang.short)}</span></summary>
    <div class="lang-popover">${langLinks}</div>
  </details>`;

  const drawerLinks = [
    ...nav.map(([href, label]) => `<a href="${href}">${esc(label)}</a>`),
    `<a href="${authHref}">${esc(authLabel)}</a>`,
    ...(account ? [`<a href="/app/settings">${esc(t(L, 'navSettings'))}</a>`] : []),
  ].join('');

  const desc = 'Scan a Windows binary and see how many seconds an AI reverse-engineering agent needs to crack it.';

  return `<!doctype html>
<html lang="${L}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · RevScan</title>
<meta name="description" content="${esc(desc)}">
<meta property="og:title" content="${esc(title)} · RevScan">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:type" content="website">
<link rel="stylesheet" href="${assetUrl('app.css')}">
<link rel="icon" href="${FAVICON}">
<script>(function(){try{var s=localStorage.getItem('tk_theme');var t=(s==='light'||s==='dark')?s:(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');document.documentElement.setAttribute('data-theme',t);}catch(e){}})();</script>
</head>
<body class="${bodyClass}">
<div class="scroll-rail" id="scrollRail" aria-hidden="true"></div>
<a class="skip-link" href="#main-content">${esc(t(L, 'skipLink'))}</a>
<div class="nav-wrap">
  <header class="nav">
    <a class="brand" href="/"><span class="brand-dot" aria-hidden="true"></span>RevScan</a>
    <nav class="nav-links" aria-label="Primary">${navHtml}</nav>
    <div class="nav-right">
      <button class="theme-btn" id="themeToggle" type="button" aria-label="${esc(t(L, 'themeToggle'))}" aria-pressed="false">${ICON_THEME}</button>
      ${langMenu}
      ${account
        ? `<span class="who">${esc(account.email)}</span><a class="btn ${active === 'app' ? '' : 'ghost'} sm nav-auth" href="/app">${esc(t(L, 'navDashboard'))}</a><a class="btn ghost sm nav-settings" href="/app/settings">${esc(t(L, 'navSettings'))}</a>`
        : `<a class="btn ${active === 'app' ? '' : 'ghost'} sm nav-auth" href="/login">${esc(t(L, 'navLogin'))}</a>`}
      <button class="menu-btn" id="menuToggle" type="button" aria-expanded="false" aria-controls="mobileDrawer" aria-label="${esc(t(L, 'menuOpen'))}">${ICON_MENU}</button>
    </div>
  </header>
</div>
<div class="mobile-drawer" id="mobileDrawer" aria-hidden="true">${drawerLinks}</div>
<main id="main-content">${body}</main>
<footer class="foot">
  <div>
    <strong>RevScan</strong> — ${esc(t(L, 'footerTagline'))}
    <span class="muted">${esc(t(L, 'footerNotice'))}</span>
  </div>
  <div class="muted">
    <a href="/legal/privacy">${esc(t(L, 'footerPrivacy'))}</a> ·
    <a href="/docs/calibration">${esc(t(L, 'footerTerms'))}</a> ·
    <a href="/pricing">${esc(t(L, 'navPricing'))}</a> ·
    <a href="/scan">${esc(t(L, 'navScan'))}</a>
  </div>
</footer>
<script src="${assetUrl('motion.js')}" defer></script>
</body>
</html>`;
}

/* ------------------------------- landing ------------------------------- */

function landing({ lang = 'vi', currentPath = '/' } = {}) {
  const L = normalizeLang(lang);
  const taglineWords = esc(t(L, 'taglineReveal'))
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => `<span class="reveal-word">${w}</span>`)
    .join(' ');

  const body = `
<section class="hero-stage">
  <div class="hero-grid">
    <div class="hero-copy">
      <div class="kicker motion-in" style="--d:0"><span class="pulse-dot" aria-hidden="true"></span>${esc(t(L, 'landingKicker'))}</div>
      <h1 class="hero-title motion-in" style="--d:1"><span class="hero-line">${esc(t(L, 'landingH1Line1'))}</span><span class="hero-line hero-accent">${esc(t(L, 'landingH1Line2'))}</span></h1>
      <p class="hero-sub motion-in" style="--d:2">${t(L, 'landingLede')}</p>
      <div class="cta-row motion-in" style="--d:3"><a class="btn" href="/scan">${esc(t(L, 'landingCtaPrimary'))}<span class="btn-arrow" aria-hidden="true">→</span></a><a class="btn ghost" href="/demo">${esc(t(L, 'heroCtaDemo'))}</a></div>
    </div>
    <div class="hero-showcase motion-in" style="--d:4">
      <div class="xray-stage" data-tilt>
        <div class="xray-head">
          <div class="xray-win"><span class="win-dot"></span><span class="win-dot"></span><span class="win-dot"></span><span class="xray-file" id="xrayFile">InvoicePro.exe</span></div>
          <div class="demo-tabs segmented">
            <button class="demo-tab active" type="button" data-demo-tab="before" data-file="InvoicePro.exe" aria-pressed="true"><span class="status-dot bad" aria-hidden="true"></span>${esc(t(L, 'demoBeforeTab'))}</button>
            <button class="demo-tab" type="button" data-demo-tab="after" data-file="InvoicePro.protected.exe" aria-pressed="false"><span class="status-dot ok" aria-hidden="true"></span>${esc(t(L, 'demoAfterTab'))}</button>
          </div>
        </div>
        <div class="xray-panel panel-enter" data-demo-panel="before">
          <div class="xray-metrics">
            <span class="xray-big bad">~8.2s</span>
            <span class="xray-mid bad">risk 88/100</span>
            <span class="xray-mid">p=0.95</span>
            <svg class="xray-ring" width="44" height="44" viewBox="0 0 36 36" aria-hidden="true"><circle cx="18" cy="18" r="16" fill="none" stroke="var(--surface-2, #171920)" stroke-width="3"/><circle cx="18" cy="18" r="16" fill="none" stroke="var(--bad, #ef4444)" stroke-width="3" stroke-dasharray="100.5" stroke-dashoffset="${100.5 * (1 - 0.88)}" transform="rotate(-90 18 18)"/></svg>
          </div>
          <div class="byte-stream">
            <div class="scan-beam" aria-hidden="true"></div>
            <div class="byte-label">LicenseService::CheckLicenseKey</div>
            <div class="byte-cells"><span class="bcell flip">2D</span><span class="bcell flip">0C</span><span class="bcell">→</span><span class="bcell flip">2C</span><span class="bcell flip">0C</span></div>
            <div class="byte-tag">${esc(t(L, 'xrayBeforeBadge'))}</div>
          </div>
          <div class="xray-chips"><span class="xchip bad">${esc(t(L, 'xrayBeforeChip1'))}</span><span class="xchip bad">${esc(t(L, 'xrayBeforeChip2'))}</span></div>
          <p class="xray-plain">${esc(t(L, 'demoBeforePlain'))}</p>
        </div>
        <div class="xray-panel" data-demo-panel="after" hidden>
          <div class="xray-metrics">
            <span class="xray-big ok">~14.2 ${esc(t(L, 'minUnit'))}</span>
            <span class="xray-mid ok">risk 34/100</span>
            <span class="xray-mid">p=0.38</span>
            <svg class="xray-ring" width="44" height="44" viewBox="0 0 36 36" aria-hidden="true"><circle cx="18" cy="18" r="16" fill="none" stroke="var(--surface-2, #171920)" stroke-width="3"/><circle cx="18" cy="18" r="16" fill="none" stroke="var(--ok, #10b981)" stroke-width="3" stroke-dasharray="100.5" stroke-dashoffset="${100.5 * (1 - 0.34)}" transform="rotate(-90 18 18)"/></svg>
          </div>
          <div class="decoy-mesh">
            <div class="decoy-label">${esc(t(L, 'xrayAfterResult'))}</div>
            <div class="decoy-nodes">${Array.from({length: 14}, (_, i) => `<span class="dnode">#${String(i + 1).padStart(2, '0')}</span>`).join('')}</div>
          </div>
          <div class="xray-chips"><span class="xchip ok">${esc(t(L, 'xrayAfterChip1'))}</span><span class="xchip ok">${esc(t(L, 'xrayAfterChip2'))}</span></div>
          <p class="xray-plain">${esc(t(L, 'demoAfterPlain'))}</p>
        </div>
        <div class="xray-foot">
          <span class="caption-5 muted">InvoicePro.exe vs InvoicePro.protected.exe</span>
          <a class="xray-link" href="/demo">${esc(t(L, 'demoOpenFull'))} →</a>
        </div>
      </div>
    </div>
  </div>
  <div class="hero-hud">
    <div class="hud-pillars">${esc(t(L, 'landingProof'))}</div>
    <div class="hud-stats"><span class="hud-stat"><strong data-count="260" data-suffix="+">260+</strong> ${esc(t(L, 'hudTestsLabel'))}</span><span class="hud-stat"><strong data-count="12">12</strong> ${esc(t(L, 'hudLangsLabel'))}</span><span class="hud-stat"><strong>0</strong> ${esc(t(L, 'hudDepsLabel'))}</span></div>
    <div class="hud-scroll"><span class="hud-scroll-label">SCROLL</span><span class="hud-scroll-track"><span id="hudScrollFill"></span></span><span class="hud-scroll-pct" id="scrollPct">0%</span></div>
  </div>
</section>

<section class="section reveal-block">
  <div class="card wide">
    <div class="step">${esc(t(L, 'problemKicker'))}</div>
    <h2 class="heading-5">${esc(t(L, 'problemTitle'))}</h2>
    <p class="body-3 muted" style="margin-bottom:0">${esc(t(L, 'problemBody'))}</p>
  </div>
</section>

<section class="tagline-reveal-section">
  <div class="tagline-reveal" id="taglineReveal">
    <p class="heading-3" style="margin:0">${taglineWords}</p>
  </div>
</section>

<section class="section reveal-block">
  <div class="step">${esc(t(L, 'benefitsKicker'))}</div>
  <h2 class="heading-4" style="margin-bottom:var(--s-300)">${esc(t(L, 'benefitsTitle'))}</h2>
  <div class="bento-grid">
    <article class="card bento-card" data-spotlight>
      <div class="bento-visual"><svg width="84" height="84" viewBox="0 0 80 80" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="40" cy="40" r="30" opacity="0.2"/><circle cx="40" cy="40" r="20" opacity="0.4"/><circle cx="40" cy="40" r="10"/><line x1="40" y1="10" x2="40" y2="6"/><line x1="40" y1="70" x2="40" y2="74"/><line x1="10" y1="40" x2="6" y2="40"/><line x1="70" y1="40" x2="74" y2="40"/></svg></div>
      <div class="step">01</div>
      <h3 class="heading-6">${esc(t(L, 'step1Title'))}</h3>
      <p class="body-6 muted" style="margin-bottom:0">${t(L, 'step1Body')}</p>
    </article>
    <article class="card bento-card" data-spotlight>
      <div class="bento-visual"><svg width="84" height="84" viewBox="0 0 80 80" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M20 60 L40 20 L60 60" opacity="0.3"/><circle cx="40" cy="20" r="4"/><circle cx="25" cy="50" r="3"/><circle cx="55" cy="50" r="3"/><line x1="40" y1="24" x2="25" y2="47" stroke-dasharray="3 3"/><line x1="40" y1="24" x2="55" y2="47" stroke-dasharray="3 3"/><line x1="25" y1="50" x2="55" y2="50" stroke-dasharray="3 3"/></svg></div>
      <div class="step">02</div>
      <h3 class="heading-6">${esc(t(L, 'step2Title'))}</h3>
      <p class="body-6 muted" style="margin-bottom:0">${t(L, 'step2Body')}</p>
    </article>
    <article class="card bento-card" data-spotlight>
      <div class="bento-visual"><svg width="84" height="84" viewBox="0 0 80 80" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="15" y="50" width="12" height="20" rx="2" opacity="0.3"/><rect x="34" y="30" width="12" height="40" rx="2" opacity="0.5"/><rect x="53" y="15" width="12" height="55" rx="2"/><line x1="10" y1="70" x2="70" y2="70" opacity="0.2"/></svg></div>
      <div class="step">03</div>
      <h3 class="heading-6">${esc(t(L, 'step3Title'))}</h3>
      <p class="body-6 muted" style="margin-bottom:0">${t(L, 'step3Body')}</p>
    </article>
  </div>
</section>

<section class="pipeline-section section reveal-block">
  <div class="step">${esc(t(L, 'howKicker'))}</div>
  <h2 class="heading-4" style="margin-bottom:var(--s-100)">${esc(t(L, 'howTitle'))}</h2>
  <p class="muted" style="max-width:640px">${esc(t(L, 'howSubtitle'))}</p>
  <div class="pipeline-track">
    <div class="pipe-node card">
      <div class="step">STEP 01</div>
      <h3 class="title-2">${esc(t(L, 'how1Title'))}</h3>
      <p class="body-6 muted" style="margin-bottom:0">${t(L, 'how1Body')}</p>
    </div>
    <svg class="pipe-connector" width="40" height="20" viewBox="0 0 40 20" aria-hidden="true"><line x1="0" y1="10" x2="40" y2="10" stroke="currentColor" stroke-width="1.5" stroke-dasharray="4 4" opacity="0.3"/></svg>
    <div class="pipe-node card">
      <div class="step">STEP 02</div>
      <h3 class="title-2">${esc(t(L, 'how2Title'))}</h3>
      <p class="body-6 muted" style="margin-bottom:0">${t(L, 'how2Body')}</p>
    </div>
    <svg class="pipe-connector" width="40" height="20" viewBox="0 0 40 20" aria-hidden="true"><line x1="0" y1="10" x2="40" y2="10" stroke="currentColor" stroke-width="1.5" stroke-dasharray="4 4" opacity="0.3"/></svg>
    <div class="pipe-node card">
      <div class="step">STEP 03</div>
      <h3 class="title-2">${esc(t(L, 'how3Title'))}</h3>
      <p class="body-6 muted" style="margin-bottom:0">${t(L, 'how3Body')}</p>
    </div>
  </div>
</section>

<section class="faq-split section reveal-block">
  <div class="faq-intro">
    <h2 class="heading-5">${esc(t(L, 'formulaHeading'))}</h2>
    <p class="body-3 muted">${t(L, 'formulaExplain')}</p>
    <div class="formula-box">
      <code>seconds = tool_time + read_budget / prefill_rate + rounds * 1200 / decode_rate</code>
    </div>
  </div>
  <div class="faq-list">
    <h2 class="heading-5">${esc(t(L, 'faqTitle'))}</h2>
    <details class="faq"><summary>${esc(t(L, 'faq1Q'))}<span class="faq-icon" aria-hidden="true">+</span></summary><p>${esc(t(L, 'faq1A'))}</p></details>
    <details class="faq"><summary>${esc(t(L, 'faq2Q'))}<span class="faq-icon" aria-hidden="true">+</span></summary><p>${esc(t(L, 'faq2A'))}</p></details>
    <details class="faq"><summary>${esc(t(L, 'faq3Q'))}<span class="faq-icon" aria-hidden="true">+</span></summary><p>${esc(t(L, 'faq3A'))}</p></details>
    <details class="faq"><summary>${esc(t(L, 'faq4Q'))}<span class="faq-icon" aria-hidden="true">+</span></summary><p>${esc(t(L, 'faq4A'))}</p></details>
    <details class="faq"><summary>${esc(t(L, 'faq5Q'))}<span class="faq-icon" aria-hidden="true">+</span></summary><p>${esc(t(L, 'faq5A'))}</p></details>
    <details class="faq"><summary>${esc(t(L, 'faq6Q'))}<span class="faq-icon" aria-hidden="true">+</span></summary><p>${esc(t(L, 'faq6A'))}</p></details>
  </div>
</section>

<section class="cta-stage reveal-block">
  <div class="stage-orb" aria-hidden="true"></div>
  <h2 class="heading-3" style="max-width:680px;margin:0 auto var(--s-200)">${esc(t(L, 'finalCtaTitle'))}</h2>
  <p class="lede body-3 muted">${esc(t(L, 'finalCtaBody'))}</p>
  <div class="cta-row">
    <a class="btn" href="/scan">${esc(t(L, 'landingCtaPrimary'))}</a>
    <a class="btn ghost" href="/demo">${esc(t(L, 'heroCtaDemo'))}</a>
  </div>
</section>
`;
  return layout({ title: t(L, 'landingTitle'), body, active: '', bodyClass: 'landing-page', lang: L, currentPath });
}

/* -------------------------------- scan -------------------------------- */

function scanPage({
  account,
  anonymousLeft,
  aiAvailable = true,
  aiCooldownSeconds = 0,
  lang = 'vi',
  currentPath = '/scan',
}) {
  const L = normalizeLang(lang);
  const cooling = aiCooldownSeconds > 0;
  const cooldownMinutes = Math.max(1, Math.ceil(aiCooldownSeconds / 60));
  const aiNote = cooling
    ? t(L, 'aiCoolingShort', { m: cooldownMinutes })
    : aiAvailable
      ? ''
      : t(L, 'aiUnconfigured');
  const body = `
<section class="hero compact">
  <h1>${esc(t(L, 'scanHeading'))}</h1>
  <p class="lede muted">${t(L, 'scanLede')}</p>
</section>

<section class="drop" id="drop"
  data-msg-too-large="${esc(t(L, 'uploadTooLarge'))}"
  data-msg-bad-ext="${esc(t(L, 'uploadBadExt'))}"
  data-msg-err-prefix="${esc(t(L, 'uploadErrPrefix'))}"
  data-msg-net-err="${esc(t(L, 'uploadNetErr'))}">
  <input type="file" id="file" accept=".exe,.dll,.bin,.sys" hidden>
  <div class="drop-inner">
    <div class="drop-radar"><svg width="80" height="80" viewBox="0 0 80 80" fill="none" stroke="currentColor" stroke-width="1" aria-hidden="true"><circle cx="40" cy="40" r="36" opacity="0.1"/><circle cx="40" cy="40" r="24" opacity="0.15"/><circle cx="40" cy="40" r="12" opacity="0.2"/></svg>${ICON_UPLOAD}</div>
    <p>${t(L, 'dropPrompt')}</p>
    <p class="caption-5 muted">${esc(t(L, 'dropLimit'))}</p>
    <div class="mode-switch">
      <label class="radio mode-pill"><input type="radio" name="mode" value="static" checked> ${esc(t(L, 'modeStatic'))} <span class="muted">${esc(t(L, 'modeStaticHint'))}</span></label>
      <label class="radio mode-pill"><input type="radio" name="mode" value="ai" ${aiAvailable ? '' : 'disabled'}> ${esc(t(L, 'modeAi'))} <span class="muted">${esc(t(L, 'modeAiHint', { note: aiNote }))}</span></label>
    </div>
    ${cooling ? `<p class="caption-5 muted">${esc(t(L, 'aiCoolingFull', { m: cooldownMinutes }))}</p>` : ''}
    ${account ? '' : `<p class="caption-5 muted">${t(L, 'anonNotice', { left: anonymousLeft })}</p>`}
  </div>
  <div class="progress" id="progress" hidden><div class="bar" id="bar"></div></div>
</section>

<p class="demo-hint caption-5 muted">${t(L, 'scanTryDemo')}</p>

<section id="result"></section>

<section class="privacy-strip" id="privacy">
  <h2>${esc(t(L, 'privacyBoxTitle'))}</h2>
  <div class="privacy-cols">
    <div>${t(L, 'privacyItem1')}</div>
    <div>${esc(t(L, 'privacyItem2'))}</div>
    <div>${t(L, 'privacyItem3')}</div>
  </div>
</section>

<script src="${assetUrl('scan.js')}"></script>
`;
  return layout({
    title: t(L, 'scanTitle'),
    body,
    account,
    active: 'scan',
    bodyClass: 'scan-page',
    lang: L,
    currentPath,
  });
}

/* ------------------------------- report ------------------------------- */

function redactCrackSimulation(cs) {
  if (!cs || typeof cs !== 'object') return cs;
  const out = {
    seconds: cs.seconds,
    model: cs.model,
    success: Boolean(cs.success),
    redacted: true,
  };
  if (cs.error) out.error = cs.error;
  if (cs.reason) out.reason = cs.reason;
  if (cs.patch && typeof cs.patch === 'object') {
    out.patch = {
      strategy: cs.patch.strategy,
      difficulty: cs.patch.difficulty,
      patch_size: cs.patch.patch_size,
      verified: cs.patch.verified,
      confidence: cs.patch.confidence,
      redacted: true,
    };
  }
  return out;
}

function summaryReport(report, limit = 2) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const strip = ({ fix, ...rest }) => rest;
  const allLeaks = findings.filter((f) => f.weight > 0);
  const leaks = allLeaks.slice(0, limit).map(strip);
  const guards = findings.filter((f) => f.weight <= 0).map(strip);
  const out = {
    ...report,
    findings: [...leaks, ...guards],
    hidden_leaks: Math.max(0, allLeaks.length - leaks.length),
    redacted: true,
  };
  if (report.crack_simulation) {
    out.crack_simulation = redactCrackSimulation(report.crack_simulation);
  }
  if (report.measured && report.measured.output_sample) {
    out.measured = { ...report.measured };
    delete out.measured.output_sample;
  }
  return out;
}

function crackSimView(cs, { full = true, authenticated = true, lang = 'vi' } = {}) {
  if (!cs || typeof cs !== 'object') return '';
  const L = normalizeLang(lang);
  if (cs.error) {
    return `<div class="crack-sim">
      <div class="crack-sim-head"><span class="tag bad">ERR</span> ${esc(t(L, 'crackSimError'))}</div>
      <div class="muted caption-5">${esc(cs.error)}</div>
    </div>`;
  }
  if (cs.success && cs.patch) {
    const p = cs.patch;
    const size = Number(p.patch_size || 0);
    const unit = size === 1 ? 'byte' : 'bytes';
    const showPatch = full && !p.redacted && p.original !== undefined;
    const offsetHex = Number(p.offset || 0).toString(16).padStart(4, '0');
    const detailHtml = showPatch
      ? `
        ${p.method ? `<div class="crack-sim-line">Method: <code>${esc(p.method)}</code></div>` : ''}
        <div class="crack-sim-line">Patch: <code>offset 0x${esc(offsetHex)}: ${esc(p.original || '??')} → ${esc(p.patched || '??')}</code></div>
        ${p.explanation ? `<div class="crack-sim-warn"><span class="tag warn">WARN</span> ${esc(p.explanation)}</div>` : ''}
        ${p.verified === false ? `<div class="crack-sim-bad"><span class="tag bad">UNVERIFIED</span> ${esc(t(L, 'crackSimUnverified'))}</div>` : ''}
      `
      : `<div class="paywall"><span class="tag lock">LOCKED</span> ${esc(t(L, 'crackSimPaywallPrefix'))}${
          authenticated ? '' : t(L, 'crackSimLoginPrefix')
        }<a href="/pricing">Audit Pass ($49)</a></div>`;
    return `<div class="crack-sim">
      <div class="crack-sim-head"><span class="tag sim">SIM</span> ${esc(
        t(L, 'crackSimHeader', { model: cs.model || '?', sec: Number(cs.seconds || 0).toFixed(1) })
      )}</div>
      <div class="crack-sim-meta">
        Strategy: <code>${esc(p.strategy || '?')}</code> ·
        Difficulty: <strong>${esc(p.difficulty || '?')}</strong> (${size} ${unit})
      </div>
      ${detailHtml}
    </div>`;
  }
  return `<div class="crack-sim">
    <div class="crack-sim-head"><span class="tag sim">SIM</span> CRACK SIMULATION — ${esc(cs.model || '?')}</div>
    <div class="muted caption-5">${esc(cs.reason || t(L, 'crackSimNoPatch'))}</div>
  </div>`;
}

function reportView(
  report,
  { full = true, authenticated = true, shareUrl = null, filename = null, lang = 'vi' } = {}
) {
  const L = normalizeLang(lang);
  const risk = Number(report.risk || 0);
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const leaks = findings.filter((f) => f.weight > 0);
  const guards = findings.filter((f) => f.weight <= 0);
  const shown = full ? leaks : leaks.slice(0, 2);

  const leakRows = shown
    .map(
      (f) => `
      <li class="finding ${f.weight >= 20 ? 'sev-3' : f.weight >= 10 ? 'sev-2' : 'sev-1'}">
        <span class="chip">-${f.weight}</span>
        <div>
          <div class="fid">${esc(f.id)}</div>
          <div class="fdetail">${esc(f.detail)}</div>
          ${full ? `<div class="ffix">fix: ${esc(f.fix)}</div>` : ''}
        </div>
      </li>`
    )
    .join('');

  const guardRows = guards
    .map(
      (f) => `
      <li class="finding guard">
        <span class="chip ok">+${-f.weight}</span>
        <div><div class="fid">${esc(f.id)}</div><div class="fdetail">${esc(f.detail)}</div></div>
      </li>`
    )
    .join('');

  const secret = Math.max(leaks.length - shown.length, Number(report.hidden_leaks || 0));
  const numLocale = L === 'vi' ? 'vi-VN' : 'en-US';

  return `
<section class="report">
  <div class="report-head">
    <div>
      <div class="caption-5 muted mono">${esc(filename || report.file || '')} · ${esc(report.kind)} · ${Number(report.size || 0).toLocaleString(numLocale)} bytes</div>
      <div class="headline">
        <span class="big">~${duration(report.crack_seconds_best, L)}</span>
        <span class="verdict ${report.p_success >= 0.8 ? 'bad' : report.p_success >= 0.5 ? 'warn' : 'ok'}">
          ${verdict(report.p_success)} · p=${report.p_success}
        </span>
      </div>
      <div class="caption-5 muted">${esc(t(L, 'crackTargetSub'))}</div>
    </div>
    <div class="risk">
      <svg class="risk-dial" width="52" height="52" viewBox="0 0 64 64" aria-hidden="true"><circle cx="32" cy="32" r="28" fill="none" stroke="var(--surface-2, #171920)" stroke-width="4"/><circle cx="32" cy="32" r="28" fill="none" stroke="${risk >= 70 ? 'var(--bad, #ef4444)' : risk >= 40 ? 'var(--warn, #f59e0b)' : 'var(--ok, #10b981)'}" stroke-width="4" stroke-dasharray="175.9" stroke-dashoffset="${(175.9 * (1 - risk / 100)).toFixed(1)}" transform="rotate(-90 32 32)"/></svg>
      <div class="risk-num ${riskClass(risk)}">${risk}<span>/100</span></div>
      <div class="caption-5 muted mono">RISK</div>
    </div>
  </div>

  <div class="riskbar ${riskClass(risk)}"><i style="width:${Math.max(2, risk)}%"></i></div>

  ${crackSimView(report.crack_simulation, { full, authenticated, lang: L })}

  <div class="report-grid">
    <div>
      <h3>${esc(t(L, 'agentReadsTitle'))}</h3>
      <ul class="notes">${(report.model_notes || []).map((n) => `<li>${esc(n)}</li>`).join('')}</ul>
    </div>
    <div>
      <h3>${esc(t(L, 'numbersTitle'))}</h3>
      <table class="kv">
        ${Object.entries(report.crack_seconds || {})
          .map(([, v]) => `<tr><td>${esc(v.label)}</td><td>~${duration(v.seconds, L)}</td></tr>`)
          .join('')}
        <tr><td>P(success)</td><td>${report.p_success}</td></tr>
        <tr><td>${esc(t(L, 'readBudgetLabel'))}</td><td>${Number(report.read_budget_tokens || 0).toLocaleString(numLocale)} tokens</td></tr>
        <tr><td>${esc(t(L, 'roundsLabel'))}</td><td>${report.rounds}</td></tr>
        <tr><td>${esc(t(L, 'toolTimeLabel'))}</td><td>${duration(report.tool_seconds, L)}</td></tr>
        <tr><td>${esc(t(L, 'confidenceLabel'))}</td><td>${esc(report.confidence || 'model')}</td></tr>
        ${
          report.calibration
            ? `<tr><td>calibrated</td><td>k=${esc(report.calibration.k)}${
                report.calibration.model ? ` (${esc(report.calibration.model)})` : ''
              }</td></tr>`
            : ''
        }
        ${
          report.measured
            ? `<tr><td>${esc(t(L, 'measuredLabel'))}</td><td>${duration(report.measured.seconds, L)} · ${esc(
                report.measured.model || ''
              )}</td></tr>`
            : ''
        }
      </table>
    </div>
  </div>

  <h3>${esc(t(L, 'leaksTitle'))}</h3>
  ${shown.length ? `<ul class="findings">${leakRows}</ul>` : `<p class="muted">${esc(t(L, 'noLeaks'))}</p>`}
  ${
    !full && (secret > 0 || leaks.length > 0)
      ? `<p class="paywall">${
          secret > 0 ? `${t(L, 'paywallMore', { n: secret })} ` : ''
        }${
          authenticated ? t(L, 'paywallUpgradePrefix') : t(L, 'paywallLoginOr')
        }${t(L, 'paywallSuffix')}</p>`
      : ''
  }

  ${guards.length ? `<h3>${esc(t(L, 'guardsTitle'))}</h3><ul class="findings">${guardRows}</ul>` : ''}

  ${full && leaks.length ? `
  <h3>${esc(t(L, 'fixesTitle'))}</h3>
  <ol class="fixes">
    ${[...new Set(leaks.map((f) => f.fix))].slice(0, 5).map((f) => `<li>${esc(f)}</li>`).join('')}
  </ol>` : ''}

  <p class="caption-5 muted" style="margin-bottom:0">
    ${t(L, 'reportFooterNote')}
    ${shareUrl ? `· <a href="${esc(shareUrl)}">${esc(t(L, 'shareLinkLabel'))}</a>` : ''}
  </p>
</section>`;
}

/* -------------------------------- login -------------------------------- */

function loginPage({ sent = false, error = null, lang = 'vi', currentPath = '/login' } = {}) {
  const L = normalizeLang(lang);
  const body = `
<section class="panel motion-in">
  <h1>${esc(t(L, 'loginTitle'))}</h1>
  ${error ? `<div class="alert bad">${esc(error)}</div>` : ''}
  ${sent
    ? `<div class="alert ok">${t(L, 'loginSent')}</div>`
    : `<p class="muted">${esc(t(L, 'loginPrompt'))}</p>
       <form method="post" action="/api/auth/request" id="loginForm">
         <label>Email<input type="email" name="email" required placeholder="you@studio.com" autocomplete="email"></label>
         <button class="btn" type="submit">${esc(t(L, 'loginButton'))}</button>
       </form>`}
</section>`;
  return layout({ title: t(L, 'loginTitle'), body, active: 'app', bodyClass: 'center-page', lang: L, currentPath });
}

/* ------------------------------ dashboard ------------------------------ */

function dashboard({ account, scans, apiTokenHint = null, lang = 'vi', currentPath = '/app' }) {
  const L = normalizeLang(lang);
  const plan = config.plans[account.plan] || config.plans.free;
  const features = planFeatures(L, plan.id, plan.features);
  const dateLocale = L === 'vi' ? 'vi-VN' : 'en-US';

  const rows = scans
    .map(
      (s) => `<tr>
        <td><a href="/app/scan/${esc(s.id)}">${esc(redact(s.filename))}</a><div class="caption-5 muted mono">${esc(s.kind)}</div></td>
        <td class="mono"><span class="led ${riskClass(s.risk)}"></span>${s.risk}</td>
        <td class="mono">~${duration(s.crack_seconds, L)}</td>
        <td class="muted mono">${new Date(s.created_at).toLocaleString(dateLocale)}</td>
      </tr>`
    )
    .join('');

  const body = `
<section class="page-head">
  <div>
    <h1>${esc(t(L, 'dashTitle'))}</h1>
    <p class="muted" style="margin-bottom:0">${esc(account.email)} · ${esc(t(L, 'dashPlanPrefix'))} <strong>${esc(plan.label)}</strong></p>
  </div>
  <a class="btn" href="/scan">${esc(t(L, 'dashNewScan'))}</a>
</section>

<section class="grid three">
  <div class="card stat">
    <div class="stat-num">${plan.unlimitedStatic ? '∞' : account.credits_static}</div>
    <div class="stat-label">${esc(t(L, 'dashStaticLeft'))}</div>
  </div>
  <div class="card stat">
    <div class="stat-num">${account.credits_ai}</div>
    <div class="stat-label">${esc(t(L, 'dashAiLeft'))}</div>
  </div>
  <div class="card stat">
    <div class="stat-num">${new Date(account.period_start + (plan.periodDays || 30) * 86400000).toLocaleDateString(dateLocale)}</div>
    <div class="stat-label">${esc(plan.oneTime ? t(L, 'dashExpires') : t(L, 'dashNextReset'))}</div>
  </div>
</section>

<section class="card wide">
  <h2>${esc(t(L, 'dashRecentScans'))}</h2>
  ${rows ? `<table class="table"><thead><tr><th>${esc(t(L, 'dashThFile'))}</th><th>${esc(t(L, 'dashThRisk'))}</th><th>${esc(t(L, 'dashThCrack'))}</th><th>${esc(t(L, 'dashThTime'))}</th></tr></thead><tbody>${rows}</tbody></table>` : `<p class="muted" style="margin-bottom:0">${esc(t(L, 'dashNoScans'))}</p>`}
</section>

<section class="card wide">
  <h2>${esc(plan.label)}</h2>
  <ul class="ticks">${features.map((f) => `<li>${esc(f)}</li>`).join('')}</ul>
  ${account.plan === 'free' ? `<a class="btn" href="/pricing">${esc(t(L, 'dashBuyAudit'))}</a>` : ''}
</section>

${apiTokenHint ? `<section class="card wide"><h2>${esc(t(L, 'dashNewToken'))}</h2><p class="muted">${esc(t(L, 'dashNewTokenHint'))}</p><pre>${esc(apiTokenHint)}</pre></section>` : ''}
`;
  return layout({ title: t(L, 'dashTitle'), body, account, active: 'app', lang: L, currentPath });
}

/* -------------------------------- admin -------------------------------- */

function adminPage({ accounts, scans = [], stats, lang = 'vi', currentPath = '/app/admin' }) {
  const L = normalizeLang(lang);
  const dateLocale = L === 'vi' ? 'vi-VN' : 'en-US';
  const accountRows = accounts
    .map(
      (a) => `<tr>
        <td>${esc(a.email)}</td>
        <td class="mono">${esc(a.plan)}</td>
        <td class="mono">${a.credits_static}/${a.credits_ai}</td>
        <td class="muted mono">${new Date(a.created_at).toLocaleDateString(dateLocale)}</td>
        <td>
          <button class="btn sm ghost" data-grant="${esc(a.email)}" data-plan="audit">→ audit</button>
          <button class="btn sm ghost" data-grant="${esc(a.email)}" data-plan="annual">→ annual</button>
          <button class="btn sm ghost" data-grant="${esc(a.email)}" data-plan="free">→ free</button>
        </td>
      </tr>`
    )
    .join('');

  const scanRows = (Array.isArray(scans) ? scans : [])
    .map(
      (s) => `<tr>
        <td><a href="/r/${esc(s.public_id)}">${esc(redact(s.filename))}</a><div class="caption-5 muted"><code>${esc(s.id)}</code></div></td>
        <td class="mono">${esc(s.mode)}</td>
        <td class="mono"><span class="led ${riskClass(s.risk)}"></span>${Number(s.risk ?? 0)}</td>
        <td class="mono">~${duration(s.crack_seconds, L)}</td>
        <td class="mono">${Number(s.credits_used || 0)}</td>
        <td class="muted mono">${new Date(s.created_at).toLocaleString(dateLocale)}</td>
      </tr>`
    )
    .join('');

  const body = `
<section class="page-head"><h1>Admin</h1><span class="muted mono">${stats.accounts} accounts · ${stats.scans} scans</span></section>

<section class="grid three">
  <div class="card stat"><div class="stat-num">${stats.scans24h}</div><div class="stat-label">scans / 24h</div></div>
  <div class="card stat"><div class="stat-num">${stats.aiScans}</div><div class="stat-label">AI scans</div></div>
  <div class="card stat" title="Authenticated account scans served from 24h cache (event type=cache_hit).">
    <div class="stat-num">${stats.cacheHits}</div><div class="stat-label">cache hits (accounts)</div>
  </div>
</section>

<section class="card wide">
  <h2>Scan gần đây</h2>
  ${scanRows
    ? `<table class="table"><thead><tr><th>File · id</th><th>Mode</th><th>Risk</th><th>Crack</th><th>Credits</th><th>Thời gian</th></tr></thead><tbody>${scanRows}</tbody></table>`
    : '<p class="muted">Chưa có scan nào.</p>'}
  <p class="caption-5 muted" style="margin-bottom:0">50 scan mới nhất. Tên file đã che; link mở báo cáo công khai.</p>
</section>

<section class="card wide">
  <h2>Tài khoản</h2>
  <input id="adminKey" placeholder="admin key" class="mono">
  <table class="table"><thead><tr><th>Email</th><th>Plan</th><th>Credits</th><th>Tạo</th><th></th></tr></thead><tbody>${accountRows}</tbody></table>
  <p class="caption-5 muted" style="margin-bottom:0">Nút đổi gói ghi vào bảng <code>events</code> để audit.</p>
</section>

<script>
const keyInput = document.getElementById('adminKey');
keyInput.value = localStorage.getItem('tk_admin') || '';
document.querySelectorAll('[data-grant]').forEach((btn) => {
  btn.addEventListener('click', async () => {
    localStorage.setItem('tk_admin', keyInput.value);
    const res = await fetch('/api/admin/grant', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-admin-key': keyInput.value },
      body: JSON.stringify({ email: btn.dataset.grant, plan: btn.dataset.plan }),
    });
    const json = await res.json();
    btn.textContent = json.ok ? 'OK' : 'ERR';
    if (json.ok) setTimeout(() => location.reload(), 500);
  });
});
</script>
`;
  return layout({ title: 'Admin', body, lang: L, currentPath });
}

/* ------------------------------- settings ------------------------------ */

function settingsPage({ account, apiTokenHint = null, lang = 'vi', currentPath = '/app/settings' }) {
  const L = normalizeLang(lang);
  const plan = config.plans[account.plan] || config.plans.free;
  const body = `
<section class="page-head"><h1>${esc(t(L, 'settingsTitle'))}</h1></section>

<section class="card wide">
  <h2>${esc(t(L, 'settingsAccount'))}</h2>
  <table class="kv">
    <tr><td>Email</td><td>${esc(account.email)}</td></tr>
    <tr><td>${esc(t(L, 'settingsPlan'))}</td><td>${esc(plan.label || account.plan)}</td></tr>
    <tr><td>${esc(t(L, 'settingsStaticLeft'))}</td><td>${plan.unlimitedStatic ? '∞' : account.credits_static}</td></tr>
    <tr><td>${esc(t(L, 'settingsAiLeft'))}</td><td>${account.credits_ai}</td></tr>
  </table>
</section>

<section class="card wide">
  <h2>${esc(t(L, 'settingsCiToken'))}</h2>
  <p class="muted">${esc(t(L, 'settingsCiHint'))}</p>
  ${apiTokenHint ? `<pre>${esc(apiTokenHint)}</pre>` : ''}
  <pre>curl -X POST ${esc(config.publicUrl)}/api/scan?mode=static \\
  -H "authorization: Bearer $TRAPKEY_TOKEN" \\
  -H "x-filename: App.exe" \\
  --data-binary @dist/App.exe</pre>
  <form method="post" action="/api/api-token">
    <button class="btn" type="submit">${esc(t(L, 'settingsRotateToken'))}</button>
  </form>
</section>

<section class="card wide danger">
  <h2>${esc(t(L, 'settingsDeleteTitle'))}</h2>
  <p class="muted">${esc(t(L, 'settingsDeleteHint'))}</p>
  <form method="post" action="/api/account/delete" onsubmit="return confirm('${esc(t(L, 'settingsDeleteConfirm'))}')">
    <button class="btn ghost" type="submit">${esc(t(L, 'settingsDeleteTitle'))}</button>
  </form>
</section>
`;
  return layout({ title: t(L, 'settingsTitle'), body, account, active: 'app', lang: L, currentPath });
}

/* ------------------------------- compare ------------------------------- */

function compareResultHtml(result, lang = 'vi') {
  if (!result) return '';
  const L = normalizeLang(lang);
  const findingRows = (items, kind) =>
    (items || [])
      .map((f) => {
        const weight = typeof f.weight === 'number' ? f.weight : 0;
        const sign = kind === 'fixed' ? 'OK ' : weight <= 0 ? '+' : '-';
        return `<li class="finding ${kind === 'fixed' ? 'guard' : ''}">
          <span class="chip ${weight <= 0 ? 'ok' : ''}">${sign}${Math.abs(weight)}</span>
          <div><div class="fid">${esc(f.id)}</div><div class="fdetail">${esc(f.detail || '')}</div>
          ${f.fix ? `<div class="ffix">fix: ${esc(f.fix)}</div>` : ''}</div>
        </li>`;
      })
      .join('');

  const changedRows = (items) =>
    (items || [])
      .map(
        (c) =>
          `<li class="finding"><span class="chip">${esc(c.before.weight)} → ${esc(c.after.weight)}</span>
           <div><div class="fid">${esc(c.id)}</div><div class="fdetail">${esc(c.after.detail || '')}</div></div></li>`
      )
      .join('');

  return `
  <section class="report">
    <div class="report-head">
      <div>
        <div class="headline"><span class="big">${esc(result.verdict)}</span></div>
        <div class="caption-5 muted">${t(L, 'compareModelNote')}</div>
      </div>
      <div class="risk">
        <div class="risk-num ${riskClass(result.protected.risk)}">${result.protected.risk}<span>/100</span></div>
        <div class="caption-5 muted mono">${esc(t(L, 'compareRiskAfter'))}</div>
      </div>
    </div>
    <div class="riskbar ${riskClass(result.protected.risk)}"><i style="width:${Math.max(2, result.protected.risk)}%"></i></div>
    <div class="report-grid">
      <div>
        <h3>${esc(t(L, 'compareBefore'))}</h3>
        <table class="kv">
          <tr><td>File</td><td>${esc(result.original.file || '—')}</td></tr>
          <tr><td>Crack</td><td>~${duration(result.original.crack_seconds_best, L)} .. ~${duration(result.original.crack_seconds_worst, L)}</td></tr>
          <tr><td>P(success)</td><td>${result.original.p_success}</td></tr>
          <tr><td>Risk</td><td>${result.original.risk}/100</td></tr>
          ${result.original.measured ? `<tr><td>${esc(t(L, 'compareMeasured'))}</td><td>${duration(result.original.measured.seconds, L)} · ${result.original.measured.success ? 'found' : 'none'}</td></tr>` : ''}
        </table>
      </div>
      <div>
        <h3>${esc(t(L, 'compareAfter'))}</h3>
        <table class="kv">
          <tr><td>File</td><td>${esc(result.protected.file || '—')}</td></tr>
          <tr><td>Crack</td><td>~${duration(result.protected.crack_seconds_best, L)} .. ~${duration(result.protected.crack_seconds_worst, L)}</td></tr>
          <tr><td>P(success)</td><td>${result.protected.p_success}</td></tr>
          <tr><td>Risk</td><td>${result.protected.risk}/100</td></tr>
          ${result.protected.measured ? `<tr><td>${esc(t(L, 'compareMeasured'))}</td><td>${duration(result.protected.measured.seconds, L)} · ${result.protected.measured.success ? 'found' : 'none'}</td></tr>` : ''}
        </table>
      </div>
    </div>
    <div class="delta-strip">
      <div class="delta-tile"><span class="delta-val">${result.delta.seconds_best >= 0 ? '+' : ''}${result.delta.seconds_best}s</span><span class="delta-key">Crack</span></div>
      <div class="delta-tile"><span class="delta-val">${result.delta.p_success >= 0 ? '+' : ''}${result.delta.p_success}</span><span class="delta-key">P(success)</span></div>
      <div class="delta-tile"><span class="delta-val">${result.delta.risk >= 0 ? '+' : ''}${result.delta.risk}</span><span class="delta-key">Risk</span></div>
    </div>
    ${result.ai ? `<table class="kv" style="margin-bottom:var(--s-300)">
      <tr><td>Δ AI measured</td><td>${result.ai.delta_seconds >= 0 ? '+' : ''}${result.ai.delta_seconds}s · ${esc(result.ai.model || '')}</td></tr>
      <tr><td>AI verdict</td><td>${esc(result.ai.verdict)}</td></tr>
    </table>` : ''}
    <h3>${esc(t(L, 'compareFixed'))}</h3>
    ${result.fixed_findings.length ? `<ul class="findings">${findingRows(result.fixed_findings, 'fixed')}</ul>` : `<p class="muted">${esc(t(L, 'compareNoFixed'))}</p>`}
    <h3>${esc(t(L, 'compareNew'))}</h3>
    ${result.new_findings.length ? `<ul class="findings">${findingRows(result.new_findings, 'new')}</ul>` : `<p class="muted">${esc(t(L, 'compareNoNew'))}</p>`}
    <h3>${esc(t(L, 'compareAdded'))}</h3>
    ${result.protection_added.length ? `<ul class="findings">${findingRows(result.protection_added, 'added')}</ul>` : `<p class="muted">${esc(t(L, 'compareNoAdded'))}</p>`}
    ${result.changed_findings.length ? `<h3>${esc(t(L, 'compareChanged'))}</h3><ul class="findings">${changedRows(result.changed_findings)}</ul>` : ''}
    ${result.protection_removed.length ? `<h3>${esc(t(L, 'compareRemoved'))}</h3><ul class="findings">${findingRows(result.protection_removed, 'removed')}</ul>` : ''}
    <p class="caption-5 muted" style="margin-bottom:0">${esc((result.notes || []).join(' · '))}</p>
  </section>`;
}

function demoPage({
  sample = 'dotnet',
  compareResult = null,
  lang = 'vi',
  currentPath = '/demo',
  account = null,
} = {}) {
  const L = normalizeLang(lang);
  const chosen = ['dotnet', 'native', 'protected', 'compare'].includes(sample) ? sample : 'dotnet';
  const tabs = [
    ['dotnet', t(L, 'demoTabDotnet')],
    ['native', t(L, 'demoTabNative')],
    ['protected', t(L, 'demoTabProtected')],
    ['compare', t(L, 'demoTabCompare')],
  ];
  const tabsHtml = tabs
    .map(
      ([id, label]) =>
        `<a class="demo-tab ${chosen === id ? 'active' : ''}" href="/demo?sample=${id}">${esc(label)}</a>`
    )
    .join('');

  const explainKey =
    chosen === 'native'
      ? 'demoExplainNative'
      : chosen === 'protected'
        ? 'demoExplainProtected'
        : chosen === 'compare'
          ? 'demoExplainCompare'
          : 'demoExplainDotnet';

  const content =
    chosen === 'compare'
      ? compareResultHtml(compareResult || demo.getCompareFallback(L), L)
      : reportView(demo.getSample(chosen, L), {
          full: true,
          authenticated: true,
          lang: L,
        });

  const body = `
<section class="hero compact">
  <h1>${esc(t(L, 'demoPageHeading'))}</h1>
  <p class="lede muted">${esc(t(L, 'demoPageLede'))}</p>
</section>

<div class="demo-banner">
  <div class="demo-tabs">${tabsHtml}</div>
  <div class="preview-plain" style="margin-top:0">
    <strong>${esc(t(L, 'demoExplainTitle'))}:</strong> ${esc(t(L, explainKey))}
  </div>
  <p class="caption-5 muted" style="margin:var(--s-100) 0 0">${esc(t(L, 'demoBannerNote'))}</p>
</div>

${content}

<section class="cta-row" style="margin-top:var(--s-400)">
  <a class="btn" href="/scan">${esc(t(L, 'landingCtaPrimary'))}</a>
  <a class="btn ghost" href="/compare?demo=1">${esc(t(L, 'compareLoadDemo'))}</a>
</section>
`;
  return layout({ title: t(L, 'demoPageTitle'), body, account, active: 'demo', lang: L, currentPath });
}

function comparePage({
  result = null,
  error = null,
  originalText = '',
  protectedText = '',
  lang = 'vi',
  currentPath = '/compare',
  account = null,
}) {
  const L = normalizeLang(lang);
  const resultHtml = compareResultHtml(result, L);

  const body = `
<section class="hero compact">
  <h1>${esc(t(L, 'compareHeading'))}</h1>
  <p class="lede muted">${t(L, 'compareLede')}</p>
</section>

${error ? `<div class="alert bad">${esc(error)}</div>` : ''}
${resultHtml}

<section class="card wide">
  <form method="post" action="/compare">
    <div class="grid two">
      <label>${esc(t(L, 'compareBeforeLabel'))}
        <input type="file" accept=".json,application/json" data-target="original">
        <textarea name="original" id="original" rows="8" placeholder='{"crack_seconds_best": 72.4, ...}'>${esc(originalText)}</textarea>
      </label>
      <label>${esc(t(L, 'compareAfterLabel'))}
        <input type="file" accept=".json,application/json" data-target="protected">
        <textarea name="protected" id="protected" rows="8" placeholder='{"crack_seconds_best": 82.6, ...}'>${esc(protectedText)}</textarea>
      </label>
    </div>
    <div class="row" style="margin:var(--s-200) 0">
      <button class="btn" type="submit">${esc(t(L, 'compareSubmit'))}</button>
      <a class="btn ghost" href="/compare?demo=1">${esc(t(L, 'compareLoadDemo'))}</a>
    </div>
  </form>
  <p class="caption-5 muted" style="margin-bottom:0">${t(L, 'compareFooter')}</p>
</section>

<script>
document.querySelectorAll('input[type=file][data-target]').forEach((input) => {
  input.addEventListener('change', () => {
    const file = input.files && input.files[0];
    if (!file) return;
    const target = document.getElementById(input.dataset.target);
    const reader = new FileReader();
    reader.onload = () => { if (target) target.value = String(reader.result || ''); };
    reader.readAsText(file);
  });
});
</script>
`;
  return layout({ title: t(L, 'compareTitle'), body, account, active: 'compare', lang: L, currentPath });
}

/* ------------------------------- pricing ------------------------------- */

function pricingPage({ account, lang = 'vi', currentPath = '/pricing' }) {
  const L = normalizeLang(lang);
  const priceSuffix = (p) => {
    if (!p.price) return esc(t(L, 'freePrice'));
    if (p.oneTime) return `$${p.price}<span>${esc(t(L, 'oneTimeSuffix'))}</span>`;
    if (p.billing === 'year') return `$${p.price}<span>${esc(t(L, 'yearSuffix'))}</span>`;
    return `$${p.price}<span>${esc(t(L, 'monthSuffix'))}</span>`;
  };
  const cards = Object.values(config.plans)
    .map((p) => {
      const current = account && account.plan === p.id;
      const features = planFeatures(L, p.id, p.features);
      return `<div class="card plan ${p.id === 'audit' ? 'featured' : ''}" data-spotlight>
        ${p.id === 'audit' ? '<span class="plan-badge">AUDIT</span>' : ''}
        <div class="plan-name">${esc(p.label)}</div>
        <div class="plan-price">${priceSuffix(p)}</div>
        <ul class="ticks">${features.map((f) => `<li>${esc(f)}</li>`).join('')}</ul>
        ${
          p.id === 'free'
            ? `<a class="btn ghost" href="/scan">${esc(t(L, 'startFreeBtn'))}</a>`
            : current
              ? `<button class="btn ghost" disabled>${esc(t(L, 'currentPlanBtn'))}</button>`
              : `<button class="btn" data-checkout="${p.id}">${esc(t(L, 'choosePlanBtn', { label: p.label }))}</button>`
        }
      </div>`;
    })
    .join('');

  const body = `
<section class="hero compact"><h1>${esc(t(L, 'pricingTitle'))}</h1><p class="lede muted">${t(L, 'pricingLede')}</p></section>
<div id="checkoutNotice" hidden></div>
<section class="pricing-grid">${cards}</section>
<section class="consulting-banner">
  <h2>${esc(t(L, 'consultingTitle'))}</h2>
  <p class="muted" style="margin-bottom:0">${esc(t(L, 'consultingBody'))}</p>
</section>
<section class="card wide">
  <div class="faq-list">
  <h2>${esc(t(L, 'faqTitle'))}</h2>
  <details class="faq"><summary>${esc(t(L, 'faq1Q'))}<span class="faq-icon" aria-hidden="true">+</span></summary><p>${esc(t(L, 'faq1A'))}</p></details>
  <details class="faq"><summary>${esc(t(L, 'faq2Q'))}<span class="faq-icon" aria-hidden="true">+</span></summary><p>${esc(t(L, 'faq2A'))}</p></details>
  <details class="faq"><summary>${esc(t(L, 'faq3Q'))}<span class="faq-icon" aria-hidden="true">+</span></summary><p>${esc(t(L, 'faq3A'))}</p></details>
  <details class="faq"><summary>${esc(t(L, 'faq4Q'))}<span class="faq-icon" aria-hidden="true">+</span></summary><p>${esc(t(L, 'faq4A'))}</p></details>
  <details class="faq"><summary>${esc(t(L, 'faq5Q'))}<span class="faq-icon" aria-hidden="true">+</span></summary><p>${esc(t(L, 'faq5A'))}</p></details>
  <details class="faq"><summary>${esc(t(L, 'faq6Q'))}<span class="faq-icon" aria-hidden="true">+</span></summary><p>${esc(t(L, 'faq6A'))}</p></details>
  </div>
</section>
<script>
const notice = document.getElementById('checkoutNotice');
function showNotice(kind, text) {
  if (!notice) return;
  notice.hidden = false;
  notice.className = 'alert ' + kind;
  notice.textContent = text;
}
document.querySelectorAll('[data-checkout]').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const plan = btn.dataset.checkout;
    const res = await fetch('/api/billing/checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ plan }),
    });
    const json = await res.json();
    if (!json.ok) return showNotice('bad', json.error.message);
    if (json.data.url) location.href = json.data.url;
    else showNotice('ok', json.data.message || ${JSON.stringify(t(L, 'checkoutFallbackMsg'))});
  });
});
</script>
`;
  return layout({ title: t(L, 'pricingTitle'), body, account, active: 'pricing', lang: L, currentPath });
}

function privacyPage({ account = null, lang = 'vi', currentPath = '/legal/privacy' } = {}) {
  const L = normalizeLang(lang);
  const body = `
<section class="panel prose">
  <h1>${esc(t(L, 'privacyTitle'))}</h1>
  <p>${esc(t(L, 'privacyShort'))}</p>
  <h2>${esc(t(L, 'privacyStoreTitle'))}</h2>
  <ul class="ticks">
    <li>${esc(t(L, 'privacyStore1'))}</li>
    <li>${esc(t(L, 'privacyStore2'))}</li>
    <li>${esc(t(L, 'privacyStore3'))}</li>
  </ul>
  <h2>${esc(t(L, 'privacyNoStoreTitle'))}</h2>
  <ul class="ticks">
    <li>${esc(t(L, 'privacyNoStore1'))}</li>
    <li>${esc(t(L, 'privacyNoStore2'))}</li>
  </ul>
  <h2>${esc(t(L, 'privacyAiTitle'))}</h2>
  <p>${t(L, 'privacyAiBody')}</p>
  <h2>${esc(t(L, 'privacyDeleteTitle'))}</h2>
  <p>${t(L, 'privacyDeleteBody')}</p>
</section>`;
  return layout({ title: t(L, 'privacyTitle'), body, account, lang: L, currentPath });
}

function notFound({ account = null, lang = 'vi', currentPath = '/' } = {}) {
  const L = normalizeLang(lang);
  return layout({
    title: t(L, 'notFoundTitle'),
    account,
    bodyClass: 'center-page',
    lang: L,
    currentPath,
    body: `<section class="panel motion-in"><h1>404</h1><p class="muted">${esc(t(L, 'notFoundBody'))}</p><a class="btn" href="/scan">${esc(t(L, 'notFoundCta'))}</a></section>`,
  });
}

function errorPage(message, { account = null, lang = 'vi', currentPath = '/' } = {}) {
  const L = normalizeLang(lang);
  return layout({
    title: t(L, 'errorTitle'),
    account,
    bodyClass: 'center-page',
    lang: L,
    currentPath,
    body: `<section class="panel motion-in"><h1>${esc(t(L, 'errorHeading'))}</h1><p class="muted">${esc(message)}</p><a class="btn" href="/">${esc(t(L, 'errorHome'))}</a></section>`,
  });
}

module.exports = {
  esc,
  duration,
  redact,
  layout,
  landing,
  demoPage,
  scanPage,
  comparePage,
  reportView,
  summaryReport,
  redactCrackSimulation,
  crackSimView,
  loginPage,
  dashboard,
  adminPage,
  settingsPage,
  pricingPage,
  privacyPage,
  notFound,
  errorPage,
};
