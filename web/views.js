'use strict';

const config = require('./config');

/* ------------------------------- helpers ------------------------------- */

const esc = (value) =>
  String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  }[c]));

function duration(seconds) {
  const s = Number(seconds) || 0;
  if (s < 90) return `${Math.round(s)}s`;
  if (s < 3600) return `${(s / 60).toFixed(1)} phút`;
  return `${(s / 3600).toFixed(1)} giờ`;
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

/* ------------------------------- layout -------------------------------- */

function layout({ title, body, account, active = '', bodyClass = '' }) {
  const nav = [
    ['/scan', 'Scan', 'scan'],
    ['/compare', 'So sánh', 'compare'],
    ['/pricing', 'Giá', 'pricing'],
    [account ? '/app' : '/login', account ? 'Dashboard' : 'Đăng nhập', 'app'],
  ];
  const navHtml = nav
    .map(
      ([href, label, key]) =>
        `<a href="${href}" class="${active === key ? 'active' : ''}">${label}</a>`
    )
    .join('');

  return `<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · TrapKey</title>
<meta name="description" content="Scan a Windows app and see how many seconds an AI reverse-engineering agent needs to crack it.">
<link rel="stylesheet" href="/static/app.css">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🜂</text></svg>">
</head>
<body class="${bodyClass}">
<header class="nav">
  <a class="brand" href="/">Trap<span>Key</span></a>
  <nav>${navHtml}</nav>
  <div class="nav-right">
    ${account ? `<span class="who">${esc(account.email)}</span><a class="btn ghost sm" href="/app/settings">Cài đặt</a>` : ''}
  </div>
</header>
<main>${body}</main>
<footer class="foot">
  <div>
    <strong>TrapKey</strong> — đo chi phí bẻ khóa bằng AI.
    <span class="muted">File của bạn bị xóa ngay sau khi scan.</span>
  </div>
  <div class="muted">
    <a href="/legal/privacy">Quyền riêng tư</a> ·
    <a href="/pricing">Giá</a> ·
    <a href="/scan">Scan</a>
  </div>
</footer>
</body>
</html>`;
}

/* ------------------------------- landing ------------------------------- */

function landing() {
  const body = `
<section class="hero">
  <p class="kicker">AI reverse engineering is free now</p>
  <h1>AI bẻ được app của bạn<br>trong bao nhiêu giây?</h1>
  <p class="lede">
    Kéo thả file <code>.exe</code> / <code>.dll</code>. Chúng tôi đọc PE và .NET metadata
    như một AI agent, rồi báo cáo: nó mất bao lâu để tìm ra chỗ kiểm tra license,
    và bạn đang để lộ những gì.
  </p>
  <div class="cta-row">
    <a class="btn" href="/scan">Scan miễn phí</a>
    <a class="btn ghost" href="/pricing">Xem giá</a>
  </div>
  <p class="tiny muted">Không cần tài khoản · file bị xóa ngay sau khi scan · không upload lên CDN</p>
</section>

<section class="grid three">
  <div class="card">
    <div class="step">01</div>
    <h3>Đo, không đoán</h3>
    <p>Đếm chính xác số hàm từ <code>.pdata</code> và số method từ metadata .NET.
       Không phải "có vẻ yếu" — mà là "agent cần đọc 70.000 token".</p>
  </div>
  <div class="card">
    <div class="step">02</div>
    <h3>Chỉ ra chỗ rò</h3>
    <p>Tên hàm <code>CheckLicense</code>, chuỗi "trial", đường dẫn PDB, import crypto:
       mỗi thứ đều làm agent tìm nhanh hơn.</p>
  </div>
  <div class="card">
    <div class="step">03</div>
    <h3>Đo lại sau khi vá</h3>
    <p>Sửa xong, scan lại. Nếu thời gian không tăng và xác suất không giảm,
       lớp bảo vệ đó là trang trí.</p>
  </div>
</section>

<section class="card wide">
  <h2>Ví dụ một báo cáo</h2>
  <pre class="report-snippet">→ AI cracks this in ~48s (likely, p=0.9) · risk 59/100

Leaks (worst first)
  -25  named-functions  3 function(s) are named after licensing: CheckLicense, ActivateTrial
        fix: rename to neutral names, or obfuscate identifiers
  -15  dotnet-readable  27492 .NET methods with readable names (1,726,714 bytes of IL)
        fix: obfuscate identifiers; keep licence logic out of IL</pre>
  <a class="btn ghost" href="/scan">Chạy trên file của bạn</a>
</section>

<section class="card wide">
  <h2>Cách tính</h2>
  <p class="muted">
    <code>seconds = tool_time + read_budget / prefill_rate + rounds × 1200 / decode_rate</code>
  </p>
  <p>
    <code>read_budget</code> phụ thuộc vào việc agent có tìm được chỗ kiểm tra bằng
    <code>grep</code> hay phải đọc cả code. Công thức, hằng số và cách calibrate nằm ở
    <a href="/docs/calibration">tài liệu công khai</a> — vì một con số không giải thích được
    thì không đáng tin.
  </p>
</section>
`;
  return layout({ title: 'AI bẻ app của bạn trong bao nhiêu giây?', body, active: '' });
}

/* -------------------------------- scan -------------------------------- */

function scanPage({ account, anonymousLeft, aiAvailable = true, aiCooldownSeconds = 0 }) {
  const cooling = aiCooldownSeconds > 0;
  const cooldownMinutes = Math.max(1, Math.ceil(aiCooldownSeconds / 60));
  const aiNote = cooling
    ? ` — tạm nghỉ, thử lại sau ${cooldownMinutes} phút`
    : aiAvailable
      ? ''
      : ' — chưa cấu hình model';
  const body = `
<section class="hero compact">
  <h1>Scan một app</h1>
  <p class="lede">Chọn file <code>.exe</code> / <code>.dll</code>. Kết quả trong vài giây.</p>
</section>

<section class="drop" id="drop">
  <input type="file" id="file" accept=".exe,.dll,.bin,.sys" hidden>
  <div class="drop-inner">
    <div class="drop-icon">⇪</div>
    <p><strong>Kéo thả file vào đây</strong> hoặc <button class="link" id="pick">chọn file</button></p>
    <p class="tiny muted">Tối đa 150MB. File bị xóa ngay sau khi scan. Không lưu bản sao.</p>
    <div class="row">
      <label class="radio"><input type="radio" name="mode" value="static" checked> Static scan <span class="muted">(miễn phí)</span></label>
      <label class="radio"><input type="radio" name="mode" value="ai" ${aiAvailable ? '' : 'disabled'}> AI-measured <span class="muted">(1 credit, chậm hơn${aiNote})</span></label>
    </div>
    ${cooling ? `<p class="tiny muted">AI tạm nghỉ, thử lại sau ${cooldownMinutes} phút — provider vừa báo hết quota.</p>` : ''}
    ${account ? '' : `<p class="tiny muted">Khách vãng lai: ${anonymousLeft} lượt/ngày, chỉ xem tóm tắt. <a href="/login">Đăng nhập</a> để xem đủ.</p>`}
  </div>
  <div class="progress" id="progress" hidden><div class="bar" id="bar"></div></div>
</section>

<section id="result"></section>

<section class="card wide" id="privacy">
  <h2>Chúng tôi làm gì với file của bạn</h2>
  <ul class="ticks">
    <li>File được ghi vào thư mục tạm, scan, rồi <strong>xóa ngay</strong> — kể cả khi scan lỗi.</li>
    <li>Chỉ giữ lại: SHA-256, kích thước, và báo cáo JSON.</li>
    <li>Không gửi file cho bên thứ ba. Chế độ <code>--ai</code> chỉ gửi <em>chuỗi và tên hàm</em>, không gửi binary.</li>
  </ul>
</section>

<script src="/static/scan.js"></script>
`;
  return layout({ title: 'Scan', body, account, active: 'scan', bodyClass: 'scan-page' });
}

/* ------------------------------- report ------------------------------- */

/**
 * What an anonymous visitor gets: the headline numbers plus the top leaks,
 * without the fix text. The scan API used to return the full report to the
 * uploader, which made the paywall a one-line devtools bypass.
 */
function summaryReport(report, limit = 3) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const strip = ({ fix, ...rest }) => rest;
  const leaks = findings.filter((f) => f.weight > 0).slice(0, limit).map(strip);
  const guards = findings.filter((f) => f.weight <= 0).map(strip);
  return { ...report, findings: [...leaks, ...guards], redacted: true };
}

function reportView(report, { full = true, shareUrl = null, filename = null } = {}) {
  const risk = Number(report.risk || 0);
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const leaks = findings.filter((f) => f.weight > 0);
  const guards = findings.filter((f) => f.weight <= 0);
  const shown = full ? leaks : leaks.slice(0, 3);

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

  const secret = leaks.length - shown.length;

  return `
<section class="report">
  <div class="report-head">
    <div>
      <div class="tiny muted">${esc(filename || report.file || '')} · ${esc(report.kind)} · ${Number(report.size || 0).toLocaleString('vi-VN')} bytes</div>
      <div class="headline">
        <span class="big">~${duration(report.crack_seconds_best)}</span>
        <span class="verdict ${report.p_success >= 0.8 ? 'bad' : report.p_success >= 0.5 ? 'warn' : 'ok'}">
          ${verdict(report.p_success)} · p=${report.p_success}
        </span>
      </div>
      <div class="tiny muted">thời gian để một AI agent tạo được keygen/patch</div>
    </div>
    <div class="risk">
      <div class="risk-num ${riskClass(risk)}">${risk}<span>/100</span></div>
      <div class="tiny muted">risk</div>
    </div>
  </div>

  <div class="riskbar ${riskClass(risk)}"><i style="width:${Math.max(2, risk)}%"></i></div>

  <div class="report-grid">
    <div>
      <h3>Agent đọc gì để ra kết quả này</h3>
      <ul class="notes">${(report.model_notes || []).map((n) => `<li>${esc(n)}</li>`).join('')}</ul>
    </div>
    <div>
      <h3>Con số</h3>
      <table class="kv">
        ${Object.entries(report.crack_seconds || {})
          .map(([k, v]) => `<tr><td>${esc(v.label)}</td><td>~${duration(v.seconds)}</td></tr>`)
          .join('')}
        <tr><td>P(success)</td><td>${report.p_success}</td></tr>
        <tr><td>read budget</td><td>${Number(report.read_budget_tokens || 0).toLocaleString('vi-VN')} tokens</td></tr>
        <tr><td>agent rounds</td><td>${report.rounds}</td></tr>
        <tr><td>tool time</td><td>${duration(report.tool_seconds)}</td></tr>
        <tr><td>nguồn số</td><td>${esc(report.confidence || 'model')}</td></tr>
        ${
          report.calibration
            ? `<tr><td>calibrated</td><td>k=${esc(report.calibration.k)}${
                report.calibration.model ? ` (${esc(report.calibration.model)})` : ''
              }</td></tr>`
            : ''
        }
        ${
          report.measured
            ? `<tr><td>đo thật (1 round)</td><td>${duration(report.measured.seconds)} · ${esc(
                report.measured.model || ''
              )}</td></tr>`
            : ''
        }
      </table>
    </div>
  </div>

  <h3>Rò rỉ (nặng nhất trước)</h3>
  ${shown ? `<ul class="findings">${leakRows}</ul>` : '<p class="muted">Không thấy dấu hiệu license rõ ràng.</p>'}
  ${secret > 0 && !full ? `<p class="paywall">Còn <strong>${secret}</strong> phát hiện nữa. <a href="/login">Đăng nhập</a> để xem đầy đủ + cách vá.</p>` : ''}

  ${guards.length ? `<h3>Đã có bảo vệ</h3><ul class="findings">${guardRows}</ul>` : ''}

  ${full && leaks.length ? `
  <h3>Làm gì trước</h3>
  <ol class="fixes">
    ${[...new Set(leaks.map((f) => f.fix))].slice(0, 5).map((f) => `<li>${esc(f)}</li>`).join('')}
  </ol>` : ''}

  <p class="tiny muted">
    Đây là cost model, không phải phép đo. Chế độ <code>--ai</code> mới là đo thật.
    ${shareUrl ? `· <a href="${esc(shareUrl)}">link công khai</a>` : ''}
  </p>
</section>`;
}

/* -------------------------------- login -------------------------------- */

function loginPage({ sent = false, error = null } = {}) {
  const body = `
<section class="panel">
  <h1>Đăng nhập</h1>
  ${error ? `<div class="alert bad">${esc(error)}</div>` : ''}
  ${sent
    ? `<div class="alert ok">Đã gửi link đăng nhập. Kiểm tra hộp thư (hoặc <code>web-data/outbox</code> khi chạy dev).</div>`
    : `<p class="muted">Nhập email, chúng tôi gửi một link dùng một lần. Không mật khẩu.</p>
       <form method="post" action="/api/auth/request" id="loginForm">
         <label>Email<input type="email" name="email" required placeholder="you@studio.com" autocomplete="email"></label>
         <button class="btn" type="submit">Gửi link</button>
       </form>`}
</section>`;
  return layout({ title: 'Đăng nhập', body, active: 'app' });
}

/* ------------------------------ dashboard ------------------------------ */

function dashboard({ account, scans, apiTokenHint = null }) {
  const plan = config.plans[account.plan] || config.plans.free;
  const rows = scans
    .map(
      (s) => `<tr>
        <td><a href="/app/scan/${esc(s.id)}">${esc(redact(s.filename))}</a><div class="tiny muted">${esc(s.kind)}</div></td>
        <td>${riskClass(s.risk) === 'bad' ? '🔴' : riskClass(s.risk) === 'warn' ? '🟠' : '🟢'} ${s.risk}</td>
        <td>~${duration(s.crack_seconds)}</td>
        <td class="muted">${new Date(s.created_at).toLocaleString('vi-VN')}</td>
      </tr>`
    )
    .join('');

  const body = `
<section class="page-head">
  <div>
    <h1>Dashboard</h1>
    <p class="muted">${esc(account.email)} · gói <strong>${esc(plan.label)}</strong></p>
  </div>
  <a class="btn" href="/scan">Scan mới</a>
</section>

<section class="grid three">
  <div class="card stat">
    <div class="stat-num">${account.credits_static}</div>
    <div class="stat-label">static scans còn lại</div>
  </div>
  <div class="card stat">
    <div class="stat-num">${account.credits_ai}</div>
    <div class="stat-label">AI-measured còn lại</div>
  </div>
  <div class="card stat">
    <div class="stat-num">${new Date(account.period_start + 30 * 86400000).toLocaleDateString('vi-VN')}</div>
    <div class="stat-label">reset tiếp theo</div>
  </div>
</section>

<section class="card wide">
  <h2>Scan gần đây</h2>
  ${rows ? `<table class="table"><thead><tr><th>File</th><th>Risk</th><th>Crack</th><th>Thời gian</th></tr></thead><tbody>${rows}</tbody></table>` : '<p class="muted">Chưa có scan nào.</p>'}
</section>

<section class="card wide">
  <h2>Gói ${esc(plan.label)}</h2>
  <ul class="ticks">${plan.features.map((f) => `<li>${esc(f)}</li>`).join('')}</ul>
  ${account.plan === 'free' ? '<a class="btn" href="/pricing">Nâng cấp</a>' : ''}
</section>

${apiTokenHint ? `<section class="card wide"><h2>CI token mới</h2><p class="muted">Chỉ hiện một lần. Dán vào secret của CI.</p><pre>${esc(apiTokenHint)}</pre></section>` : ''}
`;
  return layout({ title: 'Dashboard', body, account, active: 'app' });
}

/* -------------------------------- admin -------------------------------- */

function adminPage({ accounts, scans = [], stats }) {
  const accountRows = accounts
    .map(
      (a) => `<tr>
        <td>${esc(a.email)}</td>
        <td>${esc(a.plan)}</td>
        <td>${a.credits_static}/${a.credits_ai}</td>
        <td class="muted">${new Date(a.created_at).toLocaleDateString('vi-VN')}</td>
        <td>
          <button class="btn sm ghost" data-grant="${esc(a.email)}" data-plan="pro">→ pro</button>
          <button class="btn sm ghost" data-grant="${esc(a.email)}" data-plan="team">→ team</button>
          <button class="btn sm ghost" data-grant="${esc(a.email)}" data-plan="free">→ free</button>
        </td>
      </tr>`
    )
    .join('');

  const scanRows = (Array.isArray(scans) ? scans : [])
    .map(
      (s) => `<tr>
        <td><a href="/r/${esc(s.public_id)}">${esc(redact(s.filename))}</a><div class="tiny muted"><code>${esc(s.id)}</code></div></td>
        <td>${esc(s.mode)}</td>
        <td>${riskClass(s.risk) === 'bad' ? '🔴' : riskClass(s.risk) === 'warn' ? '🟠' : '🟢'} ${Number(s.risk ?? 0)}</td>
        <td>~${duration(s.crack_seconds)}</td>
        <td>${Number(s.credits_used || 0)}</td>
        <td class="muted">${new Date(s.created_at).toLocaleString('vi-VN')}</td>
      </tr>`
    )
    .join('');

  const body = `
<section class="page-head"><h1>Admin</h1><span class="muted">${stats.accounts} accounts · ${stats.scans} scans</span></section>

<section class="grid three">
  <div class="card stat"><div class="stat-num">${stats.scans24h}</div><div class="stat-label">scans / 24h</div></div>
  <div class="card stat"><div class="stat-num">${stats.aiScans}</div><div class="stat-label">AI scans</div></div>
  <div class="card stat" title="Số lượt scan của tài khoản được trả từ cache 24h (event type=cache_hit). Không tính scan khách vãng lai.">
    <div class="stat-num">${stats.cacheHits}</div><div class="stat-label">cache hits (tài khoản)</div>
  </div>
</section>

<section class="card wide">
  <h2>Scan gần đây</h2>
  ${scanRows
    ? `<table class="table"><thead><tr><th>File · id</th><th>Mode</th><th>Risk</th><th>Crack</th><th>Credits</th><th>Thời gian</th></tr></thead><tbody>${scanRows}</tbody></table>`
    : '<p class="muted">Chưa có scan nào.</p>'}
  <p class="tiny muted">50 scan mới nhất. Tên file đã che; link mở báo cáo công khai. Cache hit chỉ tính khi tài khoản đăng nhập nhận lại báo cáo trong 24h.</p>
</section>

<section class="card wide">
  <h2>Tài khoản</h2>
  <input id="adminKey" placeholder="admin key" class="mono">
  <table class="table"><thead><tr><th>Email</th><th>Plan</th><th>Credits</th><th>Tạo</th><th></th></tr></thead><tbody>${accountRows}</tbody></table>
  <p class="tiny muted">Nút đổi gói ghi vào bảng <code>events</code> để audit.</p>
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
    btn.textContent = json.ok ? '✓' : '✗';
    if (json.ok) setTimeout(() => location.reload(), 500);
  });
});
</script>
`;
  return layout({ title: 'Admin', body });
}

/* ------------------------------- settings ------------------------------ */

function settingsPage({ account, apiTokenHint = null }) {
  const body = `
<section class="page-head"><h1>Cài đặt</h1></section>

<section class="card wide">
  <h2>Tài khoản</h2>
  <table class="kv">
    <tr><td>Email</td><td>${esc(account.email)}</td></tr>
    <tr><td>Gói</td><td>${esc(config.plans[account.plan]?.label || account.plan)}</td></tr>
    <tr><td>Static còn lại</td><td>${account.credits_static}</td></tr>
    <tr><td>AI còn lại</td><td>${account.credits_ai}</td></tr>
  </table>
</section>

<section class="card wide">
  <h2>CI token</h2>
  <p class="muted">Dùng để scan từ pipeline. Token chỉ hiện một lần khi tạo.</p>
  ${apiTokenHint ? `<pre>${esc(apiTokenHint)}</pre>` : ''}
  <pre>curl -X POST ${esc(config.publicUrl)}/api/scan?mode=static \\
  -H "authorization: Bearer $TRAPKEY_TOKEN" \\
  -H "x-filename: App.exe" \\
  --data-binary @dist/App.exe</pre>
  <form method="post" action="/api/api-token">
    <button class="btn" type="submit">Tạo token mới</button>
  </form>
</section>

<section class="card wide danger">
  <h2>Xóa tài khoản</h2>
  <p class="muted">Xóa tài khoản, session và lịch sử scan. Không thể hoàn tác.</p>
  <form method="post" action="/api/account/delete" onsubmit="return confirm('Xóa tài khoản?')">
    <button class="btn ghost" type="submit">Xóa tài khoản</button>
  </form>
</section>
`;
  return layout({ title: 'Cài đặt', body, account, active: 'app' });
}

/* ------------------------------- compare ------------------------------- */

function comparePage({ result = null, error = null, originalText = '', protectedText = '' }) {
  const findingRows = (items, kind) =>
    (items || [])
      .map((f) => {
        const weight = typeof f.weight === 'number' ? f.weight : 0;
        const sign = kind === 'fixed' ? '✓' : weight <= 0 ? '+' : '-';
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

  const resultHtml = result
    ? `
  <section class="report">
    <div class="report-head">
      <div>
        <div class="headline"><span class="big">${esc(result.verdict)}</span></div>
        <div class="tiny muted">cost model · không phải phép đo; chạy <code>scan.py --ai</code> để đo thật</div>
      </div>
      <div class="risk">
        <div class="risk-num ${riskClass(result.protected.risk)}">${result.protected.risk}<span>/100</span></div>
        <div class="tiny muted">risk sau</div>
      </div>
    </div>
    <div class="riskbar ${riskClass(result.protected.risk)}"><i style="width:${Math.max(2, result.protected.risk)}%"></i></div>
    <div class="report-grid">
      <div>
        <h3>Trước</h3>
        <table class="kv">
          <tr><td>File</td><td>${esc(result.original.file || '—')}</td></tr>
          <tr><td>Crack</td><td>~${duration(result.original.crack_seconds_best)} .. ~${duration(result.original.crack_seconds_worst)}</td></tr>
          <tr><td>P(success)</td><td>${result.original.p_success}</td></tr>
          <tr><td>Risk</td><td>${result.original.risk}/100</td></tr>
        </table>
      </div>
      <div>
        <h3>Sau</h3>
        <table class="kv">
          <tr><td>File</td><td>${esc(result.protected.file || '—')}</td></tr>
          <tr><td>Crack</td><td>~${duration(result.protected.crack_seconds_best)} .. ~${duration(result.protected.crack_seconds_worst)}</td></tr>
          <tr><td>P(success)</td><td>${result.protected.p_success}</td></tr>
          <tr><td>Risk</td><td>${result.protected.risk}/100</td></tr>
        </table>
      </div>
    </div>
    <table class="kv">
      <tr><td>Δ crack (best)</td><td>${result.delta.seconds_best >= 0 ? '+' : ''}${result.delta.seconds_best}s</td></tr>
      <tr><td>Δ p_success</td><td>${result.delta.p_success >= 0 ? '+' : ''}${result.delta.p_success}</td></tr>
      <tr><td>Δ risk</td><td>${result.delta.risk >= 0 ? '+' : ''}${result.delta.risk}</td></tr>
    </table>
    <h3>Leak đã vá</h3>
    ${result.fixed_findings.length ? `<ul class="findings">${findingRows(result.fixed_findings, 'fixed')}</ul>` : '<p class="muted">Không có leak nào biến mất.</p>'}
    <h3>Leak mới</h3>
    ${result.new_findings.length ? `<ul class="findings">${findingRows(result.new_findings, 'new')}</ul>` : '<p class="muted">Không có leak mới.</p>'}
    <h3>Bảo vệ thêm</h3>
    ${result.protection_added.length ? `<ul class="findings">${findingRows(result.protection_added, 'added')}</ul>` : '<p class="muted">Không có finding bảo vệ mới.</p>'}
    ${result.changed_findings.length ? `<h3>Finding đổi weight</h3><ul class="findings">${changedRows(result.changed_findings)}</ul>` : ''}
    ${result.protection_removed.length ? `<h3>Bảo vệ bị mất</h3><ul class="findings">${findingRows(result.protection_removed, 'removed')}</ul>` : ''}
    <p class="tiny muted">${esc((result.notes || []).join(' · '))}</p>
  </section>`
    : '';

  const body = `
<section class="hero compact">
  <h1>So sánh trước / sau protect</h1>
  <p class="lede">Chạy local: <code>python3 scan.py App.exe --json &gt; before.json</code>, protect, rồi <code>scan.py App.protected.exe --json &gt; after.json</code>. Upload hai báo cáo — không upload binary.</p>
</section>

${error ? `<div class="alert bad">${esc(error)}</div>` : ''}
${resultHtml}

<section class="card wide">
  <form method="post" action="/compare">
    <div class="grid two">
      <label>Báo cáo TRƯỚC
        <input type="file" accept=".json,application/json" data-target="original">
        <textarea name="original" id="original" rows="8" placeholder='{"crack_seconds_best": 72.4, ...}'>${esc(originalText)}</textarea>
      </label>
      <label>Báo cáo SAU
        <input type="file" accept=".json,application/json" data-target="protected">
        <textarea name="protected" id="protected" rows="8" placeholder='{"crack_seconds_best": 82.6, ...}'>${esc(protectedText)}</textarea>
      </label>
    </div>
    <button class="btn" type="submit">So sánh</button>
  </form>
  <p class="tiny muted">Chỉ nhận JSON của <code>scan.py --json</code>. Protect vẫn chạy trên máy bạn; server không nhận binary ở trang này.</p>
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
  return layout({ title: 'So sánh protect', body, active: 'compare' });
}

/* ------------------------------- pricing ------------------------------- */

function pricingPage({ account }) {
  const cards = Object.values(config.plans)
    .map((p) => {
      const current = account && account.plan === p.id;
      return `<div class="card plan ${p.id === 'pro' ? 'featured' : ''}">
        <div class="plan-name">${esc(p.label)}</div>
        <div class="plan-price">${p.price ? `$${p.price}<span>/tháng</span>` : 'Miễn phí'}</div>
        <ul class="ticks">${p.features.map((f) => `<li>${esc(f)}</li>`).join('')}</ul>
        ${
          p.id === 'free'
            ? '<a class="btn ghost" href="/scan">Bắt đầu</a>'
            : current
              ? '<button class="btn ghost" disabled>Gói hiện tại</button>'
              : `<button class="btn" data-checkout="${p.id}">Chọn ${esc(p.label)}</button>`
        }
      </div>`;
    })
    .join('');

  const body = `
<section class="hero compact"><h1>Giá</h1><p class="lede">Scan miễn phí. Trả tiền khi bạn cần đo nhiều và cần chế độ AI thật.</p></section>
<section class="grid three">${cards}</section>
<section class="card wide">
  <h2>Câu hỏi thường gặp</h2>
  <details><summary>Có cần gửi source không?</summary><p>Không. Chỉ cần file đã build. Và file bị xóa ngay sau khi scan.</p></details>
  <details><summary>Con số có chính xác không?</summary><p>Đây là cost model, sai số ±2x. Chế độ AI-measured gọi model thật và đo wall-clock — đó là lý do nó tốn credit.</p></details>
  <details><summary>Nó có làm app tôi không bị crack?</summary><p>Không. Không có công cụ nào hứa được điều đó. TrapKey đo chi phí để bẻ, và chỉ ra chỗ làm nó rẻ đi.</p></details>
  <details><summary>File của tôi có bị lưu?</summary><p>Không. Chỉ giữ SHA-256 và báo cáo.</p></details>
</section>
<script>
document.querySelectorAll('[data-checkout]').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const plan = btn.dataset.checkout;
    const res = await fetch('/api/billing/checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ plan }),
    });
    const json = await res.json();
    if (!json.ok) return alert(json.error.message);
    if (json.data.url) location.href = json.data.url;
    else alert(json.data.message || 'Đã ghi nhận yêu cầu. Chúng tôi sẽ liên hệ qua email.');
  });
});
</script>
`;
  return layout({ title: 'Giá', body, account, active: 'pricing' });
}

function privacyPage() {
  const body = `
<section class="panel prose">
  <h1>Quyền riêng tư</h1>
  <p>Bản ngắn: chúng tôi không giữ file bạn upload.</p>
  <h2>Chúng tôi lưu gì</h2>
  <ul class="ticks">
    <li>SHA-256 của file, kích thước, và báo cáo JSON.</li>
    <li>Email của bạn (nếu đăng nhập) và lịch sử scan.</li>
    <li>Hash của IP (không lưu IP thô) để chống lạm dụng.</li>
  </ul>
  <h2>Chúng tôi không lưu gì</h2>
  <ul class="ticks">
    <li>Không lưu file .exe/.dll — xóa ngay sau khi scan.</li>
    <li>Không dùng analytics bên thứ ba, không quảng cáo.</li>
  </ul>
  <h2>Chế độ AI</h2>
  <p>Chế độ <code>--ai</code> gửi <em>chuỗi và tên hàm trích xuất được</em> tới nhà cung cấp model.
     Không gửi binary. Nếu điều đó không chấp nhận được, dùng static scan.</p>
  <h2>Xóa dữ liệu</h2>
  <p>Vào <a href="/app/settings">Cài đặt</a> để xóa tài khoản và lịch sử.</p>
</section>`;
  return layout({ title: 'Quyền riêng tư', body });
}

function notFound() {
  return layout({
    title: 'Không tìm thấy',
    body: '<section class="panel"><h1>404</h1><p class="muted">Trang này không tồn tại.</p><a class="btn" href="/scan">Scan một file</a></section>',
  });
}

function errorPage(message) {
  return layout({
    title: 'Lỗi',
    body: `<section class="panel"><h1>Có lỗi</h1><p class="muted">${esc(message)}</p><a class="btn" href="/">Về trang chủ</a></section>`,
  });
}

module.exports = {
  esc,
  duration,
  redact,
  layout,
  landing,
  scanPage,
  comparePage,
  reportView,
  summaryReport,
  loginPage,
  dashboard,
  adminPage,
  settingsPage,
  pricingPage,
  privacyPage,
  notFound,
  errorPage,
};
