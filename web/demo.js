'use strict';

/**
 * Sample binary audit reports used by the /demo gallery and the ?demo=1
 * preset on /compare. Structural fields live in BASE_SAMPLES; human-facing
 * strings localize to Vietnamese (lang === 'vi') or English otherwise.
 */

const BASE_SAMPLES = {
  dotnet: {
    file: 'InvoicePro.exe',
    sha256: '4b825dc642cb6eb9a060e54bf8d69288fbee4904f8b92c7d1a00000000000001',
    kind: 'dotnet',
    size: 482304,
    crack_seconds_best: 8.2,
    crack_seconds_worst: 21.0,
    p_success: 0.95,
    risk: 88,
    read_budget_tokens: 14200,
    rounds: 1.6,
    tool_seconds: 2.0,
    confidence: 'model+measured',
    markers: ['CheckLicenseKey', 'ActivateTrial', 'IsProUnlocked'],
    tier_seconds: { frontier: 8.2, mid: 13.5, local: 21.0 },
    measured: { seconds: 3.1, model: 'gpt-6-luna', success: true },
    crack_simulation_base: {
      seconds: 4.3,
      model: 'deepseek-v4.1-flash',
      success: true,
      patch: {
        strategy: 'patch-branch',
        difficulty: 'TRIVIAL',
        patch_size: 2,
        offset: 0x0029,
        method: 'InvoicePro.LicenseService::CheckLicenseKey',
        original: '2d0c',
        patched: '2c0c',
        verified: true,
      },
    },
    finding_weights: [
      { id: 'named-functions', weight: 25 },
      { id: 'dotnet-readable', weight: 18 },
      { id: 'license-strings', weight: 14 },
      { id: 'single-check-point', weight: 12 },
    ],
  },

  native: {
    file: 'AudioClipTool.exe',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    kind: 'native',
    size: 3840512,
    crack_seconds_best: 22.4,
    crack_seconds_worst: 58.0,
    p_success: 0.84,
    risk: 76,
    read_budget_tokens: 34500,
    rounds: 2.3,
    tool_seconds: 3.1,
    confidence: 'model+measured',
    markers: ['VerifyActivation', 'Invalid or expired license key'],
    tier_seconds: { frontier: 22.4, mid: 35.0, local: 58.0 },
    measured: { seconds: 4.8, model: 'deepseek-v4.1-flash', success: true },
    crack_simulation_base: {
      seconds: 6.1,
      model: 'deepseek-v4.1-flash',
      success: true,
      patch: {
        strategy: 'patch-branch',
        difficulty: 'EASY',
        patch_size: 2,
        offset: 0x1140,
        method: 'VerifyActivation (0x1400142a0)',
        original: '7418',
        patched: 'eb18',
        verified: true,
      },
    },
    finding_weights: [
      { id: 'license-strings', weight: 22 },
      { id: 'named-exports', weight: 16 },
      { id: 'no-anti-tamper', weight: 10 },
    ],
  },

  protected: {
    file: 'InvoicePro.protected.exe',
    sha256: 'c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2',
    kind: 'dotnet',
    size: 912896,
    crack_seconds_best: 852.0,
    crack_seconds_worst: 2140.0,
    p_success: 0.38,
    risk: 34,
    read_budget_tokens: 418000,
    rounds: 7.4,
    tool_seconds: 2.8,
    confidence: 'model+measured',
    markers: ['decoy-kit', 'obfuscated'],
    tier_seconds: { frontier: 852.0, mid: 1380.0, local: 2140.0 },
    measured: { seconds: 7.9, model: 'gpt-6-luna', success: false },
    crack_simulation_base: { seconds: 7.9, model: 'gpt-6-luna', success: false },
    finding_weights: [
      { id: 'dotnet-readable', weight: 8 },
      { id: 'decoy-kit', weight: -24 },
      { id: 'symbol-renaming', weight: -15 },
    ],
  },
};

const COPY = {
  vi: {
    tiers: {
      frontier: 'AI mạnh nhất (API)',
      mid: 'AI phổ thông',
      local: 'AI chạy local',
    },
    dotnet: {
      notes: [
        'App .NET còn giữ nguyên tên hàm rõ nghĩa (CheckLicenseKey, IsProUnlocked)',
        'Đoạn kiểm tra bản quyền đọc được trực tiếp, chưa bị làm rối (obfuscate)',
        'Chuỗi thông báo "License expired" trỏ thẳng vào hàm kiểm tra',
      ],
      explanation: 'Đổi lệnh rẽ nhánh tại offset 0x0029 (nếu sai -> hợp lệ) để mọi key đều được chấp nhận.',
      findings: [
        {
          detail: 'Lộ tên hàm kiểm tra bản quyền: CheckLicenseKey, ActivateTrial, IsProUnlocked',
          fix: 'Đổi tên ký hiệu (symbol renaming) với ConfuserEx / Obfuscar và bỏ file .pdb khi release.',
        },
        {
          detail: '412 KB mã trung gian .NET (.NET IL) đọc trực tiếp được như mã nguồn C#',
          fix: 'Bật obfuscate cho các hàm xử lý bản quyền hoặc chuyển logic quan trọng sang thư viện native đã bọc.',
        },
        {
          detail: 'Chuỗi văn bản rõ ràng ("Invalid license key", "Trial expired") dẫn thẳng tới chỗ kiểm tra',
          fix: 'Mã hóa chuỗi nhạy cảm hoặc tách thông báo lỗi khỏi hàm quyết định khóa/mở tính năng.',
        },
        {
          detail: 'Chỉ kiểm tra bản quyền tại 1 chỗ duy nhất khi mở ứng dụng — sửa 1 lần là mở toàn bộ app',
          fix: 'Dùng TrapKey Decoy Kit để rải kiểm tra đa điểm kèm các hàm mồi đánh lạc hướng.',
        },
      ],
    },
    native: {
      notes: [
        'App C++ nhưng vẫn còn chuỗi thông báo lỗi bản quyền dạng văn bản thường',
        'Không phát hiện packer, lớp bảo vệ bộ nhớ hay bẫy đánh lạc hướng',
        'Hàm VerifyActivation chỉ có 1 nhánh nhảy có điều kiện duy nhất',
      ],
      explanation: 'Thay lệnh nhảy có điều kiện (je) thành nhảy vô điều kiện (jmp) để bỏ qua nhánh báo lỗi.',
      findings: [
        {
          detail: 'Chuỗi "Invalid or expired license key" lộ vị trí hàm VerifyActivation',
          fix: 'Ẩn hoặc mã hóa chuỗi bản quyền trong code C++ bằng macro compile-time trước khi build.',
        },
        {
          detail: 'Còn bảng thông tin hàm debug/symbol giúp AI khoanh vùng nhanh',
          fix: 'Tắt tạo PDB hoặc strip sạch đường dẫn debug trên bản build chính thức.',
        },
        {
          detail: 'File bị sửa byte vẫn chạy bình thường, không có kiểm tra toàn vẹn',
          fix: 'Thêm kiểm tra checksum / chữ ký nội bộ và rải các hàm bẫy TrapKey Decoy Kit.',
        },
      ],
    },
    protected: {
      notes: [
        'Tên hàm đã được làm mờ — không còn tên gợi ý như CheckLicense',
        'Phát hiện 14 hàm mồi TrapKey Decoy tại 4 luồng thực thi khác nhau',
        'AI thử đoán nhầm vào hàm mồi, không xác minh được bản patch hoạt động',
      ],
      reason: 'AI đoán nhầm vào hàm mồi đánh lạc hướng và không tạo được bản patch hợp lệ.',
      findings: [
        {
          detail: 'Một số lớp giao diện UI vẫn đọc được nhưng đã tách khỏi logic kiểm tra bản quyền',
          fix: 'Có thể bọc thêm native packing nếu cần nâng độ khó lên mức rất cao.',
        },
        {
          detail: 'Đã gắn TrapKey Decoy Kit: 14 hàm bẫy + kiểm tra đa điểm làm AI tốn nhiều vòng thử sai',
          fix: '',
        },
        {
          detail: 'Đã ẩn toàn bộ tên hàm/biến và xóa thông tin debug (.pdb)',
          fix: '',
        },
      ],
    },
    compare: {
      aiVerdict: 'AI không còn bẻ được trên bản đã bảo vệ',
      verdict: 'protected (+14.1 phút)',
      note: 'So sánh mẫu giữa InvoicePro.exe (bản gốc) và InvoicePro.protected.exe (đã gắn Decoy Kit + obfuscate).',
    },
  },

  en: {
    tiers: {
      frontier: 'Frontier AI (API)',
      mid: 'Mid-tier AI',
      local: 'Local AI model',
    },
    dotnet: {
      notes: [
        '.NET build keeps readable function names (CheckLicenseKey, IsProUnlocked)',
        'License validation logic is readable without obfuscation',
        '"License expired" strings point directly to the check routine',
      ],
      explanation: 'Flip branch opcode at offset 0x0029 (brtrue.s -> brfalse.s) so any license key passes.',
      findings: [
        {
          detail: 'Exposed license symbols: CheckLicenseKey, ActivateTrial, IsProUnlocked',
          fix: 'Enable symbol renaming (ConfuserEx / Obfuscar) and strip .pdb files in release builds.',
        },
        {
          detail: '412 KB of readable .NET IL can be decompiled back to near-original C#',
          fix: 'Obfuscate licensing assemblies or move critical checks into a hardened native library.',
        },
        {
          detail: 'Plaintext strings ("Invalid license key", "Trial expired") lead straight to the guard',
          fix: 'Encrypt sensitive license strings or decouple error messages from the entitlement gate.',
        },
        {
          detail: 'Single validation point at startup — patching one branch unlocks the entire app',
          fix: 'Use TrapKey Decoy Kit to spread multi-point checks alongside decoy trap functions.',
        },
      ],
    },
    native: {
      notes: [
        'Compiled C++ binary still exposes plaintext license error strings',
        'No packer, integrity check, or decoy traps detected',
        'VerifyActivation relies on a single conditional jump',
      ],
      explanation: 'Replace conditional jump (je) with unconditional jump (jmp) to skip the failure path.',
      findings: [
        {
          detail: 'String "Invalid or expired license key" pinpoints VerifyActivation immediately',
          fix: 'Hide or encrypt license strings at compile time before shipping release binaries.',
        },
        {
          detail: 'Remaining debug/symbol info helps AI narrow down the check quickly',
          fix: 'Disable PDB generation or strip debug paths in public release builds.',
        },
        {
          detail: 'Binary continues running normally after byte patches (no tamper check)',
          fix: 'Add self-checksum verification and embed TrapKey Decoy Kit traps.',
        },
      ],
    },
    protected: {
      notes: [
        'Symbol names are hidden — no obvious CheckLicense hints remain',
        'Detected 14 TrapKey Decoy functions spread across 4 execution paths',
        'AI chased decoy paths and failed to verify a working bypass patch',
      ],
      reason: 'AI targeted decoy trap functions and failed to produce a verified bypass patch.',
      findings: [
        {
          detail: 'Some UI classes remain readable but are decoupled from entitlement checks',
          fix: 'Optional native packing can raise difficulty further if needed.',
        },
        {
          detail: 'TrapKey Decoy Kit active: 14 decoy functions + multi-point validation slow AI guesses',
          fix: '',
        },
        {
          detail: 'Function names hidden and debug symbols (.pdb) stripped cleanly',
          fix: '',
        },
      ],
    },
    compare: {
      aiVerdict: 'AI failed to crack the protected build',
      verdict: 'protected (+14.1 min)',
      note: 'Demo comparison between InvoicePro.exe (original) and InvoicePro.protected.exe (Decoy Kit + obfuscation).',
    },
  },
};

function buildSample(name, lang = 'vi') {
  const locale = lang === 'vi' ? 'vi' : 'en';
  const base = BASE_SAMPLES[name] || BASE_SAMPLES.dotnet;
  const copy = COPY[locale];
  const loc = copy[name] || copy.dotnet;

  const crack_seconds = {
    frontier: { label: copy.tiers.frontier, seconds: base.tier_seconds.frontier },
    mid: { label: copy.tiers.mid, seconds: base.tier_seconds.mid },
    local: { label: copy.tiers.local, seconds: base.tier_seconds.local },
  };

  const crack_simulation = { ...base.crack_simulation_base };
  if (crack_simulation.patch) {
    crack_simulation.patch = { ...crack_simulation.patch, explanation: loc.explanation };
  } else if (loc.reason) {
    crack_simulation.reason = loc.reason;
  }

  const findings = base.finding_weights.map((fw, idx) => ({
    id: fw.id,
    weight: fw.weight,
    detail: loc.findings[idx].detail,
    fix: loc.findings[idx].fix,
  }));

  return {
    file: base.file,
    sha256: base.sha256,
    kind: base.kind,
    size: base.size,
    crack_seconds_best: base.crack_seconds_best,
    crack_seconds_worst: base.crack_seconds_worst,
    p_success: base.p_success,
    risk: base.risk,
    read_budget_tokens: base.read_budget_tokens,
    rounds: base.rounds,
    tool_seconds: base.tool_seconds,
    confidence: base.confidence,
    markers: base.markers,
    crack_seconds,
    model_notes: loc.notes,
    measured: base.measured,
    crack_simulation,
    findings,
  };
}

function getSample(name, lang = 'vi') {
  return buildSample(name, lang);
}

function getCompareFallback(lang = 'vi') {
  const locale = lang === 'vi' ? 'vi' : 'en';
  const orig = buildSample('dotnet', locale);
  const prot = buildSample('protected', locale);
  const c = COPY[locale].compare;
  return {
    ok: true,
    original: orig,
    protected: prot,
    delta: {
      seconds_best: 843.8,
      seconds_worst: 2119.0,
      p_success: -0.57,
      risk: -54,
    },
    ai: {
      delta_seconds: 4.8,
      model: 'gpt-6-luna',
      verdict: c.aiVerdict,
    },
    fixed_findings: [orig.findings[0], orig.findings[2], orig.findings[3]],
    new_findings: [],
    protection_added: [prot.findings[1], prot.findings[2]],
    changed_findings: [
      {
        id: 'dotnet-readable',
        before: orig.findings[1],
        after: prot.findings[0],
      },
    ],
    protection_removed: [],
    same_file: false,
    verdict: c.verdict,
    notes: [c.note],
  };
}

const SAMPLES = {
  dotnet: buildSample('dotnet', 'vi'),
  native: buildSample('native', 'vi'),
  protected: buildSample('protected', 'vi'),
};

module.exports = {
  SAMPLES,
  COMPARE_FALLBACK: getCompareFallback('vi'),
  getSample,
  getCompareFallback,
};
