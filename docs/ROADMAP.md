# RevScan — Roadmap v2 (cập nhật 2026-11-18)

> Thay thế roadmap v1 (30 ngày). Pivot: từ "scan + subscription $29/tháng" sang
> "crack simulation + one-time audit + decoy kit". Lý do: xem review 2026-11-18.

## Đã xong (tuần 1 — repo hiện tại)

- [x] Scanner + cost model: 34 test
- [x] Calibrate: 18 test, k=1.2673 (gpt-6-luna)
- [x] Benchmark harness: 46 test
- [x] CLI protect (strip PDB + payload v2): 15 test
- [x] CLI compare (before/after + --ai): 29 test
- [x] IL decoder + native xref: 14 test
- [x] Web SaaS (upload, scan, auth, billing, admin): 45 test
- [x] License server + admin UI: 16 test
- [x] SDK C++ / .NET (viết xong, chưa compile)

Tổng: **217 test pass**, zero npm dependency.

## P0: Crack Simulation — Round 2 (tuần 2, ~4 ngày)

> **Đây là tính năng thay đổi hoàn toàn giá trị sản phẩm.** Chuyển từ "nói cho bạn
> biết AI tìm hàm trong mấy giây" thành "show bạn AI crack app bạn trong mấy giây".

- [x] Round 2 prompt trong `ai.py`: sau khi tìm hàm (Round 1), gửi IL/disasm
      của hàm đó → model đề xuất patch bytes cụ thể
- [x] Verify patch hợp lệ bằng Python (không LLM): check offset, decode IL/x86
- [x] `measure()` trả thêm `raw_function` cho Round 2 sử dụng
- [x] `crack_simulate()` gọi Round 2 + verify + trả `crack_simulation` dict
- [x] `Estimate` dataclass có field `crack_simulation`
- [x] `report.py` render crack simulation section (CLI + JSON)
- [x] `scan.py` gọi Round 2 sau Round 1 khi `--ai` thành công
- [x] Test: 20 test cho round 2 + verify + report + parse + difficulty
- [x] `views.js` render crack simulation trên web (phân tầng free/paid)

**Output mẫu cho free tier:**
```
⚡ CRACK SIMULATION — gpt-6-luna, 8.2s
  Strategy: patch-branch   Difficulty: TRIVIAL (1 byte)
  🔒 Xem code + patch cụ thể → Audit Pass ($49)
```

**Output cho paid tier:**
```
⚡ CRACK SIMULATION — gpt-6-luna, 8.2s
  IL_0006: brfalse.s IL_000b
  Patch: offset 0x2056: 2C → 2D (brfalse → brtrue)
  ⚠️  1 byte = vô hiệu hóa toàn bộ RSA-2048 verify
```

## P0: Cập nhật pricing (tuần 2, ~1 ngày)

- [x] Thêm `audit` plan vào `config.js`: $49 mua đứt, 10 static + 3 AI, 30 ngày (+ `annual` $199/năm)
- [x] `credits.js`: support one-time plan (không reset, không renew) + unlimited static cho Annual CI
- [x] `views.js` pricing page: Free / Audit Pass / Annual CI (+ Consulting)
- [x] Giới hạn free report: chỉ hiện risk + top 2 findings (`summaryReport` giấu `fix` + giấu crack patch bytes)

## P1: Decoy Kit (tuần 3, ~5 ngày)

- [x] `TrapKeyDecoy.cs` — single-file include:
  - 8 fake license functions (`BuildSeed` per build, realistic logic)
  - `NoInlining` + real xrefs từ startup (`Warmup`)
  - Multi-point check API: `TrapKeyDecoy.Verify(key, slice)` ở ≥5 nơi
  - Delayed check (`ScheduleDelayedCheck` async verify sau 1–5 phút random)
- [x] `revscan_decoy.h` — tương đương cho C/C++ (header-only)
- [x] Scanner nhận diện decoy coverage: đếm số fake function + check points (`il.call_tokens`) + delayed check
- [x] Compare report đo hiệu quả: scan trước/sau integrate Decoy Kit (compile thật bằng `csc.exe`)

## P2: Triển khai + Thanh toán (tuần 3–4)

- [ ] VPS (Hetzner/DO $6/tháng) + systemd + nginx + certbot
- [ ] Stripe checkout cho Audit Pass $49 (one-time) + Annual CI $199
- [ ] Resend cho magic link email
- [ ] Landing page: headline "AI crack app bạn trong 8 giây — xem demo"

## P2: Fix bugs kỹ thuật

- [x] Fix `BCryptVerifySignature` padding info (C++ SDK)
- [x] JSON escaping key input (C++ SDK)
- [x] Cảnh báo Authenticode khi `protect` (pe.py / revscan.py)
- [x] Sửa privacy statement `--ai` (views.js)

## P3: Marketing (tuần 4+)

- [ ] Scan 20 thư viện licensing NuGet → bài blog thống kê
- [ ] Show HN: "I built an AI that cracks .NET apps in 8 seconds — here's how to stop it"
- [ ] r/dotnet, r/csharp, r/indiedev
- [ ] 50 outbound email → ISV bán app .NET ≥$49

## Kill criteria (giữ từ v1, cập nhật giá)

| Quan sát | Kết luận | Hành động |
|---|---|---|
| 100 outbound → <5 reply | sai kênh | đổi kênh (forum/Discord) |
| 20 báo cáo → 0 ai hỏi cách vá | sai pain | dừng bán scan, chỉ bán license server |
| 10 người hỏi → 0 trả $49 | sai giá | hạ giá $29, không thêm feature |
| Khách chỉ hỏi "có free không" | sai ICP | nhắm app có giá ≥$50 |

## Không làm (v2)

- Obfuscation CFF/VM (dùng ConfuserEx/VMProtect, không tự viết)
- Binary rewriting post-build (runtime reference) — đã chứng minh không hiệu quả
- macOS/Linux/Android (chờ có khách trả tiền trên Windows trước)
- Team/seat/SSO/analytics
- Prompt injection payload cải tiến (đã chứng minh không hoạt động với frontier model)
