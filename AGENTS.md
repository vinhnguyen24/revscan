# AGENTS.md — TrapKey

> Ngữ cảnh master. Đọc file này trước khi mở code. Trạng thái phiên gần nhất:
> `docs/HANDOFF_2026-11-16.md`. Quyết định kỹ thuật: `docs/CALIBRATION.md`, `docs/WEB_PLAN.md`.

Cập nhật: 2026-11-18.

---

## 1. Sản phẩm là gì (và không là gì)

**TrapKey trả lời một câu hỏi duy nhất:**

> Một AI reverse-engineering agent (REA) mất bao nhiêu giây để crack app Windows
> này — và đây là bằng chứng: code bị lộ, patch cụ thể, mọi thứ.

Sản phẩm: **scan → crack simulation → decoy kit → (optional) monitor**.

| Có bán | Không bán |
|---|---|
| Crack simulation: show code bị lộ + patch bytes cụ thể | "Chống crack tuyệt đối" — không hứa được |
| Decoy Kit (NuGet/header): fake functions + multi-point check | Obfuscator/VM (dùng ConfuserEx/VMProtect) |
| Annual CI license + Audit Pass ($49 one-time) | License server (commodity, chỉ là add-on) |
| CLI scan/protect miễn phí | Binary rewriter post-build (đã chứng minh không hiệu quả) |

**Đừng định vị lại thành "key server".** Đã bàn và loại bỏ: Keygen.sh/Cryptolens
thắng ở đó, và khách không trả tiền cho license verification.

**Đừng bán subscription $29/tháng.** Nhu cầu scan là episodic (1–3 lần/quý), free
tier quá đủ cho indie dev → churn >70%. Bán one-time audit + annual CI thay vì.

## 2. Trạng thái hiện tại (đã chạy thật)

| Thành phần | Trạng thái |
|---|---|
| `scanner/` + `scan.py` | ✅ 34 test |
| `calibrate.py` | ✅ 18 test |
| `web/` (SaaS) | ✅ 57 test (48 e2e + 9 UI/i18n) |
| `server/` (license, add-on) | ✅ 16 test |
| `cli/trapkey.py protect` | ✅ 15 test, chạy trên PE thật |
| `cli/trapkey.py compare` | ✅ 29 test, protect → rescan → diff (+ `--ai`) |
| `scanner/il.py` + `scanner/native.py` | ✅ 14 test, IL + objdump xref trong evidence pack |
| `benchmark.py` | ✅ 46 test, ground-truth harness (static + AI) |
| `sdk/cpp` + `sdk/dotnet` | ⚠️ `TrapKeyDecoy.cs` đã compile & test thật (`csc.exe`); `sdk/cpp` chưa compile (không có MSVC) |
| `Decoy Kit` (`TrapKeyDecoy.cs` + `trapkey_decoy.h` + scanner) | ✅ 4 test (compile + run + scan + compare trên `.exe` thật) |
| `--ai` với model thật | ✅ Mặc định OpenCode Go `gpt-6-luna` (~2.5–4.6s/scan, $0.10/$0.50 per 1M, **k=1.2673**); `deepseek-v4.1-flash` mạnh hơn cho native; Gemini 3.1-lite/3.6/3.8 là fallback; native vẫn yếu |
| `--ai` crack simulation (Round 2) | ✅ 20 test, Round 2 prompt + verify patch + report render |

Tổng: **256 test pass** (183 Python + 73 JS trên Node 22+), 0 dependency npm (objdump là optional, không phải dependency).

## 3. Bản đồ code

```
scan.py                 CLI scan; --json cho web/CI, --min-seconds cho CI gate, --ai
calibrate.py            batch + fit multiplier k (geometric mean, tool time không scale)
benchmark.py            chấm scanner/--ai bằng nhãn ground truth (hit/FP/FN, latency)

scanner/
  peinfo.py             PE: sections, entropy, imports, exports, .pdata (đếm hàm chính xác)
  dotnet.py             ECMA-335 metadata: MethodDef/TypeDef/MemberRef, IL body + token resolve
  il.py                 IL decoder -> method body (ldstr/call có tên thật) cho evidence pack
  native.py             objdump: xref license string/crypto import -> disassembly hàm đó
  ident.py              tách camelCase/underscore -> match cả từ (chống false positive)
  evidence.py           thu thập bằng chứng + phát hiện trap/packer/asar
  estimate.py           cost model -> giây; đọc TRAPKEY_CALIBRATION_K
  report.py             render human/JSON; risk = p_success * ease(seconds)
  ai.py                 resolve_config() cho openai-compatible/ollama/anthropic + classify_failure()
  compare.py            scan gốc vs bản protect: delta giây/p/risk + finding thay đổi

web/
  server.js             HTTP, routes, billing, admin, static, dispatch
  db.js                 node:sqlite, schema, tx(), ledger(), event()
  auth.js               magic link (hash trong DB), session cookie, CI token
  credits.js            2 bucket, reset 30 ngày, quota anonymous, applyPlan
  scanjob.js            upload stream -> temp -> spawn engine -> delete
  views.js              server-rendered HTML (không framework, không build)
  static/app.css,scan.js

cli/trapkey.py          protect (strip PDB + payload v2) / verify (RSA offline) / info / compare / compare-reports
cli/pe.py               3 chiến lược chèn (slack -> new-section -> overlay) + strip_debug
server/                 license server + admin UI (add-on, zero dep)
sdk/cpp, sdk/dotnet     SDK licensing (CNG + WinHTTP, không third-party)
deploy/                 systemd unit + nginx conf
benchmarks/             README + labels.example.json cho ground-truth corpus
docs/                   SPEC, CALIBRATION, WEB_PLAN, ROADMAP, HANDOFF, calibration/
```

## 4. Lệnh

```bash
npm start                                  # web, http://127.0.0.1:7200
npm test                                   # 217 test (scan + calibrate + protect + compare + disasm + benchmark + web + license)

python3 scan.py App.exe                    # báo cáo
python3 scan.py App.exe --json             # cho web/CI
python3 scan.py dist/*.exe --min-seconds 60  # CI gate, exit 1 nếu dưới ngưỡng
python3 scan.py App.exe --ai               # đo thật + crack simulation (cần provider)

python3 calibrate.py <dir> --limit 20
TRAPKEY_AI_PROVIDER=ollama python3 calibrate.py <dir> --ai --limit 10

TRAPKEY_CALIBRATION_K=1.7 python3 scan.py App.exe
python3 cli/trapkey.py protect App.exe --level 3      # strip PDB + payload v2
python3 cli/trapkey.py protect App.exe --sig feed.sig --pubkey vendor.pem
python3 cli/trapkey.py info App.protected.exe
python3 cli/trapkey.py compare App.exe App.protected.exe --json  # before/after diff
python3 cli/trapkey.py compare App.exe App.protected.exe --ai --repeat 3 --json  # đo thật cả 2 bản
python3 cli/trapkey.py compare-reports before.json after.json --json  # web /compare dùng lệnh này

python3 benchmark.py --corpus <dir> --labels labels.json --static
python3 benchmark.py --corpus <dir> --labels labels.json --ai --limit 10
```

## 5. Bất biến (đừng phá)

1. **Zero npm dependency ở web.** Server-rendered HTML, không build step. Lý do: một
   sản phẩm bảo mật ship 4MB JS bundle là trò đùa; và deploy = `git pull`.
2. **Engine chạy như subprocess Python**, có timeout + SIGKILL. Một PE lỗi không được
   làm sập web. Không import engine vào process Node.
3. **File upload phải bị xoá ngay** sau scan (kể cả lỗi). Chỉ giữ sha256 + report.
   Có sweep xoá file > 1h lúc boot.
4. **Credit trừ trước, hoàn nếu engine lỗi.** Cache theo `sha256` trong 24h → không trừ.
   Mọi thay đổi ghi `ledger`.
5. **Không nói "uncrackable".** Mọi output ghi rõ "cost model" và `--ai` mới là đo thật.
6. **Không bao giờ gửi binary của khách lên server của ta.** Protect chạy local.
7. **Authority:** không tự `git init`/commit/deploy. Chỉ khi user nói rõ.

## 6. Quyết định đã chốt (không bàn lại)

| Quyết định | Lý do |
|---|---|
| RSA-2048 PKCS#1 thay Ed25519 | CNG của Windows verify được, SDK C++ zero dependency |
| `verifyKey.e` là hex (`010001`), `n` là base64url | C++ nhúng literal được; JWK dùng base64url cho cả hai |
| Per-product keypair | Rotate 1 vendor không ảnh hưởng vendor khác |
| HWID = sha256(MachineGuid + ":" + productId) | Cùng máy ra ID khác nhau cho từng product |
| `protect` 3 chiến lược chèn | `mscorlib.dll` hết chỗ header → phải có overlay fallback |
| CLI protect = free/open | Mua 1 lần rồi copy được; bán audit pass + decoy kit thay vì bán CLI |
| Scan + crack simulation là sản phẩm chính | Dev quan tâm "bị bẻ trong bao lâu" + muốn thấy bằng chứng (patch bytes) |
| One-time audit, không subscription | Nhu cầu episodic (1–3 lần/quý), subscription churn >70% |
| Dừng protect v2 runtime reference | Binary rewriting quá phức tạp + AV false positive; Decoy Kit source-level thay thế |
| Dừng prompt injection payload feed | Frontier model miễn nhiễm; fake code functions hiệu quả hơn fake data |
| SQLite (`node:sqlite`) | Có tiền trong dữ liệu → cần transaction, không dùng JSON store |
| Magic link, không mật khẩu | Ít bề mặt tấn công, không cần reset flow |

## 7. Env vars

| Biến | Dùng cho |
|---|---|
| `PORT` `HOST` `DATA_DIR` `PUBLIC_URL` `TRAPKEY_TLS` | web |
| `ADMIN_KEY` | admin (mặc định sinh vào `DATA_DIR/admin.key`) |
| `STRIPE_SECRET_KEY` `STRIPE_WEBHOOK_SECRET` `STRIPE_PRICE_AUDIT/ANNUAL` | billing thật |
| `RESEND_API_KEY` `MAIL_FROM` | email (không có → outbox file) |
| `TRAPKEY_AI_PROVIDER` = `openai`\|`ollama`\|`anthropic`\|`gemini` | `--ai` |
| `OLLAMA_API_KEY` | Ollama Cloud (`https://ollama.com/v1`), không cần cài Ollama |
| `GEMINI_API_KEY` (`GOOGLE_API_KEY`) | Google Gemini qua AI Studio; base mặc định `https://generativelanguage.googleapis.com/v1beta` |
| `GEMINI_BASE_URL` | override base Gemini (mặc định `.../v1beta`) |
| `TRAPKEY_AI_THINKING_BUDGET` | Gemini `thinkingBudget` (mặc định `0`; rỗng/`off` = để model tự quyết) |
| `TRAPKEY_AI_TIMEOUT` | socket timeout cho 1 call `--ai` (mặc định 120s; `gemini-3.8-flash` cần ~300s và vẫn rất chậm) |
| `OPENAI_BASE_URL` `OPENAI_API_KEY` `ANTHROPIC_API_KEY` `TRAPKEY_AI_MODEL` | `--ai` |
| OpenCode Go | `OPENAI_BASE_URL=https://opencode.ai/inference/go/openai/v1` + `OPENAI_API_KEY=<Go key>`; model `gpt-6-luna` (rẻ), `deepseek-v4.1-flash`, `gemini-4-argon`, `gpt-5.6-luna`… |
| `TRAPKEY_AI_MAX_TOKENS` | output budget cho `--ai` (mặc định 1200; reasoning model ăn hết 400) |
| `TRAPKEY_AI_REASONING_EFFORT` | `low` cho model thinking (tuỳ gateway) |
| `TRAPKEY_AI_CODE` | `0` để tắt IL/objdump trong evidence pack (batch không cần code) |
| `TRAPKEY_CALIBRATION_K` | multiplier từ `calibrate.py` |
| `TRAPKEY_CALIBRATION_MODEL` | band mà `k` áp dụng (`cloud-fast`/`cloud-cheap`/`local-20b`) |
| `TRAPKEY_DEV_MAILER` | `1` để trả `devUrl` cả khi `NODE_ENV=production` (mặc định: chỉ ngoài production) |
| `MAX_CONCURRENT_SCANS` | số engine Python chạy song song (mặc định 4; vượt → 503 `BUSY`) |
| `TRAPKEY_RETENTION_DAYS` | TTL cho scans/events (mặc định 180, tối thiểu 7 — phải > retry window webhook) |
| `COMPARE_TIMEOUT_MS` | timeout cho `/compare` và `compare-reports` (mặc định 30s) |

## 8. Bẫy đã gặp (đừng dẫm lại)

- **Base64url padding**: đổi 1 ký tự cuối có thể decode ra cùng bytes (bit thừa). Test
  tamper phải sửa ký tự **giữa**. SDK C++ reject non-canonical encoding.
- **False positive tên hàm**: `m_userSerializationData`, `Verify_v15`, `ActivationContext`
  từng khớp `serial`/`verify`/`activation`. Đã sửa: tách từ + `STRONG`/`AMBIGUOUS`/`WEAK`.
- **IL size**: `next_rva - rva` không có section bound từng cho ra 1.6GB IL. Đã cap 64KB/method
  và bound theo section.
- **Section header full** (.NET linker-tight): phải fallback overlay.
- **`Tool time` scale**: binary 110MB không thể import Ghidra trong 22s → `size_mb^0.25`.
- **Read budget không đổi giữa các binary** → trông giả. Thêm `sift_tokens` theo code size.
- **`--ai` fail sau khi upload** → đã chuyển check lên trước khi nhận body.
- **Rate limit upload 10/h/IP** làm test web hết quota → test AI mode phải chạy trước
  hoặc dùng DATA_DIR mới.
- **`--ai` là một round, không phải cả workflow**: `measured` không gồm tool time. Đừng
  nhét nó vào `est.seconds` (từng làm `--ai --json` crash `KeyError('measured')` và in
  headline `~0s`).
- **Fit `k`**: `measured` không chứa tool time; chuẩn hoá theo token thật của call
  (`prompt_tokens/prefill + completion_tokens/decode`) → `k` là speed factor. Đừng so
  với một-round/all-round variable (đã trộn workload với speed, k thấp ~3x).
- **Một call là nhiễu**: call đầu batch bị cold-start; dùng `--repeat 3–5` + median.
- **Cache key phải có `mode`**: thiếu nó, scan AI trả lại report static và không trừ credit.
- **UTF-16 strings**: nếu quét ASCII tới limit trước, binary lớn mất toàn bộ string
  UTF-16 (thường là string license của Windows) → chia budget 2/3 + 1/3.
- **So sánh tên section**: `{"UPX0"} & {s.lower()}` luôn rỗng → phát hiện UPX/VMProtect chết.
- **Magic link**: `SELECT used=0` rồi `UPDATE` là race; dùng `UPDATE ... WHERE used=0`
  trong transaction.
- **Admin key không đi qua query string** (access log/referrer) → POST form + cookie HttpOnly.
- **Strip PDB**: zero cả data-directory entry lẫn CodeView bytes; chỉ zero entry thì
  `strings` vẫn thấy đường dẫn build.
- **Payload v2 seed theo build nhưng phải decode được**: seed lưu obfuscated (`seed_c`)
  trong blob; nếu không agent không đọc được decoy thì trap vô dụng.
- **Đừng đặt tên method trùng attribute**: `PE.data_dir` là offset int, method đọc entry
  phải tên khác (`dir_entry`), không thì `self.data_dir(6)` nổ.
- **Metadata HeapSizes ở `base+6`**, không phải `base+7` (đó là Reserved2, compiler nào
  ghi 0x01/0x0a tuỳ ý). Đọc sai → mọi bảng lệch, tên method rác, `license_methods` rỗng.
  Đây là bug cũ làm `dotnet_il_bytes` sai; đã sửa + test `types[0] == '<Module>'`.
- **IL opcode 0x76–0x81**: phải có *hai* slot `unused` sau `conv.r.un`; thiếu một slot làm
  `throw` decode thành `ldfld` và mọi token sau đó lệch.
- **xref = địa chỉ trong comment `# 0x...`, không phải địa chỉ instruction**: so `addr`
  với map string (VA) luôn trượt. Comment của objdump cho PE là VA (`image_base + rva`).
- **Chỉ annotate string ở section không writable**: `.data` chứa con trỏ, đọc ra ký tự
  rác (`+PLTE`) và làm model hiểu sai.
- **objdump có thể không có** (Windows CI): disassembly là optional, thiếu thì pack vẫn
  chạy; đừng import `capstone` hay thêm dependency.
- **Success của `--ai` phải grounded**: model từng trả `ValidateKeyName` (không có trong
  pack) mà vẫn tính success. Giờ `FUNCTION:` phải xuất hiện trong pack (tên) hoặc là địa
  chỉ nằm trong image, nếu không = fail. Prompt cũng yêu cầu chỉ nêu hàm có trong evidence.
- **`is_license_ident` cần chặn context word**: `ValidateKeyName/Rights/Mode` là registry
  API (validate + key = 2 weak). Thêm `CONTEXT` (name/mode/value/size...) và đếm weak
  **distinct** (`GetBaseKeyFromKeyName` lặp "key" 2 lần).
- **`TrialDivisionBounds` vẫn là false positive** (trial là STRONG): chấp nhận, hiếm gặp
  ngoài thư viện toán; đừng thêm stoplist mỗi lúc gặp một tên.
- **`if (secret) verify(...)` = webhook không xác thực**: thiếu `STRIPE_WEBHOOK_SECRET`
  thì mọi event không chữ ký đều được nhận (tự nâng gói). Phải trả 503 khi thiếu secret,
  verify cả timestamp (±300s), và không tin `metadata.plan` một cách mù quáng — nhưng
  metadata do checkout của ta set + chữ ký Stripe là đủ; nhớ set `subscription_data`
  để event huỷ subscription tìm được account.
- **`X-Forwarded-For` lấy phần tử đầu là spoofable**: nginx `$proxy_add_x_forwarded_for`
  nối thêm IP thật vào **cuối**, nên phần tử đầu do client gửi. Dùng `X-Real-IP` do
  nginx ghi đè (chỉ tin khi peer là loopback/private), đừng đọc XFF.
- **Quota anonymous phải giữ chỗ trước khi nhận body**: check sau upload cho phép đốt
  150MB/lần dù đã hết quota. Reserve trước, refund trong `finally` nếu scan fail.
- **`report.file` là path tạm của server**: đừng trả nguyên path trong JSON công khai;
  web ghi đè bằng basename của `x-filename`, `ai.py` chỉ gửi basename cho model.
- **Gateway S3 bọc 429 của Ollama trong HTTP 503**: đừng chỉ nhìn status; phải đọc body
  (`weekly usage limit`, `reset after ...`). `classify_failure()` trả `AI_QUOTA/AI_AUTH/
  AI_MODEL/AI_PROVIDER/AI_NETWORK`; `scan.py --json` in envelope lỗi và exit 3; web map
  thành 429/503 với message đúng, không được báo "engine could not read this file".
- **`compare` không được nói "unchanged = không tốt hơn" khi có finding đã mất**: verdict
  và fixed_findings phải đọc cùng một nguồn; weight đổi nhưng id giữ nguyên phải vào
  `changed_findings`, guard biến mất phải vào `protection_removed`.
- **Benchmark phải lấy nhãn làm truth**: không dùng `measure()["success"]`/`grounded`
  làm đúng/sai; header model có thể là `**FUNCTION:**`, `1. FUNCTION:`; label key có
  `/` không được fallback theo basename (sẽ gán nhãn sai cho file khác cùng tên).
- **Retention xoá `events`**: `events` vừa là audit vừa là webhook idempotency; TTL
  tối thiểu 7 ngày và phải > retry window của provider (Stripe ~72h). Timestamp ±300s
  vẫn là lớp chặn replay cuối.
- **AI cooldown toàn cục** chỉ set cho `AI_QUOTA`, cap 1h; `AI_AUTH`/`AI_MODEL` không
  được khoá AI 5 phút; static scan không bị ảnh hưởng.
- **`readJson` lỗi phải map ở dispatch, không chỉ trong route `/api/compare`**: `BAD_JSON`
  ném từ auth/checkout/admin grant từng trả 500 INTERNAL; `EMPTY`/`UPLOAD` cũng phải là
  400 và quota đã refund trước khi lỗi ra tới đây.
- **Xoá account phải xoá theo email, không chỉ account_id**: `magic_links` key theo email,
  còn event `magic_link` ghi `account_id=NULL`; chỉ `DELETE ... WHERE account_id` để lại PII.
  Scrub payload event (`{}`) và giữ row như audit ẩn danh.
- **`compare` phải check magic `MZ` trước `collect()`**: file non-PE 200MB từng bị đọc 2 lần
  + extract strings trước khi báo lỗi (~4.6s, 227MB RSS); giờ đọc 2 byte là đủ.
- **Sweeper upload/tmp phải chịu được thư mục biến mất**: `readdirSync` ném ENOENT trong
  timer callback từng làm sập web; test gọi trực tiếp qua `server.trapkey.sweepUploads`.
- **OpenCode Go chặn UA mặc định của Python**: gọi `opencode.ai/inference/go/openai/v1`
  bằng urllib không set `User-Agent`/`x-opencode-session` trả **403/1010** dù key đúng.
  `_call_openai` set `trapkey/1.0` + session ngẫu nhiên; token OAuth trong OpenCode DB
  hết hạn ~26 ngày, production nên dùng API key tạo ở Console → Go.
- **`compare --ai` không được trộn measured với cost model**: `measured` là 1 round,
  không gồm tool time; để riêng `delta`/`ai` và in “live measurement does not confirm”
  khi static nói better mà measured không tăng. Case study Cryptlex: static +12.8s
  nhưng measured **-1.19s**, cả hai vẫn tìm ra check → protect data-only chưa đủ.
- **Median của `--repeat` chỉ tính round success** (giống `calibrate.summarize_attempts`):
  gộp round fail vào median có thể gắn `success=true` với thời gian của lần model bỏ cuộc.
- **1 round không đủ kết luận nhanh/chậm**: ngưỡng là `max(2s, 15%)` và ≥3 round mỗi bên;
  1.19s trong case study là **within noise**, đừng đổi thành "faster".
- **`measured` trong report upload là input không tin cậy**: `attempts` phải sanitize
  (`int(dict)` ném TypeError làm reject cả report), và `model` phải `esc()` khi render
  `/compare` (từng render thẳng thành thẻ HTML).

## 9. Việc đang mở (ưu tiên từ trên xuống)

1. **P0 — Crack Simulation (Round 2 AI)**: ✅ Done (prompt, verify, report, scan.py, `views.js` free/paid tiering).
   Chi phí thêm ~$0.0002/scan. Xem `docs/ROADMAP.md`.
2. **P0 — Pricing pivot**: ✅ Done (`config.js` Free / Audit Pass $49 / Annual CI $199,
   `credits.js` one-time expiry + unlimited static, `server.js` checkout `mode=payment`,
   `views.js` pricing + free report redaction + UI high-tech + i18n `vi`/`en`).
3. **P1 — Decoy Kit**: ✅ Done (`sdk/dotnet/TrapKeyDecoy.cs` + `sdk/cpp/trapkey_decoy.h` +
   `evidence.py`/`estimate.py` decoy coverage & multi-point IL call detection + `test_decoy_kit.py`).
4. **P2 — Triển khai**: VPS + systemd + nginx + certbot + Stripe ($49 Audit Pass) + Resend.
5. **P2 — Fix bugs**: ✅ Done (`BCryptVerifySignature` `BCRYPT_PKCS1_PADDING_INFO` + `JsonEscape` trong `sdk/cpp/trapkey.cpp`, Authenticode warning trong `pe.py`/`trapkey.py`, privacy statement trong `views.js`). *(C++ SDK vẫn chưa compile thử trên MSVC.)*
6. **Re-fit `k`**: đã fit cho default `gpt-6-luna` (OpenCode Go) — **k=1.2673**,
   n=7, spread 2.27x, corpus 7 DLL licensing NuGet + System.Core/Security + WinRAR
   (2026-11-16). DeepSeek V4.1 Flash chưa fit được vì 1200 token bị reasoning ăn hết;
   nếu đổi sang DeepSeek phải đặt `TRAPKEY_AI_MAX_TOKENS=4000` rồi chạy lại
   `calibrate.py --ai --repeat 3`, xem `docs/CALIBRATION.md` §8.
7. **Calibrate thêm**: corpus run 4 có 8/11 là .NET; chỉ WinRAR/notepad native.
   Cần thêm 5–6 shareware native thật cho fit `k` native.
8. **SDK C++**: build trên Windows, sửa bugs, thêm CI `windows-latest`.

**Đã loại bỏ khỏi roadmap:**
- ~~Protect v2 runtime reference~~ — binary rewriting post-build quá phức tạp,
  case study chứng minh data-only payload không hiệu quả, AV false positive risk.
  Thay bằng Decoy Kit source-level.
- ~~Payload feed server~~ — prompt injection bị frontier model miễn nhiễm.
- ~~Monthly subscription $29~~ — churn >70% cho diagnostic tool episodic.

## 10. Định vị & giá (pivot 2026-11-18)

> Đổi từ subscription sang one-time + annual. Lý do: scan là nhu cầu episodic
> (1–3 lần/quý), subscription $29/tháng bị churn >70% ở tháng 2.

| Gói | Giá | static | ai (crack sim) |
|---|---|---|---|
| Free | $0 | 5/tháng | 3/tháng (giấu patch bytes) |
| Anonymous | — | 1/ngày/IP | — |
| Audit Pass | **$49 mua đứt** | 10 | 3 (full report + Decoy Kit) |
| Annual CI | **$199/năm** | unlimited | 50/năm + CI badge |
| Consulting | **$500–2,000/lần** | — | Custom report + tư vấn |

Chi phí AI ~$0.0005/scan (2 round gpt-6-luna) → biên gần như toàn phần.
Anonymous scan là marketing. Free tier giấu patch bytes + giấu fix → incentive mua.

**Giá cũ (đã bỏ):** ~~Pro $29/tháng, Team $99/tháng~~ — churn quá cao cho diagnostic tool.

## 11. Cách viết code trong repo này

- Python: type hints nhẹ, `from __future__ import annotations`, không dependency ngoài
  `cryptography` (chỉ dùng cho `verify` và test AI/offline).
- JS: CommonJS, không framework, template literal cho HTML, escape mọi thứ qua `views.esc`.
- Comment giải thích **tại sao**, không giải thích **cái gì**.
- Mọi con số trong báo cáo phải in ra được cách tính (breakdown/notes), nếu không thì
  không đáng tin.
- Test: `unittest` cho Python, script tự chạy cho Node. Không mock engine — dùng PE thật.
