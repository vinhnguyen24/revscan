# TrapKey

> **Bắt đầu ở đây:** [`AGENTS.md`](AGENTS.md) — ngữ cảnh master cho phiên làm việc mới.
> Trạng thái gần nhất: [`docs/HANDOFF_2026-11-14.md`](docs/HANDOFF_2026-11-14.md).

**Scan một app Windows: AI reverse-engineering agent mất bao nhiêu giây để bẻ?**

```bash
python3 scan.py C:/path/YourApp.exe
```

```
TrapKey scan — YourApp.exe
dotnet · 4,631,552 bytes · sha256 952703a7a04ee371…
────────────────────────────────────────────────────────
→ AI cracks this in ~48s (likely, p=0.9) · risk 59/100

AI crack time (estimated)
  Claude/GPT class (API)     ~48s
  cheap API model            ~81s
  local 20B (Ollama)         ~3.1 phút
  P(success)                 0.9
  risk                       59/100 (100 = cracked in seconds)

What the agent actually reads
  · licence strings visible but functions unnamed: agent must resolve xrefs
  · tool time scaled x1.5 for a 5 MB binary
  · read budget 104,721 tokens / agent rounds 2.6 / tool time 3s
```

### Chế độ `--ai` dùng model nào? (không bắt buộc OpenAI)

Static scan **không cần key gì cả**. `--ai` là tuỳ chọn, và dùng interface
OpenAI-compatible nên cắm được gần như mọi model:

| Provider | Env | Chi phí |
|---|---|---|
| **Ollama local** | `TRAPKEY_AI_PROVIDER=ollama` `TRAPKEY_AI_MODEL=qwen2.5-coder:7b` | 0đ (chậm) |
| **Ollama Cloud** | `OLLAMA_API_KEY` `TRAPKEY_AI_MODEL=gpt-oss:120b` | theo plan, không cần GPU |
| OpenAI | `OPENAI_API_KEY` `TRAPKEY_AI_MODEL=gpt-4o-mini` | ~$0.01/scan |
| **DeepSeek / Groq / Together / OpenRouter / vLLM / LM Studio** | `OPENAI_BASE_URL=https://api.deepseek.com/v1` + `OPENAI_API_KEY` | rẻ hơn OpenAI |
| Anthropic | `ANTHROPIC_API_KEY` | ~$0.01/scan |

```bash
# local, miễn phí
TRAPKEY_AI_PROVIDER=ollama TRAPKEY_AI_MODEL=qwen2.5-coder:7b python3 scan.py App.exe --ai

# Ollama Cloud: chỉ cần key, base https://ollama.com/v1 được set tự động
OLLAMA_API_KEY=... TRAPKEY_AI_MODEL=gpt-oss:120b python3 scan.py App.exe --ai

# rẻ, nhanh
OPENAI_BASE_URL=https://api.deepseek.com/v1 OPENAI_API_KEY=sk-... \
  TRAPKEY_AI_MODEL=deepseek-chat python3 scan.py App.exe --ai
```

Web tự ẩn nút "AI-measured" khi chưa cấu hình model, và trả `503 AI_UNAVAILABLE`
kèm hướng dẫn thay vì lỗi mơ hồ.

### `--ai` gửi gì cho model?

Không chỉ strings: pack có **code thật** để model không trả "insufficient evidence".

- .NET: method body IL của các method load licence string (`ldstr`) hoặc tên licence —
  token được resolve thành `Type::Method`, `ldstr` thành chuỗi thật.
- Native: `objdump` tìm instruction tham chiếu licence string (rip-relative) rồi lấy
  nguyên hàm chứa nó; call vào import table được annotate (`->CRYPT32!CryptVerifySignatureA`).
  Không có xref thì fallback: crypto imports → named export → entry point.
- `objdump` là **optional**: thiếu nó thì pack không có code, scan vẫn chạy.
  Tắt hẳn bằng `TRAPKEY_AI_CODE=0` (batch chỉ đo strings, nhanh hơn).

---

## Web SaaS (chạy được, 0 dependency)

```bash
npm start                  # web/server.js, http://127.0.0.1:7200
```

- `/` landing · `/scan` upload · `/r/:id` báo cáo chia sẻ được
- `/pricing` · `/login` (magic link) · `/app` dashboard · `/app/settings`
- `/app/admin` (nhập key ở form; key in ra ở boot hoặc trong `web-data/admin.key`)

Dev không cần SMTP: link đăng nhập ghi vào `web-data/outbox/*.txt` và API trả `devUrl`.
Production **không** trả `devUrl` (đặt `TRAPKEY_DEV_MAILER=1` chỉ khi bạn thật sự muốn
mở lại đường dev). Không có `RESEND_API_KEY` thì link chỉ nằm trong outbox.

Thanh toán: có `STRIPE_SECRET_KEY` + `STRIPE_WEBHOOK_SECRET` thì tạo Checkout thật;
không có Stripe thì rơi vào **invoice mode** (ghi nhận yêu cầu, admin cấp gói).
Thiếu `STRIPE_WEBHOOK_SECRET` thì endpoint webhook trả 503 và **không** nhận event
không chữ ký — nếu không, ai cũng tự nâng gói được.

Chi tiết kiến trúc, API, credit, bảo mật: [`docs/WEB_PLAN.md`](docs/WEB_PLAN.md).

### Credit

| | static | ai |
|---|---|---|
| Free | 5 / tháng | 1 / tháng |
| Pro $29 | 200 / tháng | 25 / tháng |
| Team $99 | 2000 / tháng | 100 / tháng |
| Khách vãng lai | 1 / ngày / IP (chỉ tóm tắt) | — |

Cùng một file (SHA-256) trong 24h → **không trừ credit**. Scan lỗi → hoàn credit.
Mọi thay đổi ghi vào bảng `ledger`.

---

## Cái gì đang có trong repo

| Thành phần | Trạng thái | Mô tả |
|---|---|---|
| **`scanner/` + `scan.py`** | ✅ chạy được, có test | Đọc PE/.NET metadata thật, đếm hàm/method, tính thời gian crack theo cost model minh bạch |
| **`web/`** | ✅ chạy được, 40 test | SaaS: landing, upload scan, **/compare trước–sau từ 2 report JSON**, magic-link auth, credit, dashboard, admin, invoice/Stripe, retention, AI cooldown |
| `cli/trapkey.py protect` | ✅ chạy được (15 test) | Strip PDB + payload v2 mã hoá theo build, decoy chunk, chữ ký bundle tuỳ chọn |
| `cli/trapkey.py compare` | ✅ chạy được (19 test) | Scan gốc vs bản protect: delta giây/p/risk + finding thay đổi |
| `benchmark.py` | ✅ chạy được (46 test) | Ground-truth harness: chấm static/`--ai` bằng nhãn, không dùng success tự báo |
| `cli/trapkey.py verify` | ✅ chạy được | Verify token RSA offline |
| `server/` | ✅ chạy được (19 test) | License server + admin UI — **không phải sản phẩm chính**, xem ghi chú bên dưới |
| `sdk/cpp`, `sdk/dotnet` | ⚠️ chưa compile | SDK licensing, Windows-only |
| `demo/demo.py` | ✅ | Demo luồng license end-to-end |

> **Định vị:** sản phẩm là **scan → protect → monitor**. License server là add-on
> để dành, không đưa lên trang chủ (nó là commodity, không phải lý do khách trả tiền).

---

## Scan hoạt động thế nào

Không đoán. Mỗi con số đều lấy từ file:

| Lấy được gì | Từ đâu |
|---|---|
| Số hàm native (chính xác, không ước lượng) | `.pdata` — mỗi `RUNTIME_FUNCTION` 12 byte |
| Số method .NET + tên + IL bytes | ECMA-335 metadata: table `MethodDef` (0x06), heap `#Strings` |
| Tên hàm/type bị lộ | `ident.py`: tách camelCase rồi match cả từ (tránh `m_userSerializationData`) |
| Import crypto/anti-debug | import table |
| Packed / obfuscated | entropy section + tỉ lệ tên rác |
| Trap đang bật | marker `TK1`/`TK2` + pattern prompt-injection |

Sau đó `estimate.py` tính:

```
seconds = tool_time + read_budget / prefill_rate
        + rounds * 1200 output tokens / decode_rate
```

`tool_time` = 22s (Ghidra headless) hoặc 2s (.NET dump). `read_budget` phụ thuộc
vào việc agent có tìm được chỗ kiểm tra license bằng `grep` hay phải đọc cả code.
Công thức + hằng số + cách calibrate: [`docs/CALIBRATION.md`](docs/CALIBRATION.md).

---

## Chạy

```bash
# web
npm start                          # http://127.0.0.1:7200
node tests/test_web.js             # 40 test end-to-end

# scan một file
python3 scan.py C:/path/App.exe

# máy đọc (JSON, cho web/CI)
python3 scan.py App.exe --json

# CI gate: fail nếu AI bẻ được dưới 60 giây
python3 scan.py dist/App.exe --min-seconds 60

# đo thật bằng model (tốn token)
OPENAI_API_KEY=... python3 scan.py App.exe --ai

# calibrate hàng loạt: model vs đo thật -> ra một multiplier k
python3 calibrate.py C:/path/binaries --limit 20
TRAPKEY_AI_PROVIDER=ollama python3 calibrate.py C:/path/binaries --ai --limit 10
TRAPKEY_CALIBRATION_K=1.7 python3 scan.py App.exe

# protect: strip PDB + chèn payload v2 (mã hoá theo build, có decoy)
python3 cli/trapkey.py protect dist/App.exe --level 3
python3 cli/trapkey.py protect dist/App.exe --no-strip --level 2
python3 cli/trapkey.py info dist/App.protected.exe    # xem payload/chunk/decoy

# đo lại sau khi protect: trước/sau, delta giây/p/risk, finding nào mất
python3 cli/trapkey.py compare dist/App.exe dist/App.protected.exe --json

# web /compare: upload 2 report JSON, không upload binary
python3 scan.py dist/App.exe --json > before.json
python3 scan.py dist/App.protected.exe --json > after.json
# rồi mở /compare và chọn 2 file, hoặc:
python3 cli/trapkey.py compare-reports before.json after.json --json

# ground-truth benchmark: nhãn do người tạo, không lấy output TrapKey làm nhãn
python3 benchmark.py --corpus C:/corpus --labels labels.json --static
python3 benchmark.py --corpus C:/corpus --labels labels.json --ai --limit 10

# payload feed có chữ ký (tuỳ chọn; từ chối bundle không do vendor ký)
python3 cli/trapkey.py protect dist/App.exe --sig payloads.sig --pubkey vendor.pem

# test
python3 tests/test_scan.py
python3 tests/test_protect.py
node server/test/flow.test.js      # license server (add-on)
python3 demo/demo.py               # luồng license end-to-end

# không có binary Windows sẵn: trỏ tới thư mục của bạn
TRAPKEY_TEST_BINARIES=/path/to/binaries npm test
```

CI (`.github/workflows/ci.yml`) chạy Ubuntu + Windows; test PE/.NET tự skip nếu không
tìm thấy binary (`TRAPKEY_TEST_EXE`, `TRAPKEY_TEST_DOTNET`, `TRAPKEY_TEST_BINARIES`).

`protect` levels: `1` = plaintext (debug), `2` = encrypted theo build (không gợi ý),
`3` = encrypted + decoy chunk + reference trailer (khuyến nghị — agent decode được
rồi đọc decoy).

---

## Đã kiểm chứng trong môi trường này

| Việc | Kết quả |
|---|---|
| 27 test scanner (ident, PE, .NET metadata, chiều của model, provider, AI error codes, report JSON) | ✅ pass |
| 18 test calibrate (fit k, tool time không bị scale, per-model k, CLI) | ✅ pass |
| Calibrate run 3 (`ollama/gpt-oss:120b` qua gateway S3) | k=0.2758, n=10, spread 1.87x (2026-11-14) |
| 15 test protect (payload v2 round-trip, seed theo build, strip PDB, chữ ký bundle, CLI) | ✅ pass |
| 19 test compare (delta, JSON một object, same file, lỗi input, PE truncate) | ✅ pass |
| 46 test benchmark (labels, matching, FP/FN, skip, CLI, JSON) | ✅ pass |
| `notepad.exe` (không có license logic) | ~72s, p=0.35 |
| `notepad.exe` + string license | ~60s, p=0.85 (string giúp agent tìm nhanh hơn) |
| cùng file, `protect --level 3` (v2) | ~83s, p=0.05 (strip PDB + trap + decoy) |
| `mscorlib.dll` (27.492 methods) | ~48s, p=0.90 (metadata lộ toàn bộ tên hàm) |
| 40 test web (login, quota, cache, paywall, admin, CI token, webhook, retention, AI quota/cooldown, 404, AI mode) | ✅ pass |
| 16 test license server | ✅ pass |
| SDK C++ / .NET compile | ⚠️ chưa (không có MSVC ở đây) |

---

## Cấu trúc

```
scan.py                  entry: scan <file> [--json] [--min-seconds] [--ai]
calibrate.py             batch scan + đo thật -> fit multiplier k
benchmark.py             chấm static/--ai bằng nhãn ground truth (hit/FP/FN/latency)
benchmarks/              README + labels.example.json
web/
  server.js              HTTP + routes + billing + admin
  db.js                  SQLite (node:sqlite), schema, ledger
  auth.js                magic link, session cookie, CI token
  credits.js             credit buckets, monthly reset, anonymous quota
  scanjob.js             upload streaming + engine subprocess
  views.js / static/     server-rendered HTML, CSS, scan.js
deploy/                  systemd unit + nginx conf
scanner/
  peinfo.py              PE: sections, entropy, imports, exports, .pdata
  dotnet.py              ECMA-335 metadata: MethodDef/TypeDef/MemberRef + IL body
  il.py                  IL decoder (ldstr/call resolve tên thật)
  native.py              objdump xref licence string/crypto -> disassembly
  ident.py               tách identifier, tránh false positive
  evidence.py            thu thập bằng chứng + phát hiện trap/packer
  estimate.py            cost model -> số giây
  report.py              human / JSON
  ai.py                  --ai: đo thật bằng model (pack có code) + phân loại lỗi
  compare.py             original vs protected: delta + finding thay đổi
cli/trapkey.py           protect / verify / info / compare
server/                  license server (add-on)
sdk/                     SDK licensing (Windows)
docs/SPEC.md             spec license server
docs/CALIBRATION.md      công thức + cách calibrate con số
docs/ROADMAP.md          30 ngày + kill criteria
tests/test_scan.py       test scanner
```

## License

Proprietary. © 2026.
