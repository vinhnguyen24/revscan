# RevScan

> **How many seconds until an AI agent cracks your Windows app?**

RevScan is an open-source security scanner that answers one question: *how fast can an AI reverse-engineering agent find and patch the license check in your Windows binary?* It gives you hard numbers, real evidence, and a concrete crack simulation — not vague advice.

```
$ python scan.py YourApp.exe

RevScan scan — YourApp.exe
dotnet · 4,631,552 bytes · sha256 952703a7…
────────────────────────────────────────────────
→ AI cracks this in ~48s (likely, p=0.9) · risk 59/100

AI crack time (estimated)
  Claude/GPT class (API)     ~48s
  cheap API model            ~81s
  local 20B (Ollama)         ~3.1 min
  P(success)                 0.9
  risk                       59/100

What the agent reads
  · .NET app keeps English function names (CheckLicenseKey, IsProUnlocked)
  · License check is readable IL, not obfuscated
  · "License expired" string leads straight to the check function
```

## Features

- **Static scan** — parse PE headers, .NET metadata (ECMA-335), IL bytecode, imports, exports, strings. Zero external dependencies. Runs in <1 second.
- **AI-measured scan** (`--ai`) — send evidence to a live LLM and measure how many seconds it takes to find the license check. Works with OpenAI, Anthropic, Gemini, Ollama, DeepSeek, or any OpenAI-compatible API.
- **Crack simulation** — after finding the check, the AI proposes exact patch bytes (`offset 0x2056: 2C → 2D`) and RevScan verifies the patch is valid.
- **Before/after comparison** — scan your original app and the protected version, see what improved.
- **CI gate** — `--min-seconds 60` exits with code 1 if an AI could crack your app in under 60 seconds.
- **Decoy Kit** — drop-in C#/C++ source files that add realistic fake license functions to waste the attacker's time.
- **Web UI** — self-hosted SaaS with upload, reports, auth, dashboard. Zero npm dependencies, server-rendered HTML. 12 languages.
- **Calibration** — batch-scan a corpus of binaries and fit a multiplier `k` so the cost model matches real AI measurements.

## Quick Start

**Requirements:** Python 3.10+, Node.js 22+ (for web UI only)

```bash
# Scan a binary (no API key needed)
python scan.py path/to/App.exe

# JSON output for CI/scripts
python scan.py App.exe --json

# CI gate: fail if crackable in under 60 seconds
python scan.py App.exe --min-seconds 60

# Measure with a live AI model
OPENAI_API_KEY=sk-... python scan.py App.exe --ai

# Start the web UI
npm start  # http://127.0.0.1:7200
```

## AI Provider Setup

Static scan needs **no API key**. The `--ai` flag uses an OpenAI-compatible interface and works with almost any provider:

| Provider | Setup | Cost |
|---|---|---|
| **Ollama (local)** | `TRAPKEY_AI_PROVIDER=ollama TRAPKEY_AI_MODEL=qwen2.5-coder:7b` | Free (slow) |
| **Ollama Cloud** | `OLLAMA_API_KEY=... TRAPKEY_AI_MODEL=gpt-oss:120b` | Per plan |
| **Google Gemini** | `TRAPKEY_AI_PROVIDER=gemini GEMINI_API_KEY=...` | Free tier available |
| **OpenAI** | `OPENAI_API_KEY=sk-...` | ~$0.01/scan |
| **DeepSeek / Groq / Together / OpenRouter** | `OPENAI_BASE_URL=https://api.deepseek.com/v1 OPENAI_API_KEY=...` | Varies |
| **Anthropic** | `ANTHROPIC_API_KEY=...` | ~$0.01/scan |
| **Any OpenAI-compatible** | `OPENAI_BASE_URL=... OPENAI_API_KEY=...` | Varies |

See [`.env.example`](.env.example) for all configuration options.

## How the Scanner Works

No guesswork. Every number is extracted from the binary:

| Evidence | Source |
|---|---|
| Native function count (exact) | `.pdata` — each `RUNTIME_FUNCTION` is 12 bytes |
| .NET methods + names + IL bytes | ECMA-335 metadata: `MethodDef` table, `#Strings` heap |
| Leaked function/type names | `ident.py`: split camelCase, match whole words |
| Crypto/anti-debug imports | PE import table |
| Packed/obfuscated | Section entropy + junk name ratio |
| Decoy coverage | `TK_DECOY_V1` marker + IL call analysis |

The cost model in [`estimate.py`](scanner/estimate.py) then computes:

```
seconds = tool_time + read_budget / prefill_rate
        + rounds × 1200 output_tokens / decode_rate
```

Where `tool_time` = 22s (Ghidra) or 2s (.NET dump). Full formula and calibration methodology: [`docs/CALIBRATION.md`](docs/CALIBRATION.md).

## What `--ai` Sends to the Model

Not just strings — the evidence pack includes **real code** so the model doesn't return "insufficient evidence":

- **.NET**: IL method bodies of functions that load license strings (`ldstr`) or have license-related names. Tokens are resolved to `Type::Method`.
- **Native**: `objdump` finds instructions referencing license strings (RIP-relative), then extracts the containing function. Import calls are annotated (`→ CRYPT32!CryptVerifySignatureA`).
- `objdump` is **optional** — without it, the pack has no disassembly but the scan still runs. Set `TRAPKEY_AI_CODE=0` to disable.

## Project Structure

```
scan.py                  CLI entry: scan <file> [--json] [--min-seconds] [--ai]
calibrate.py             Batch scan + fit multiplier k
benchmark.py             Ground-truth harness (hit/FP/FN, latency)

scanner/
  peinfo.py              PE headers, sections, entropy, imports, exports, .pdata
  dotnet.py              ECMA-335 metadata: MethodDef/TypeDef/MemberRef, IL body
  il.py                  IL decoder → method body (ldstr/call with real names)
  native.py              objdump xref: license string/crypto → disassembly
  ident.py               Identifier splitting, false-positive prevention
  evidence.py            Evidence collection + trap/packer/asar detection
  estimate.py            Cost model → seconds
  report.py              Human-readable + JSON rendering
  ai.py                  AI provider config + crack simulation + error classification
  compare.py             Original vs protected: delta + finding changes

cli/revscan.py           protect / verify / info / compare / compare-reports
web/
  server.js              HTTP, routes, billing, admin, static
  db.js                  SQLite (node:sqlite), schema, transactions, ledger
  auth.js                Magic-link auth, session cookies, CI tokens
  credits.js             Credit buckets, monthly reset, anonymous quota
  scanjob.js             Upload streaming → engine subprocess → cleanup
  views.js               Server-rendered HTML (no framework, no build step)
  i18n.js                12 languages (en, vi, ja, ko, zh, de, fr, es, pt, ru, pl, id)
  static/                CSS, JS, assets

sdk/dotnet/              TrapKeyDecoy.cs — Decoy Kit for C#
sdk/cpp/                 revscan_decoy.h — Decoy Kit for C/C++
server/                  License server (optional add-on)
deploy/                  systemd unit + nginx config
docs/                    Spec, calibration, case studies, roadmap
benchmarks/              Ground-truth corpus instructions
tests/                   256 tests (Python unittest + Node.js)
```

## CLI Reference

```bash
# --- Scan ---
python scan.py App.exe                          # Human-readable report
python scan.py App.exe --json                   # JSON output
python scan.py App.exe --ai                     # Live AI measurement
python scan.py App.exe --min-seconds 60         # CI gate (exit 1 if below)
python scan.py dist/*.exe --json                # Batch scan

# --- Protect ---
python cli/revscan.py protect App.exe --level 3        # Strip PDB + encrypted payload + decoy
python cli/revscan.py protect App.exe --no-strip       # Keep PDB
python cli/revscan.py info App.protected.exe           # Inspect payload/chunks

# --- Compare ---
python cli/revscan.py compare App.exe App.protected.exe --json
python cli/revscan.py compare App.exe App.protected.exe --ai --repeat 3
python cli/revscan.py compare-reports before.json after.json --json

# --- Calibrate ---
python calibrate.py /path/to/binaries --limit 20
python calibrate.py /path/to/binaries --ai --repeat 3
TRAPKEY_CALIBRATION_K=1.27 python scan.py App.exe

# --- Benchmark ---
python benchmark.py --corpus /path --labels labels.json --static
python benchmark.py --corpus /path --labels labels.json --ai --limit 10
```

## Web UI

```bash
npm start  # http://127.0.0.1:7200
```

Self-hosted, zero npm dependencies, server-rendered HTML.

- `/` — Landing page
- `/demo` — Interactive demo with sample reports
- `/scan` — Upload and scan a binary
- `/compare` — Compare before/after reports
- `/pricing` — Plans (Free / Audit Pass / Annual CI)
- `/login` — Magic-link authentication
- `/app` — Dashboard (scan history, credits)
- `/r/:id` — Shareable public report

**Dev mode:** Without `RESEND_API_KEY`, login links are saved to `web-data/outbox/` and the API returns a `devUrl`. Set `NODE_ENV=production` to disable.

## Decoy Kit

Drop-in source files that add realistic fake license functions to your app. An AI agent wastes time analyzing decoys instead of finding the real check.

**C#:**
```csharp
// Add to your project, call from startup:
TrapKeyDecoy.Warmup();

// Sprinkle multi-point checks (≥5 locations):
TrapKeyDecoy.Verify(licenseKey, 0);  // in Main
TrapKeyDecoy.Verify(licenseKey, 1);  // in SaveFile
TrapKeyDecoy.Verify(licenseKey, 2);  // in ExportPdf
```

**C/C++:**
```c
#include "revscan_decoy.h"
revscan_decoy_warmup();
revscan_decoy_verify(key, 0);
```

The scanner detects Decoy Kit integration and reports coverage. See [`sdk/dotnet/TrapKeyDecoy.cs`](sdk/dotnet/TrapKeyDecoy.cs) and [`sdk/cpp/revscan_decoy.h`](sdk/cpp/revscan_decoy.h).

## Tests

```bash
# Run all 256 tests
npm test

# Or individually:
python tests/test_scan.py
python tests/test_calibrate.py
python tests/test_protect.py
python tests/test_compare.py
python tests/test_disasm.py
python tests/test_benchmark.py
python tests/test_decoy_kit.py
node tests/test_web.js
node tests/test_web_views.js
node server/test/flow.test.js
```

CI runs on Ubuntu + Windows. PE/.NET tests auto-skip if no test binaries are found. Set `TRAPKEY_TEST_EXE`, `TRAPKEY_TEST_DOTNET`, or `TRAPKEY_TEST_BINARIES` to point to real binaries.

## Configuration

All config is via environment variables. See [`.env.example`](.env.example) for the full list.

| Variable | Purpose |
|---|---|
| `TRAPKEY_AI_PROVIDER` | `openai` / `ollama` / `anthropic` / `gemini` |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | AI provider credentials |
| `TRAPKEY_AI_MODEL` | Model name (default: provider-specific) |
| `TRAPKEY_CALIBRATION_K` | Fitted multiplier from `calibrate.py` |
| `PORT` / `HOST` | Web server (default: 7200 / 127.0.0.1) |
| `ADMIN_KEY` | Admin dashboard access |
| `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` | Stripe billing (optional) |
| `RESEND_API_KEY` | Email delivery (optional; without it, links go to outbox) |

## Technical Details

- **Zero npm dependencies** — the web server uses only Node.js built-in modules (`node:http`, `node:sqlite`, `node:crypto`, `node:fs`). No Express, no React, no build step.
- **Engine isolation** — the Python scanner runs as a subprocess with timeout + SIGKILL. A malformed PE cannot crash the web server.
- **Privacy** — uploaded files are deleted immediately after scan (even on error). Only SHA-256 hash + report are stored.
- **Credits** — deducted before scan, refunded on engine error. Same file (SHA-256) cached for 24h.

## Docs

- [`docs/CALIBRATION.md`](docs/CALIBRATION.md) — Cost model formula, constants, calibration methodology
- [`docs/WEB_PLAN.md`](docs/WEB_PLAN.md) — Web architecture, API, credit system, security
- [`docs/SPEC.md`](docs/SPEC.md) — License server specification
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — Development roadmap
- [`AGENTS.md`](AGENTS.md) — AI agent context (for LLM-assisted development)

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT — see [`LICENSE`](LICENSE).

## Disclaimer

RevScan measures AI reverse-engineering resistance using cost models and live AI measurements. It does **not** guarantee protection against all attacks. The crack simulation is for defensive testing only — use it to find and fix weaknesses in your own software.
