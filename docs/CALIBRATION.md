# Calibration — what the "AI cracks it in X seconds" number means

The scan answers one question:

> **How long would an REA-style AI agent take to produce a working keygen or patch
> for this binary, starting from nothing?**

It is a **cost model**, not a measurement. Each step is printed in the report so a
technical buyer can audit it, and `--ai` replaces the model with a real measurement.

---

## 1. The model

REA-style agents work in this order:

```
strings  ->  pick candidates  ->  decompile candidates  ->  read  ->  emit patch
```

Reading is cheap (prefill); **emitting a working crack is the bottleneck** (decode).
So wall time is driven by decode tokens × number of agent rounds, not by file size.

```
seconds(model) = tool_seconds
               + read_budget_tokens / model.prefill_rate
               + rounds * OUTPUT_TOKENS_PER_ROUND / model.decode_rate
```

| Constant | Value | Where it comes from |
|---|---|---|
| `TOOL_STRINGS_S` | 0.4 s | `strings` + PE parse, measured |
| `TOOL_DOTNET_DUMP_S` | 2.0 s | ILSpy/`monodis` on a 5 MB assembly, measured |
| `TOOL_GHIDRA_S` | 22 s | Ghidra 12 headless, small native binary, measured |
| `CHARS_PER_TOKEN` | 4.0 | standard English/code approximation |
| `OUTPUT_TOKENS_PER_ROUND` | 1200 | a patch + explanation, observed in REA runs |
| `prefill_rate` (cloud-fast) | 8000 tok/s | API prefill throughput |
| `decode_rate` (cloud-fast) | 95 tok/s | API decode throughput |
| `prefill/decode` (local 20B) | 1500 / 28 | Ollama on a laptop GPU/CPU mix |
| rounds | 1.8 – 4.6 | how many agent iterations are needed to find + confirm + patch |

## 2. Read budget

This is the part that makes the estimate binary-specific instead of a guess:

| Situation | Read budget |
|---|---|
| Licence functions are **named** (`CheckLicense`, `ActivateTrial`) | named IL + 12k, 1.8 rounds |
| Licence **strings** visible, functions unnamed | strings + 40k, 2.6 rounds |
| No licence strings, but **crypto imports** mark the code | strings + 90k, 3.2 rounds |
| Nothing at all | 25% of the code, 3.4 rounds |

Modifiers: packed ×4 budget (+60 s tool time), obfuscated identifiers ×1.8,
AI-deception traps +0.8 rounds and −0.30 success probability, Electron → near-zero
budget (the asar is plain source).

## 3. Success probability

Not every attempt succeeds. `p_success` starts at 0.35–0.92 depending on the path
above (0.35 = no licence check found at all, 0.92 = named licence functions), then:

```
packed        -0.35
obfuscated    -0.15
traps         -0.30
readable .NET +0.05
```

Reported as a probability, never hidden. A slow-but-unlikely crack is not a disaster
and the risk score reflects that.

## 4. Risk score

```
risk = 100 * p_success * ease(seconds)
ease = 1 - log10(max(seconds,5)/5) / log10(3600/5)
```

100 = an agent will almost certainly crack it in seconds. 0 = an hour or more, or
very unlikely.

---

## 5. Reference points measured in this repo

| Binary | Kind | Estimated (cloud-fast) | p_success | Notes |
|---|---|---|---|---|
| `notepad.exe` (no licence logic) | native | ~72 s | 0.35 | nothing points at a licence check; "unlikely" is the honest answer |
| `notepad.exe` + injected licence strings | native | ~61 s | 0.85 | strings narrow the search; Ghidra import dominates |
| same, `revscan protect --level 3` (v2: strip + chunked payload) | native | ~71 s | 0.55 | traps add a round and cut success by 0.30; PDB gone |
| `mscorlib.dll` (27.492 methods) | .NET | ~48 s | 0.90 | metadata dump gives the whole name table |
| `WindowsCodecsRaw.dll` (32 MB) | native | ~1.8 min | 0.70 | tool-time scaling with binary size |
| `amd_comgr_2.dll` (110 MB) | native | ~2.5 min | 0.70 | sift budget grows sub-linearly, capped at 200k tokens |

The protected row is the sanity check that matters: protection must move **both**
time and success probability, in the right direction.

---

## 6. How to calibrate (do this before selling)

```bash
# batch report, free, no model calls
python3 calibrate.py /path/to/binaries --limit 20

# measure for real (costs tokens); --repeat 3 takes the median
TRAPKEY_AI_PROVIDER=ollama TRAPKEY_AI_MODEL=qwen2.5-coder:7b \
    python3 calibrate.py /path/to/binaries --ai --limit 10 --repeat 3 --out calib.json

# Ollama Cloud: key only, no local install (base is set automatically)
OLLAMA_API_KEY=... TRAPKEY_AI_MODEL=gpt-oss:120b \
    python3 calibrate.py /path/to/binaries --ai --limit 10 --repeat 3 --out calib.json

# any OpenAI-compatible gateway
OPENAI_BASE_URL=https://gateway.example/v1 OPENAI_API_KEY=... \
    TRAPKEY_AI_MODEL=... python3 calibrate.py /path/to/binaries --ai --limit 10 --repeat 3

# use the fitted number
TRAPKEY_CALIBRATION_K=0.2758 TRAPKEY_CALIBRATION_MODEL=cloud-fast python3 scan.py App.exe
```

`--repeat` (3–5) matters: the first model call in a batch is cold (connection
setup / model load) and was a 3x outlier in run 1. The median removes it.

The script fits **one** multiplier on the variable part of the model, for the
model band that was actually measured:

```
model:        seconds = tool + variable
calibrated:   seconds = tool + k * variable
measured:     one model call (no tool time)
workload:     prompt_tokens / prefill + completion_tokens / decode
=> k = measured / workload
```

`k` is a **pure speed factor**: the same token workload predicted by the model
rates vs what the endpoint actually took. The cost model keeps its own workload
assumptions (read budget, rounds, 1200 output tokens per round). Comparing
`measured` against a workload that assumed 1200 output tokens (when the model
actually emitted ~250) mixed workload with speed and made `k` ~3x too low.

Tool time is measured, so it is never scaled. `--ai` measures with one model, so
`k` is fitted against that band (`cloud-fast` for a hosted API, `local-20b` for
Ollama) and `TRAPKEY_CALIBRATION_MODEL` restricts where it is applied. Fitting
against `est.best` while measuring a 7B model is what made earlier k values
meaningless.

The fit is a geometric mean over successful measurements (`--ai` runs where the
model did not find the check are excluded — a failed crack has no crack time).

One caveat worth saying out loud: `--ai` is **one round** (one prompt, one
answer), not the multi-round agent loop the model describes. It measures how
long the model takes to *point at* the check, so treat `k` as a correction for
model speed, not as a full end-to-end benchmark.

Read the output:

| Signal | Meaning |
|---|---|
| `k` ≈ 1.0 | model is already right |
| `k` = 2.0 | reality is ~2x slower than the model says |
| `spread` > 3x | one signal is missing (packing, obfuscation, or a name false positive); fix the signal before trusting `k` |

Record in this file: date, model, k, n, spread, and the band (`model_key`).
The script prints the exact env line, e.g.:

```bash
TRAPKEY_CALIBRATION_K=1.7 TRAPKEY_CALIBRATION_MODEL=cloud-fast python3 scan.py App.exe
```

```bash
# OpenAI
OPENAI_API_KEY=... TRAPKEY_AI_MODEL=gpt-4o-mini python3 scan.py App.exe --ai

# bất kỳ endpoint OpenAI-compatible nào (DeepSeek, Groq, vLLM, LM Studio...)
OPENAI_BASE_URL=https://api.deepseek.com/v1 OPENAI_API_KEY=sk-... \
  TRAPKEY_AI_MODEL=deepseek-chat python3 scan.py App.exe --ai

# Ollama local, không cần key
TRAPKEY_AI_PROVIDER=ollama TRAPKEY_AI_MODEL=qwen2.5-coder:7b python3 scan.py App.exe --ai
```

Model local cho số **khác** (thường chậm hơn) — đó chính là điều bạn muốn đo:
một app có thể bị GPT-class bẻ trong 40s nhưng chống được model 7B. Ghi lại
model nào dùng cho lần calibrate.

Until you have done that, treat the number as **±2x**.

---

## 7. Known weaknesses (say these out loud)

- **Name heuristics can be wrong.** We split identifiers into words and require a
  strong licence word (or two weak ones), but `SerialPort.Open` in a hardware tool
  will still inflate the "named licence" path. The evidence list is printed so the
  user can see why.
- **Packed binaries** are penalised with a flat +60 s and ×4 budget. Real unpacking
  time varies from seconds to hours.
- **IL size** is derived from RVA distances, capped at 64 KB per method. Correct in
  practice, but a hand-crafted assembly could fool it.
- **A determined agent can defeat traps** once it notices them. The model gives a
  one-round penalty; reality ranges from "ignores it" to "walks around it".
- **The number is not a promise.** No scan can guarantee a binary will not be
  cracked. It estimates the cost of trying.

---

## 8. Calibration — current number (2026-11-14)

Gateway `aiproviders.s3corp.com.vn/v1`, model `ollama/gpt-oss:120b`, `--repeat 5`
(median), 10 binaries.

| Field | Value |
|---|---|
| Date | 2026-11-14 |
| Provider | `openai` (OpenAI-compatible gateway) |
| Model | `ollama/gpt-oss:120b` |
| Band | `cloud-fast` |
| `k` | **0.2758** |
| Median | 0.2892 |
| Range | 0.1933 – 0.3623 |
| `n` | 10 |
| Spread | **1.87x** (< 3x, usable) |
| Repeats | 5 (median of 5 calls per file) |

Raw artefacts: `docs/calibration/2026-11-14-gptoss.json` (this run) and
`docs/calibration/2026-11-14-nemotron.json` (frontier comparison).

`k` is `measured / workload`, where the workload is computed from the **actual**
tokens of that call:

```
workload = prompt_tokens / prefill + completion_tokens / decode
k        = measured_seconds / workload
```

That makes `k` a pure speed factor: this gateway is ~3.6x faster than the model's
default `8000 tok/s` prefill and `95 tok/s` decode. The cost model keeps its own
workload assumptions (read budget, rounds, 1200 output tokens per round).

| File | Kind | Prompt | Completion | Measured | Workload | k |
|---|---|---:|---:|---:|---:|---:|
| `Cryptlex.LexActivator.dll` | .NET | 11,264 | 430 | 2.15 s | 5.93 s | 0.362 |
| `IntelliLock.LicenseManager.dll` | .NET | 10,581 | 195 | 1.18 s | 3.38 s | 0.350 |
| `LicenseSpring.NetSDK.dll` | .NET | 24,065 | 284 | 1.44 s | 6.00 s | 0.240 |
| `Portable.Licensing.dll` | .NET | 22,988 | 209 | 1.31 s | 5.07 s | 0.258 |
| `SoftActivate.Licensing.dll` | .NET | 11,026 | 263 | 1.30 s | 4.15 s | 0.313 |
| `Syncfusion.Licensing.dll` | .NET | 13,484 | 293 | 1.49 s | 4.77 s | 0.312 |
| `ThinkSharp.Licensing.dll` | .NET | 6,923 | 417 | 1.52 s | 5.26 s | 0.289 |
| `TrialMaker.Licensing.Premium.dll` | .NET | 22,983 | 210 | 1.19 s | 5.08 s | 0.234 |
| `WinRAR.exe` | native | 22,012 | 417 | 1.38 s | 7.14 s | 0.193 |
| `sublime_text.exe` (portable) | native | 22,018 | 366 | 1.67 s | 6.61 s | 0.253 |

Apply it:

```bash
TRAPKEY_CALIBRATION_K=0.2758 TRAPKEY_CALIBRATION_MODEL=cloud-fast python3 scan.py App.exe
```

Effect: `WinRAR.exe` 70 s → **39 s**, `sublime_text.exe` 84 s → **50 s**.

**Honest caveats for this run:**

- 8 of 10 samples are **.NET licensing libraries** from NuGet; the native apps are
  `WinRAR.exe` and Sublime Text (portable). This is a speed calibration, not a
  claim that any of them is easy to crack.
- Only **speed** is calibrated. `p_success`, `rounds` and the 1200 tokens/round
  output assumption still come from the cost model.
- Single calls are noisy (network queue + cold start). Always use `--repeat`.
- The gateway, model, and plan affect `k`. Re-run when either changes; do not copy
  this number to a different model.

### Model comparison (2026-11-14, cập nhật 2026-11-16)

| Model | n | `k` | Spread | Notes |
|---|---:|---:|---:|---|
| `ollama/gpt-oss:120b` | 10 | 0.2758 | 1.87x | run 3, `.env` cũ |
| `ollama/nemotron-3-ultra` | 9 | 1.8928 | 3.27x | frontier; LicenseSpring outlier (47 s) |
| `gemini-3.6-flash` | 3 | 0.9437 | 4.15x | **provisional**; free tier 5 req/phút nên bị skip 1 file, chưa đủ mẫu |

`gemini-3.6-flash` (AI Studio, `TRAPKEY_AI_THINKING_BUDGET=0`) trả lời 2–7 s/lần
trên 3 file thành công (`System.Core.dll`, `System.Security.dll`, `WinRAR.exe`),
`mscorlib.dll`/`System.dll` trả `none`, `notepad.exe` không có license. `k=0.9437`
gần 1.0 về mặt định lượng, nhưng spread 4.15x > 3x nên **đừng dùng để bán** cho tới
khi chạy lại với corpus ≥10 file và `--repeat 5` (free tier cần `--pause 13`).

`.env` hiện dùng `gemini-3.1-flash-lite` (3.6-flash đã cạn quota ngày), nên `k` đang
để trống = 1.0; chỉ bật `k=0.9437` khi quay lại đúng model 3.6-flash.

`gemini-3.8-flash` (2026-11-16) chỉ trả lời được qua `streamGenerateContent`: non-stream
treo >150s, streaming trả "OK" sau 47s, và scan `notepad.exe` mất **276s** với
`TRAPKEY_AI_TIMEOUT=300`. Không dùng làm model mặc định cho demo; giữ để đo chất lượng.

The two differ by ~6.9x. The cost model's `cloud-fast` rates are optimistic for a
cautious frontier model and fast for an efficient open model. For the product's
risk number, use the **fastest successful model** (`gpt-oss`, `k=0.2758`): it
yields the shortest crack time, i.e. the worst case for the vendor. Use the
frontier `k` for a conservative/slow-threat claim.

Why not GPT-5.6 / Kimi / GLM: on native binaries they answered
`FUNCTION: unknown` or "insufficient evidence, no disassembly supplied". The
evidence pack contains strings + metadata, not code, so a model that refuses to
guess cannot produce a usable one-round measurement. `nemotron-3-ultra` and
`gpt-oss:120b` do answer.

### History

- **Run 1 (2026-11-13)**: `n=4`, `k=0.1413`, one call per file, Windows system
  DLLs. First call of the batch was a ~3x cold-start outlier.
- **Run 2 (2026-11-14)**: `n=9`, `k=0.0808`, `--repeat 3`. Compared the call to a
  one-round workload with **1200 output tokens**, but the model actually emitted
  ~250; that mixed workload with speed and made `k` ~3x too low. Superseded.
- **Run 3 (2026-11-14, current)**: `n=10`, `k=0.2758`, spread 1.87x, workload
  normalised by actual `prompt_tokens`/`completion_tokens`.

### After the evidence-pack change (2026-11-14, later)

`build_pack` now includes disassembly (IL for .NET, xref-selected objdump for native),
so the model reads more than strings. Two consequences:

1. **The pack no longer matches what run 3 measured.** Run 3 sent strings + metadata;
   a new run sends code too, which changes both `prompt_tokens` and the model's chance
   of finding the check. Treat `k=0.2758` as the *pre-code* number until re-measured.
2. **The .NET metadata reader was wrong** (`HeapSizes` read at `base+7` instead of
   `base+6`), so `dotnet_methods` / `dotnet_il_bytes` / `license_named_functions` were
   unreliable on assemblies with 4-byte heaps. `estimate()` output for those files has
   changed, so `model_seconds` in the run-3 rows no longer reproduces.

Both point to the same action: re-run `calibrate.py --ai --repeat 5 --limit 10` and
update `.env`, this file, and `AGENTS.md` with the new `k`. The direction is not
predictable — a richer pack can raise `k` (more prefill) while lowering failed
attempts, which removes `(no crack found)` rows from the fit.

### Success is grounded now

`--ai` used to count any non-`unknown` answer as a success. A model that invented
`ValidateKeyName` (not present in the evidence) was scored as a find. `measure()` now
requires the `FUNCTION:` value to be in the pack (name) or inside the image (address),
and the prompt says so. This *lowers* the success rate for cautious models and changes
which rows enter the fit, so `k` from run 3 is not comparable.

Related precision fix: `is_license_ident` counts **distinct** weak words and rejects
names carrying a context word (`name`, `mode`, `value`, `size`, `rights`, ...).
`ValidateKeyName`/`GetBaseKeyFromKeyName` (Win32 registry) no longer inflate the
"named licence functions" branch. `TrialDivisionBounds` still matches (`trial` is
strong); that is a known, accepted false positive.



### Run 4 (2026-11-16) — OpenCode Go / `gpt-6-luna`

Provider: `openai:gpt-6-luna` through `https://opencode.ai/inference/go/openai/v1`,
`--repeat 3`, 11 files, **7 successes**. Pack includes code (IL/objdump); prompt
tokens include Go's implicit cache reads.

| File | Kind | Prompt | Completion | Measured | Workload | k |
|---|---|---:|---:|---:|---:|---:|
| `IntelliLock.Licensing.dll` | .NET | 2,329 | 279 | 7.18 s | 3.23 s | 2.22 |
| `ThinkSharp.Licensing.dll` | .NET | 4,853 | 199 | 3.51 s | 2.70 s | 1.30 |
| `Cryptlex.LexActivator.dll` | .NET | 12,174 | 307 | 7.91 s | 4.75 s | 1.66 |
| `Licensing.Net.dll` | .NET | 10,961 | 841 | 11.63 s | 10.22 s | 1.14 |
| `System.Evaluation.dll` (TrialMaker) | .NET | 21,142 | 228 | 4.94 s | 5.04 s | 0.98 |
| `Portable.Licensing.dll` | .NET | 20,841 | 353 | 6.19 s | 6.32 s | 0.98 |
| `System.Core.dll` | .NET | 19,704 | 320 | 5.83 s | 5.83 s | 1.00 |

**Fit: `k = 1.2673`, n=7, median 1.1376, range 0.9793–2.2243, spread 2.27x.**
Spread < 3x and n≥7, so this is the first number since run 3 usable for reports.
`IntelliLock`/`Syncfusion`/`System.Security`/`WinRAR`/`notepad` returned `none`
in at least one repeat and stay out of the fit; they still calibrate failure rate.

Apply:

```bash
TRAPKEY_CALIBRATION_K=1.2673 TRAPKEY_CALIBRATION_MODEL=cloud-fast python3 scan.py App.exe
```

Effect on `notepad.exe`: best case **72.4 s → 85.9 s**, risk 21 → 20. Worst case
is unchanged because `TRAPKEY_CALIBRATION_MODEL=cloud-fast` scopes the multiplier
to the measured band only.

**DeepSeek V4.1 Flash** on the same corpus with `TRAPKEY_AI_MAX_TOKENS=1200` failed
5/7 licensing DLLs with `returned no content` (reasoning tokens ate the budget).
Its fit was n=2, spread 2.61x, so **do not use** `k=1.0807`. If you switch to
DeepSeek, raise `TRAPKEY_AI_MAX_TOKENS` to 4000 and re-run before trusting it.

**Caveat:** Go's implicit cache makes `prompt_tokens` include cached reads
(e.g. 21,142 prompt / 228 new); workload is normalised the same way as run 3, so
`k` remains a speed factor, not a price. Re-fit when the model or pack changes.
