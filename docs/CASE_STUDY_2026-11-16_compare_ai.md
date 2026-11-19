# Case study — `compare --ai` on a real licensing DLL (2026-11-16)

Goal: check whether `protect --level 3` actually makes the AI agent slower, not
just whether the static cost model says so. This is the first before/after run
where both copies were measured by the same live model.

## Setup

- File: `Cryptlex.LexActivator.dll` (60,712 bytes, .NET licensing library)
- Protect: `--level 3` → overlay + PDB strip + encrypted TK2 payload (+4,831 bytes)
- Model: `gpt-6-luna` via OpenCode Go, `--ai --repeat 3` (median of 3 rounds/file)
- Command:

```bash
python3 cli/revscan.py protect Cryptlex.LexActivator.dll --level 3
python3 cli/revscan.py compare Cryptlex.LexActivator.dll Cryptlex.protected.dll \
  --ai --repeat 3 --json
```

## Static cost model

| | Original | Protected | Delta |
|---|---:|---:|---:|
| Crack best | ~33 s | ~46 s | **+12.8 s** |
| Crack worst | ~89 s | ~2.1 min | +34.4 s |
| P(success) | 0.97 | 0.67 | -0.30 |
| Risk | 69/100 | 44/100 | -25 |
| Finding | `pdb-path` 15 | removed | fixed |

Verdict: **better** — this is what `protect` alone shows.

## Live measurement (same model, same pack)

| | Original | Protected |
|---|---:|---:|
| Median of 3 rounds | 9.69 s | 8.50 s |
| Found the check | yes | yes |
| Delta | | **-1.19 s** |

`compare --ai` therefore says:

> measured: no meaningful change; the static improvement is not confirmed
> live measurement does not confirm the static improvement

The -1.19 s delta is inside the noise band (`max(2 s, 15%)`), so the tool
refuses to call it faster. Reporting it as "faster" from 3 rounds would have
been an overclaim.

## What this means

- PDB strip removes a real leak (`pdb-path`), and the static model rewards it.
- The data-only TK2 payload did **not** slow the live agent on this DLL. The
  model still found the licence check at the same speed (within noise).
- So `protect` v1/v2 (data-only) is not enough for the core promise; the next
  protect step must change what the agent has to read (runtime reference / code
  path), not just add data.
- This is exactly why `compare` now keeps the cost-model delta and the measured
  delta in separate fields: mixing them would overstate the product.

## Caveats

- One binary, one model, 3 rounds. Not a general claim.
- A one-round measurement excludes tool time and is noisy; `--repeat 3` reduces
  but does not remove that noise.
- Re-run on your own binary before quoting a number to a customer.
