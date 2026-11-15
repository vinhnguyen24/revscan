"""REA cost model: turn evidence into "how long until an AI agent cracks it".

This is a model, not a measurement. The constants are documented and every
intermediate value is printed in the report, so a technical buyer can audit it.
`scan.py --ai` replaces the model with a real measurement against a live model.

The shape of the model follows how REA-style agents actually work:

    strings -> pick candidates -> decompile those -> read -> emit a patch/keygen

Reading is cheap (prefill), emitting a working crack is the bottleneck (decode),
so wall time is dominated by decode tokens x agent rounds, not by binary size.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .evidence import Evidence

# --- constants (see docs/CALIBRATION.md for where they come from) -----------
TOOL_STRINGS_S = 0.4
TOOL_DOTNET_DUMP_S = 2.0
TOOL_GHIDRA_S = 22.0

CHARS_PER_TOKEN = 4.0
OUTPUT_TOKENS_PER_ROUND = 1200

# An agent will read at most ~1.6 MB of decompiled source even when there is no
# pointer at all. Without this cap the "nothing found" branch grew linearly with
# the binary and contradicted the 200k sift cap used everywhere else.
MAX_FALLBACK_BUDGET_TOKENS = 400_000

MODELS = {
    "cloud-fast": {"label": "Claude/GPT class (API)", "prefill": 8000, "decode": 95},
    "cloud-cheap": {"label": "cheap API model", "prefill": 4000, "decode": 60},
    "local-20b": {"label": "local 20B (Ollama)", "prefill": 1500, "decode": 28},
}


@dataclass
class Estimate:
    seconds: dict[str, float]
    p_success: float
    rounds: float
    budget_tokens: int
    tool_seconds: float
    breakdown: list[str] = field(default_factory=list)
    confidence: str = "model"
    # Populated by `scan.py --ai`: one real round against a live model. Kept out
    # of `seconds` on purpose — it is measured differently from the model bands
    # (no tool time, one round) and must never be mistaken for the estimate.
    measured: dict | None = None
    calibration_k: float = 1.0
    calibration_model: str | None = None

    @property
    def best(self) -> float:
        return min(self.seconds.values())

    @property
    def worst(self) -> float:
        return max(self.seconds.values())


def calibration_k() -> tuple[float, str | None]:
    """Read the fitted multiplier. Bad input must not produce bad reports.

    A negative or NaN `k` turned into negative/NaN seconds, which then produced
    invalid JSON (`NaN`) for the web client.
    """
    raw = os.environ.get("TRAPKEY_CALIBRATION_K", "1") or "1"
    try:
        k = float(raw)
    except ValueError:
        k = 1.0
    if not (k == k) or k in (float("inf"), float("-inf")):  # NaN / inf
        k = 1.0
    k = max(0.0, k)
    model = os.environ.get("TRAPKEY_CALIBRATION_MODEL") or None
    if model and model not in MODELS:
        model = None
    return k, model


def estimate(ev: Evidence) -> Estimate:
    strings_tokens = min(60_000, ev.stats.get("strings_chars", 0) / CHARS_PER_TOKEN)
    code_bytes = ev.pe.code_bytes if ev.pe else max(ev.size // 3, 1024)
    code_tokens = code_bytes / CHARS_PER_TOKEN
    size_mb = max(ev.size, 1) / 1_000_000
    breakdown: list[str] = []

    # Bigger binaries are slower to load into a decompiler (sub-linear: Ghidra's
    # import time grows slower than the file).
    tool_scale = max(1.0, size_mb ** 0.25)

    # Even with a good pointer (a name, a string), a huge code base means more
    # candidates to sift. Cap it: an agent will not read 10 MB of decompiled C.
    sift_tokens = min(200_000, int(code_tokens * 0.03))

    named = ev.named_license_functions
    has_license_strings = ev.stats.get("license_strings", 0) > 0
    has_crypto_hint = bool(ev.crypto_imports)

    if named:
        il = sum(x["il_bytes"] for x in named) or len(named) * 900
        budget = 12_000 + min(strings_tokens, 30_000) * 0.5 + il / CHARS_PER_TOKEN + sift_tokens * 0.3
        rounds = 1.8
        p = 0.92
        if ev.kind == "dotnet":
            tool = TOOL_DOTNET_DUMP_S * max(1.0, size_mb ** 0.15)
            tool_name = ".NET metadata dump"
        else:
            # Named *exports* of a native PE still need a decompiler; using the
            # 2s metadata-dump constant here understated the cost by ~20s.
            tool = TOOL_GHIDRA_S * tool_scale
            tool_name = "Ghidra headless import"
        breakdown.append(f"named licence functions ({len(named)}): agent greps the name table, no search needed")
    elif has_license_strings:
        budget = min(strings_tokens, 30_000) + 40_000 + sift_tokens
        rounds = 2.6
        p = 0.85
        tool = TOOL_GHIDRA_S * tool_scale if ev.kind == "native" else TOOL_DOTNET_DUMP_S * max(1.0, size_mb ** 0.15)
        tool_name = "Ghidra headless import"
        breakdown.append("licence strings visible but functions unnamed: agent must resolve xrefs")
    elif has_crypto_hint:
        budget = min(strings_tokens, 30_000) + 90_000 + sift_tokens
        rounds = 3.2
        p = 0.70
        tool = TOOL_GHIDRA_S * tool_scale if ev.kind == "native" else TOOL_DOTNET_DUMP_S * max(1.0, size_mb ** 0.15)
        tool_name = "Ghidra headless import"
        breakdown.append("no licence strings, but crypto imports mark the verification code")
    else:
        budget = max(60_000, min(MAX_FALLBACK_BUDGET_TOKENS, code_tokens * 0.25))
        rounds = 3.4
        # Reaching this branch means named/strings/crypto are all absent, so
        # there is no "else" case: the old ternary was dead code.
        p = 0.35
        tool = TOOL_GHIDRA_S * tool_scale if ev.kind == "native" else TOOL_DOTNET_DUMP_S * max(1.0, size_mb ** 0.15)
        tool_name = "Ghidra headless import"
        breakdown.append("no licence strings and no crypto imports: agent must read a large part of the code")
        breakdown.append(
            "no licence check found at all: either the app has none, or it is well hidden"
        )

    if tool_scale > 1.05 and tool_name == "Ghidra headless import":
        breakdown.append(f"tool time scaled x{tool_scale:.1f} for a {size_mb:.0f} MB binary")

    # Electron first: the asar is plain source, but packing/traps/obfuscation
    # still apply. This block used to run last and overwrite `p` with 0.97,
    # erasing every protection penalty (a protected Electron app scored as easy).
    if ev.kind == "electron":
        budget *= 0.4
        rounds = 1.2
        p = 0.97
        breakdown.append("Electron: app.asar extracts to readable source, the crack is trivial")

    if ev.packed:
        budget *= 4
        rounds += 1.2
        p -= 0.35
        tool += 60.0
        breakdown.append("packed: +60s just to unpack before any reading starts")
    if ev.obfuscated_names:
        budget *= 1.8
        rounds += 0.6
        p -= 0.15
        breakdown.append("obfuscated identifiers: no grep shortcut")
    if ev.has_traps:
        rounds += 0.8
        p -= 0.30
        breakdown.append("AI deception payloads: the agent must notice it is being lied to")
    if ev.kind == "dotnet" and not ev.obfuscated_names:
        p = min(0.99, p + 0.05)

    budget = int(budget)
    p = max(0.02, min(0.99, p))

    # Calibration: a single multiplier on the variable part, fitted by
    # `calibrate.py --ai` against real measurements. Tool time is measured, so
    # it is not scaled. `TRAPKEY_CALIBRATION_MODEL` limits the multiplier to the
    # model class that was actually measured; without it the old behaviour
    # (scale every band) is kept.
    k, k_model = calibration_k()

    seconds: dict[str, float] = {}
    for key, m in MODELS.items():
        read_s = budget / m["prefill"]
        gen_s = rounds * OUTPUT_TOKENS_PER_ROUND / m["decode"]
        factor = k if (k_model is None or key == k_model) else 1.0
        seconds[key] = round(tool + factor * (read_s + gen_s), 1)

    breakdown.append(
        f"read budget {budget:,} tokens / agent rounds {rounds:.1f} / "
        f"tool time {tool:.0f}s (tool time is excluded from the model speeds)"
    )
    if k != 1.0:
        scope = f" for {k_model}" if k_model else " for every model band"
        breakdown.append(f"calibration multiplier k={k:g} applied to the variable part{scope}")

    return Estimate(
        seconds=seconds,
        p_success=round(p, 2),
        rounds=round(rounds, 1),
        budget_tokens=budget,
        tool_seconds=tool,
        breakdown=breakdown,
        calibration_k=k,
        calibration_model=k_model,
    )


def human_duration(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f} phút"
    return f"{seconds / 3600:.1f} giờ"
