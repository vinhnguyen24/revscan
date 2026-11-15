"""Report rendering (human + JSON)."""

from __future__ import annotations

import json
import math

from .estimate import MODELS, Estimate, human_duration
from .evidence import Evidence


def _ease(seconds: float) -> float:
    """0 = an hour or more, 1 = under 5 seconds."""
    lo, hi = 5.0, 3600.0
    value = math.log10(max(seconds, lo) / lo) / math.log10(hi / lo)
    return max(0.0, min(1.0, 1.0 - value))


def risk_score(seconds: float, p_success: float) -> int:
    """Single 0-100 number: 100 = an AI agent will almost certainly crack it fast.

    Weighted by success probability, so a fast-but-unlikely crack is not scored
    as a disaster.
    """
    return max(0, min(100, round(100 * p_success * _ease(seconds))))


def resistance(seconds: float) -> int:
    """Kept for CI/back-compat: 100 = hardest. Prefer risk_score()."""
    return max(0, min(100, round(100 * (1 - _ease(seconds)))))


def to_dict(ev: Evidence, est: Estimate) -> dict:
    risk = risk_score(est.best, est.p_success)
    # Only the model bands belong here. `measured` is a different quantity (one
    # round, no tool time) and used to crash this lookup with KeyError('measured').
    bands = {k: {"label": MODELS[k]["label"], "seconds": v} for k, v in est.seconds.items() if k in MODELS}
    out = {
        "file": ev.path,
        "sha256": ev.sha256,
        "size": ev.size,
        "kind": ev.kind,
        "evidence": ev.stats,
        "crack_seconds": bands,
        "crack_seconds_best": est.best,
        "crack_seconds_worst": est.worst,
        "p_success": est.p_success,
        "risk": risk,
        "resistance": 100 - risk,
        "confidence": est.confidence,
        "rounds": est.rounds,
        "read_budget_tokens": est.budget_tokens,
        "tool_seconds": est.tool_seconds,
        "calibration": {"k": est.calibration_k, "model": est.calibration_model}
        if est.calibration_k != 1.0
        else None,
        "model_notes": est.breakdown,
        "findings": sorted(ev.findings, key=lambda f: f["weight"], reverse=True),
        "markers": ev.markers,
        "note": "crack_seconds is a cost-model estimate; run with --ai to measure against a live model",
    }
    if est.measured:
        out["measured"] = est.measured
    return out


def render(ev: Evidence, est: Estimate) -> str:
    lines: list[str] = []
    w = 72
    lines.append(f"TrapKey scan — {ev.path}")
    lines.append(f"{ev.kind} · {ev.size:,} bytes · sha256 {ev.sha256[:16]}…")
    lines.append("─" * w)
    risk = risk_score(est.best, est.p_success)
    verdict = "likely" if est.p_success >= 0.8 else ("possible" if est.p_success >= 0.5 else "unlikely")
    lines.append(
        f"→ AI cracks this in ~{human_duration(est.best)} ({verdict}, p={est.p_success}) · risk {risk}/100"
    )
    lines.append("")

    lines.append("AI crack time (estimated)")
    for key, m in MODELS.items():
        lines.append(f"  {m['label']:<26} ~{human_duration(est.seconds[key])}")
    if est.calibration_k != 1.0:
        scope = f" ({est.calibration_model})" if est.calibration_model else ""
        lines.append(f"  {'calibrated':<26} k={est.calibration_k:g}{scope}")
    if est.measured:
        m = est.measured
        lines.append(
            f"  {'measured (1 round)':<26} {human_duration(m['seconds'])} · "
            f"{m['model']} · success={m['success']}"
            f" · code {m.get('code_chars', 0):,} chars"
        )
        lines.append(
            "  measured is one model round without tool time; it is calibration"
            " input, not the full estimate"
        )
    lines.append(f"  {'P(success)':<26} {est.p_success}")
    lines.append(f"  {'risk':<26} {risk_score(est.best, est.p_success)}/100 (100 = cracked in seconds)")
    lines.append("")

    lines.append("What the agent actually reads")
    for note in est.breakdown:
        lines.append(f"  · {note}")
    lines.append("")

    leaks = [f for f in ev.findings if f["weight"] > 0]
    guards = [f for f in ev.findings if f["weight"] <= 0]

    if leaks:
        lines.append("Leaks (worst first)")
        for f in sorted(leaks, key=lambda x: -x["weight"]):
            lines.append(f"  -{f['weight']:<3} {f['id']:<18} {f['detail']}")
            lines.append(f"        fix: {f['fix']}")
        lines.append("")

    if guards:
        lines.append("Protection already in place")
        for f in sorted(guards, key=lambda x: x["weight"]):
            lines.append(f"  +{-f['weight']:<3} {f['id']:<18} {f['detail']}")
        lines.append("")

    if leaks:
        lines.append("Do this first")
        seen = set()
        n = 0
        for f in sorted(leaks, key=lambda x: -x["weight"]):
            if f["fix"] in seen:
                continue
            seen.add(f["fix"])
            n += 1
            lines.append(f"  {n}. {f['fix']}")
            if n == 3:
                break
        lines.append("")

    lines.append("This is a cost model, not a measurement. Calibrate with: calibrate.py --ai <dir>")
    lines.append("Expect ±2x until you have calibrated on your own binaries (docs/CALIBRATION.md).")
    return "\n".join(lines)


def render_json(ev: Evidence, est: Estimate) -> str:
    return json.dumps(to_dict(ev, est), indent=2, ensure_ascii=False)
