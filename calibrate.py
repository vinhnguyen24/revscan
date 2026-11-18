#!/usr/bin/env python3
"""Calibrate the cost model against real measurements.

    # 1. batch report, no network, no cost
    python3 calibrate.py /path/to/binaries --limit 20

    # 2. measure each file with a real model (costs tokens)
    TRAPKEY_AI_PROVIDER=ollama TRAPKEY_AI_MODEL=qwen2.5-coder:7b \
        python3 calibrate.py /path/to/binaries --ai --limit 10

    # 3. re-run the model with the fitted multiplier
    TRAPKEY_CALIBRATION_K=1.7 python3 scan.py App.exe

Exit codes: 0 ok · 2 bad input · 3 no usable measurements.
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner import collect, estimate, human_duration
from scanner.ai import AIConfigError, measure, resolve_config
from scanner.estimate import MODELS, OUTPUT_TOKENS_PER_ROUND
from scanner.peinfo import PEError

EXTS = {".exe", ".dll", ".bin", ".sys"}


def model_key_for(cfg: dict | None) -> str:
    """Which model band the measurement belongs to.

    `measure()` runs one round with the configured model. Ollama is the local
    band; a hosted API is the fast band. Fitting against `est.best` (always
    cloud-fast) while measuring with a 7B local model made k meaningless.
    """
    return "local-20b" if (cfg or {}).get("local") else "cloud-fast"



def collect_files(paths: list[str], limit: int) -> list[Path]:
    out: list[Path] = []
    for pattern in paths:
        p = Path(pattern)
        if p.is_dir():
            def rank(f: Path):
                # real apps first, then small files (fast to measure), skip < 20KB noise
                prio = 0 if f.suffix.lower() in (".exe", ".dll") else 1
                return (prio, f.stat().st_size)

            candidates = sorted(
                (
                    f
                    for f in p.rglob("*")
                    if f.is_file() and f.suffix.lower() in EXTS and f.stat().st_size >= 20_000
                ),
                key=rank,
            )
        elif any(ch in pattern for ch in "*?["):
            candidates = sorted(Path(x) for x in glob.glob(pattern))
        else:
            candidates = [p]
        for c in candidates:
            if c.is_file() and c.suffix.lower() in EXTS:
                out.append(c)
            if len(out) >= limit:
                return out
    return out[:limit]


def summarize_attempts(results: list[dict]) -> dict:
    """Median over repeats, discarding errored calls.

    The first model call in a batch is usually slower (connection setup / cold
    model), which showed up as a 3x outlier and blew up `spread`. Median over 3
    repeats removes it without needing a special warm-up path.
    """
    answered = [r for r in results if not r.get("error")]
    if not answered:
        return {"error": results[0].get("error", "no attempts") if results else "no attempts"}
    successes = [r for r in answered if r.get("success")]
    timing = successes if successes else answered
    usage = answered[-1].get("usage") or {}
    return {
        "seconds": round(statistics.median([r["seconds"] for r in timing]), 2),
        "success": bool(successes),
        "successes": len(successes),
        "attempts": len(answered),
        "model": answered[-1]["model"],
        "usage": usage,
        # Actual workload of the call, so k can be a pure speed factor.
        "input_tokens": usage.get("prompt_tokens") or usage.get("input_tokens") or 0,
        "output_tokens": usage.get("completion_tokens") or usage.get("output_tokens") or 0,
        "input_chars": answered[-1].get("input_chars") or 0,
        "code_chars": answered[-1].get("code_chars") or 0,
    }


def fit_multiplier(rows: list[dict]) -> dict:
    """One number: how much faster/slower the endpoint is than the model rates.

    seconds_model = tool + variable
    seconds_real  = tool + k * variable

    The call's actual workload is `prompt_tokens/prefill + completion_tokens/decode`
    (see `workload_seconds`). k is measured/workload, so it is a pure speed
    factor: the cost model keeps its own workload assumptions (read budget,
    rounds, 1200 output tokens per round).
    """
    ratios = []
    for row in rows:
        if not row.get("measured") or not row.get("success"):
            continue
        model_s = row["model_seconds"]
        tool = row["tool_seconds"]
        workload = row.get("workload_seconds")
        if workload is None:
            workload = max(model_s - tool, 0.1)
        variable = max(workload, 0.1)
        measured_variable = max(row["measured"], 0.1)
        ratio = measured_variable / variable
        if math.isfinite(ratio) and ratio > 0:
            ratios.append(ratio)

    if not ratios:
        return {"k": None, "n": 0, "spread": None}

    log_mean = math.exp(sum(math.log(r) for r in ratios) / len(ratios))
    ordered = sorted(ratios)
    median = ordered[len(ordered) // 2]
    return {
        "k": round(log_mean, 4),
        "median": round(median, 4),
        "n": len(ratios),
        "min": round(ordered[0], 4),
        "max": round(ordered[-1], 4),
        # max/min is >= 1 by construction; the old 0.001 floor could report
        # "spread 0.54x" for a single very fast measurement.
        "spread": round(max(1.0, ordered[-1] / max(ordered[0], 1e-9)), 2),
    }


def render(rows: list[dict], fit: dict, provider: str | None, model_key: str | None = None) -> str:
    lines = []
    header = f"{'file':<34}{'kind':<9}{'model':>9}{'measured':>11}{'ratio':>8}  p"
    lines.append(header)
    lines.append("-" * len(header))
    for row in rows:
        name = row["name"][:33]
        model_s = human_duration(row["model_seconds"])
        measured = human_duration(row["measured"]) if row.get("measured") else "—"
        # A failed measurement has a duration (time to give up) but no crack
        # time, so a ratio would be misleading.
        ratio = (
            f"{row['measured'] / row['model_seconds']:.2f}x"
            if row.get("measured") and row.get("success")
            else "—"
        )
        flag = " (no crack found)" if row.get("measured") and row.get("success") is False else ""
        lines.append(
            f"{name:<34}{row['kind']:<9}{model_s:>9}{measured:>11}{ratio:>8}  "
            f"{row['p_success']}{flag}"
        )
    lines.append("")
    if fit["k"] is None:
        lines.append("No measurements. Re-run with --ai and a configured model.")
    else:
        band = f" for {model_key}" if model_key else ""
        lines.append(f"fitted multiplier k = {fit['k']}  (n={fit['n']}, median={fit['median']}, "
                     f"range {fit['min']}–{fit['max']}, spread {fit['spread']}x){band}")
        if fit["spread"] > 3:
            lines.append("spread > 3x: the model is missing a signal (packing? obfuscation?). "
                         "Fix the signal before trusting k.")
        lines.append("")
        lines.append("Apply it:")
        lines.append(
            f"    TRAPKEY_CALIBRATION_K={fit['k']}"
            + (f" TRAPKEY_CALIBRATION_MODEL={model_key}" if model_key else "")
            + " python3 scan.py App.exe"
        )
        lines.append("")
        lines.append("Then paste the number into docs/CALIBRATION.md with the model name and date.")
    if provider:
        lines.append(f"provider: {provider}")
    lines.append("")
    lines.append(f"files: {len(rows)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="directories, globs or files")
    ap.add_argument("--ai", action="store_true", help="measure each file with a real model")
    ap.add_argument("--repeat", type=int, default=1,
                    help="measure each file N times and use the median (recommended 3)")
    ap.add_argument("--limit", type=int, default=25)
    ap.add_argument("--pause", type=float, default=0.0,
                    help="sleep N seconds between model calls (Gemini free tier: 13)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="write the full result as JSON")
    a = ap.parse_args(argv)

    # Never let a previously fitted k leak into the fit: it would scale
    # `model_seconds` and make the report look calibrated twice.
    os.environ.pop("TRAPKEY_CALIBRATION_K", None)
    os.environ.pop("TRAPKEY_CALIBRATION_MODEL", None)

    files = collect_files(a.paths, a.limit)
    if not files:
        print("error: no .exe/.dll files found", file=sys.stderr)
        return 2

    provider = None
    model_key = None
    if a.ai:
        try:
            cfg = resolve_config()
            provider = f"{cfg['provider']}:{cfg['model']}" + (" (local)" if cfg["local"] else "")
            model_key = model_key_for(cfg)
        except AIConfigError as err:
            print(f"error: {err}", file=sys.stderr)
            return 2

    rows: list[dict] = []
    calls_made = 0
    for file in files:
        try:
            ev = collect(str(file))
        except (PEError, OSError) as err:
            print(f"skip {file.name}: {err}", file=sys.stderr)
            continue

        est = estimate(ev)
        key = model_key or "cloud-fast"
        model = MODELS[key]
        fallback_workload = est.budget_tokens / model["prefill"] + OUTPUT_TOKENS_PER_ROUND / model["decode"]
        row = {
            "file": str(file),
            "name": file.name,
            "kind": ev.kind,
            "size": ev.size,
            # The measurement uses one model; fit against the band that model
            # belongs to, not always `est.best` (cloud-fast).
            "model_key": key,
            "model_seconds": est.seconds[key],
            # Overwritten with the call's real token workload after measuring.
            "workload_seconds": round(fallback_workload, 3),
            "tool_seconds": est.tool_seconds,
            "p_success": est.p_success,
            "markers": ev.markers,
            "findings": len([f for f in ev.findings if f["weight"] > 0]),
            "measured": None,
            "success": None,
        }

        if a.ai:
            results = []
            for _ in range(max(1, a.repeat)):
                # Free tiers are per-minute; pacing here is cheaper than watching
                # half the corpus get skipped with 429.
                if a.pause and calls_made:
                    time.sleep(a.pause)
                calls_made += 1
                result = measure(ev)
                if result.get("error_code") == "AI_QUOTA" and result.get("retry_after"):
                    # One polite retry after the provider's own reset window.
                    time.sleep(min(int(result["retry_after"]), 60))
                    result = measure(ev)
                results.append(result)
            summary = summarize_attempts(results)
            if summary.get("error"):
                print(f"skip {file.name}: {summary['error']}", file=sys.stderr)
            else:
                row["measured"] = summary["seconds"]
                row["success"] = summary["success"]
                row["successes"] = summary["successes"]
                row["attempts"] = summary["attempts"]
                row["model_used"] = summary["model"]
                row["usage"] = summary["usage"]
                row["code_chars"] = summary.get("code_chars", 0)
                prompt = summary.get("input_tokens") or 0
                completion = summary.get("output_tokens") or 0
                if prompt:
                    workload = prompt / model["prefill"] + max(completion, 1) / model["decode"]
                elif summary.get("input_chars"):
                    workload = (
                        summary["input_chars"] / 4 / model["prefill"]
                        + OUTPUT_TOKENS_PER_ROUND / model["decode"]
                    )
                else:
                    workload = fallback_workload
                row["workload_seconds"] = round(workload, 3)
        rows.append(row)

    fit = fit_multiplier(rows)
    payload = {"provider": provider, "model_key": model_key, "fit": fit, "rows": rows}

    if a.out:
        Path(a.out).write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        print(f"wrote {a.out}", file=sys.stderr)

    if a.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(render(rows, fit, provider, model_key))

    if a.ai and fit["k"] is None:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
