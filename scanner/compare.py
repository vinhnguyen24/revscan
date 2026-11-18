"""Compare an original binary with a protected copy of it.

This is the "prove protection improved" loop: `protect` changes bytes, then this
module rescans both files with the same static cost model and reports the diff.
It is a model comparison, not a measurement — both sides use `estimate()` and no
network/`--ai` call is made, so the delta is attributable to the file, not to
model noise.

Positive `seconds_*` delta = the protected copy makes the agent work longer.
Negative `p_success` / `risk` delta = the protected copy is safer.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from struct import error as StructError

from .estimate import Estimate, estimate, human_duration
from .evidence import Evidence, collect
from .peinfo import PEError, PEInfo
from .report import risk_score

# The estimate rounds seconds to 0.1s and p_success to 0.01, so anything below
# these values is rounding noise, not a real change.
SECONDS_TOLERANCE = 0.2
P_TOLERANCE = 0.005


class AIMeasureError(RuntimeError):
    """The live model call failed; do not emit a half-measured comparison."""

    def __init__(self, message: str, code: str = "AI_ERROR", retry_after=None):
        super().__init__(message)
        self.code = code
        self.retry_after = retry_after


def _measure_side(ev: Evidence, repeat: int) -> dict:
    """Run 1..N live rounds and reduce them to one comparable number.

    One round is noisy (cold start, queueing); the default stays 1 for cost, but
    `compare --ai --repeat 3` is the honest way to claim a before/after case.
    """
    from .ai import measure as measure_ai

    results = []
    for _ in range(max(1, repeat)):
        result = measure_ai(ev)
        if result.get("error"):
            raise AIMeasureError(
                result["error"],
                result.get("error_code") or "AI_ERROR",
                result.get("retry_after"),
            )
        results.append(result)
    if len(results) == 1:
        return results[0]

    import statistics

    # Time the successful rounds only, like `calibrate.summarize_attempts`. A
    # failed round can be faster than a real answer (the model gives up), so a
    # median over all rounds paired with success=True would report "found" at the
    # wrong duration.
    successes = [r for r in results if r.get("success")]
    timing = successes or results
    seconds = [float(r["seconds"]) for r in timing]
    combined = dict(results[-1])
    combined["seconds"] = round(statistics.median(seconds), 2)
    combined["success"] = bool(successes)
    combined["grounded"] = bool(successes)
    combined["attempts"] = len(results)
    combined["successes"] = len(successes)
    combined["second_samples"] = [float(r["seconds"]) for r in results]
    return combined


# --------------------------------------------------------------------- loading

def load_side(path: str, measure: bool = False, repeat: int = 1) -> tuple[Evidence, Estimate, dict | None]:
    """Collect + estimate one file, failing loudly when it is not a PE.

    `collect()` deliberately swallows PEError and reports a headerless file as
    "native" (the web must still produce a report for odd inputs). A diff has no
    meaning in that case, so re-parse to surface the precise reason.

    `measure=True` runs one live model round for each side. This is opt-in
    (`compare --ai`) because it costs tokens and can fail on quota; the static
    estimate is still produced either way.
    """
    try:
        # Cheap rejection before `collect()`: a non-PE path used to be read in
        # full (and then a second time for the error message) before failing.
        # A 2 GB wrong path could OOM the host just to say "no MZ header".
        with Path(path).open('rb') as handle:
            magic = handle.read(2)
    except OSError as err:
        raise PEError(f"{path}: {err}") from err
    if magic != b"MZ":
        raise PEError(f"{path}: not a PE file (no MZ header)")

    try:
        ev = collect(path)
    except StructError as err:
        # `collect()` only catches PEError; a truncated header can still raise
        # struct.error. Name the file instead of leaking a bare unpack message.
        raise PEError(f"{path}: truncated PE header ({err})") from err

    if ev.pe is None:
        try:
            PEInfo(Path(path).read_bytes(), path)  # raises PEError with the real reason
        except (PEError, StructError) as err:
            raise PEError(f"{path}: {err}") from err
        raise PEError(f"{path}: not a PE file")

    # Headers alone do not make a usable binary: a partial download can have
    # valid headers and no section data. Do not call that a confident "unchanged".
    for section in ev.pe.sections:
        if section["rawsize"]:
            end = section["rawptr"] + section["rawsize"]
            if end > ev.size:
                raise PEError(
                    f"{path}: truncated PE — section {section['name']!r} ends at "
                    f"{end:,} bytes but the file is {ev.size:,} bytes"
                )
    est = estimate(ev)
    measured = None
    if measure:
        measured = _measure_side(ev, repeat)
    return ev, est, measured


# --------------------------------------------------------------------- shaping

def display_findings(ev: Evidence) -> list[dict]:
    """Only what a report/human reader needs; internal severity stays internal."""
    return [
        {"id": f["id"], "detail": f["detail"], "weight": f["weight"], "fix": f["fix"]}
        for f in sorted(ev.findings, key=lambda x: -x["weight"])
    ]


def summarize(ev: Evidence, est: Estimate, measured: dict | None = None) -> dict:
    return {
        "file": ev.path,
        "sha256": ev.sha256,
        "kind": ev.kind,
        "size": ev.size,
        "crack_seconds_best": round(est.best, 1),
        "crack_seconds_worst": round(est.worst, 1),
        "p_success": est.p_success,
        "risk": risk_score(est.best, est.p_success),
        "read_budget_tokens": est.budget_tokens,
        "markers": list(ev.markers),
        "findings": display_findings(ev),
        "measured": measured,
    }


def classify_findings(
    original: list[dict], protected: list[dict]
) -> tuple[list[dict], list[dict], list[dict], list[dict], list[dict]]:
    """Split findings into fixed/new/protection-added/changed/protection-removed.

    Finding ids are stable kinds (`pdb-path`, `packed`, ...), so an id that is
    gone means the leak itself is gone — not that its wording changed. An id
    that survives with a different weight is a *changed* finding, not a new or
    fixed one; without that bucket a 4→20 worsening was invisible.
    """
    orig_by_id = {f["id"]: f for f in original}
    prot_by_id = {f["id"]: f for f in protected}

    fixed = [
        f for f in original
        if f["weight"] > 0 and f["id"] not in prot_by_id
    ]
    removed = [
        f for f in original
        if f["weight"] <= 0 and f["id"] not in prot_by_id
    ]
    # A partition, not overlapping lists: new leaks and new protections are
    # different rows in the report and different keys in JSON.
    new = [
        f for f in protected
        if f["id"] not in orig_by_id and f["weight"] > 0
    ]
    added = [
        f for f in protected
        if f["id"] not in orig_by_id and f["weight"] <= 0
    ]
    changed = [
        {
            "id": fid,
            "before": before,
            "after": prot_by_id[fid],
            "delta_weight": prot_by_id[fid]["weight"] - before["weight"],
        }
        for fid, before in orig_by_id.items()
        if fid in prot_by_id and prot_by_id[fid]["weight"] != before["weight"]
    ]

    fixed.sort(key=lambda x: -x["weight"])
    removed.sort(key=lambda x: x["weight"])
    new.sort(key=lambda x: -x["weight"])
    added.sort(key=lambda x: x["weight"])
    changed.sort(key=lambda x: -x["delta_weight"])
    return fixed, new, added, changed, removed


def verdict_for(delta: dict) -> str:
    """Three-state answer; risk breaks ties when time and success disagree."""
    time_better = delta["seconds_best"] > SECONDS_TOLERANCE
    time_worse = delta["seconds_best"] < -SECONDS_TOLERANCE
    p_better = delta["p_success"] < -P_TOLERANCE
    p_worse = delta["p_success"] > P_TOLERANCE

    if (time_better or p_better) and (time_worse or p_worse):
        # One dimension improved, the other regressed: the combined risk score
        # is the only field that already weighs both.
        if delta["risk"] < 0:
            return "better"
        if delta["risk"] > 0:
            return "worse"
        return "unchanged"
    if time_better or p_better:
        return "better"
    if time_worse or p_worse:
        return "worse"
    return "unchanged"


def added_markers(result: dict) -> list[str]:
    """Protection markers that only the protected copy has (`TK1`/`TK2`)."""
    before = set(result["original"].get("markers") or [])
    return [m for m in (result["protected"].get("markers") or []) if m not in before]


def verdict_sentence(result: dict) -> str:
    delta = result["delta"]
    verdict = result["verdict"]
    if verdict == "unchanged":
        fixed = result.get("fixed_findings") or []
        if fixed:
            return (
                f"unchanged score — {len(fixed)} leak(s) removed, but crack time and "
                "p_success did not move; the model does not consider this protected"
            )
        if not result["protection_added"] and not added_markers(result):
            return (
                "unchanged — no new protection detected and the score did not move; "
                "this copy is not better protected"
            )
        return "unchanged — same estimated crack time and success probability"
    if verdict == "better":
        why = []
        if delta["seconds_best"] > SECONDS_TOLERANCE:
            why.append(f"best-case time {delta['seconds_best']:+.1f}s")
        if delta["p_success"] < -P_TOLERANCE:
            why.append(
                f"p_success {result['original']['p_success']} -> {result['protected']['p_success']}"
            )
        return "better — " + (", ".join(why) or "lower risk")
    why = []
    if delta["seconds_best"] < -SECONDS_TOLERANCE:
        why.append(f"best-case time {delta['seconds_best']:+.1f}s")
    if delta["p_success"] > P_TOLERANCE:
        why.append(
            f"p_success {result['original']['p_success']} -> {result['protected']['p_success']}"
        )
    return "worse — " + (", ".join(why) or "higher risk")


# -------------------------------------------------------------------- compare

def _finding_from_report(item: dict) -> dict:
    if not isinstance(item, dict):
        raise ValueError("each finding must be an object")
    try:
        weight = int(item.get("weight") or 0)
    except (TypeError, ValueError, OverflowError) as err:
        raise ValueError("finding.weight must be an integer") from err
    return {
        "id": str(item.get("id") or "unknown"),
        "detail": str(item.get("detail") or ""),
        "weight": weight,
        "fix": str(item.get("fix") or ""),
    }


def _number(report: dict, key: str, default: float = 0.0) -> float:
    """Strict numeric field: `"abc"` must be a 400, not a silent 0.

    A report with a corrupt duration used to produce a confident "unchanged"
    diff; that is worse than rejecting the file.
    """
    value = report.get(key)
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValueError(f"report.{key} must be a number, not a boolean")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as err:
        raise ValueError(f"report.{key} must be a number") from err
    if not math.isfinite(number):
        raise ValueError(f"report.{key} must be finite")
    return number


def _measured_from_report(value) -> dict | None:
    """Sanitize the optional `measured` block copied from a scan --ai report.

    Web input is untrusted, but an invalid measured block must not reject an
    otherwise valid report; it is only an extra display/delta field.
    """
    if not isinstance(value, dict):
        return None
    try:
        seconds = float(value.get("seconds"))
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(seconds) or seconds < 0:
        return None
    usage_in = value.get("usage") if isinstance(value.get("usage"), dict) else {}
    usage = {
        key: usage_in[key]
        for key in ("prompt_tokens", "completion_tokens", "total_tokens")
        if key in usage_in
    }
    # A corrupt `attempts` must not reject an otherwise valid report: this field
    # is display-only, so fall back to "one round" instead of raising from
    # int(dict)/int("abc")/int(inf) and turning a 200 into a 400.
    try:
        attempts = int(value.get("attempts") or 1)
    except (TypeError, ValueError, OverflowError):
        attempts = 1
    return {
        "seconds": round(seconds, 2),
        "provider": str(value.get("provider") or ""),
        "model": str(value.get("model") or ""),
        "success": bool(value.get("success")),
        "grounded": bool(value.get("grounded")),
        "attempts": max(1, attempts),
        "output_sample": str(value.get("output_sample") or "")[:400],
        "usage": usage,
    }


def _summary_from_report(report: dict) -> dict:
    """Accept the JSON emitted by `scan.py --json` (not a raw Evidence object).

    The web must not run `protect` on a customer binary, so the comparison page
    takes two reports the user generated locally. Keep this schema check strict
    enough to reject HTML/random JSON with a clear 400, not a traceback.
    """
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("report.findings must be a list")
    if "crack_seconds_best" not in report or "p_success" not in report:
        raise ValueError("report is missing crack_seconds_best/p_success")

    size = int(_number(report, "size"))
    best = round(_number(report, "crack_seconds_best"), 1)
    p_success = _number(report, "p_success")
    risk = report.get("risk")
    if risk is None:
        risk = risk_score(best, p_success)
    else:
        risk = int(_number(report, "risk"))
    return {
        "file": str(report.get("file") or ""),
        "sha256": str(report.get("sha256") or ""),
        "kind": str(report.get("kind") or "unknown"),
        "size": size,
        "crack_seconds_best": best,
        "crack_seconds_worst": round(_number(report, "crack_seconds_worst", best), 1),
        "p_success": p_success,
        "risk": int(risk),
        "read_budget_tokens": int(_number(report, "read_budget_tokens")),
        "markers": [str(m) for m in (report.get("markers") or [])],
        "findings": [_finding_from_report(f) for f in findings],
        "measured": _measured_from_report(report.get("measured")),
    }


def from_reports(original_report: dict, protected_report: dict) -> dict:
    """Diff two `scan.py --json` reports. Used by `compare-reports` and the web."""
    return _build_from_summaries(
        _summary_from_report(original_report),
        _summary_from_report(protected_report),
    )


def build(
    original_ev: Evidence,
    original_est: Estimate,
    protected_ev: Evidence,
    protected_est: Estimate,
    original_measured: dict | None = None,
    protected_measured: dict | None = None,
) -> dict:
    return _build_from_summaries(
        summarize(original_ev, original_est, original_measured),
        summarize(protected_ev, protected_est, protected_measured),
    )


def _ai_verdict(ai: dict) -> str:
    """Turn the live one-round result into a sentence that cannot be confused
    with the static cost-model verdict."""
    if ai["original_success"] and not ai["protected_success"]:
        return "measured: protected copy no longer yields a find"
    if not ai["original_success"] and ai["protected_success"]:
        return "measured: protected copy became easier to identify"
    if not ai["original_success"] and not ai["protected_success"]:
        return "measured: neither copy yielded a find (no signal)"
    # A 1-second floor let a single noisy call claim an improvement. Require at
    # least 3 rounds on both sides and a delta wider than 2s/15%; otherwise the
    # honest answer is "we cannot tell", not "protected is faster".
    rounds = min(ai.get("original_attempts") or 1, ai.get("protected_attempts") or 1)
    noise = max(2.0, 0.15 * max(ai["original_seconds"], ai["protected_seconds"]))
    if rounds < 3:
        return (
            f"measured: {rounds} round(s) per file; {ai['delta_seconds']:+.2f}s is within "
            "noise (use --repeat 3)"
        )
    if ai["delta_seconds"] > noise:
        return f"measured: protected copy took {ai['delta_seconds']:+.2f}s longer"
    if ai["delta_seconds"] < -noise:
        return f"measured: protected copy was {-ai['delta_seconds']:.2f}s faster"
    return "measured: no meaningful change; the static improvement is not confirmed"


def _build_from_summaries(original: dict, protected: dict) -> dict:
    delta = {
        "seconds_best": round(protected["crack_seconds_best"] - original["crack_seconds_best"], 1),
        "seconds_worst": round(protected["crack_seconds_worst"] - original["crack_seconds_worst"], 1),
        "p_success": round(protected["p_success"] - original["p_success"], 2),
        "risk": protected["risk"] - original["risk"],
    }
    static_verdict = verdict_for(delta)

    fixed, new, added, changed, removed = classify_findings(
        original["findings"], protected["findings"]
    )
    # Live measurement is a separate axis from the cost model. Store it in its
    # own block so nobody subtracts a one-round number from a full-workflow
    # estimate.
    ai = None
    measured_original = original.get("measured")
    measured_protected = protected.get("measured")
    if measured_original and measured_protected:
        original_attempts = max(1, int(measured_original.get("attempts") or 1))
        protected_attempts = max(1, int(measured_protected.get("attempts") or 1))
        attempts = max(original_attempts, protected_attempts)
        if original_attempts == protected_attempts:
            rounds = f"median of {attempts} rounds" if attempts > 1 else "one model round"
        else:
            rounds = f"{original_attempts} vs {protected_attempts} rounds"
        ai = {
            "model": measured_protected.get("model") or measured_original.get("model") or "",
            "original_seconds": measured_original["seconds"],
            "protected_seconds": measured_protected["seconds"],
            "delta_seconds": round(
                measured_protected["seconds"] - measured_original["seconds"], 2
            ),
            "original_success": bool(measured_original.get("success")),
            "protected_success": bool(measured_protected.get("success")),
            "attempts": attempts,
            "original_attempts": original_attempts,
            "protected_attempts": protected_attempts,
            "note": (
                rounds
                + "; tool time is excluded and these seconds are not the cost-model seconds"
            ),
        }
        ai["verdict"] = _ai_verdict(ai)
    # Missing hashes are not evidence that the files are identical; otherwise
    # two hand-written report stubs both default to "" and falsely say so.
    same_file = bool(original["sha256"]) and original["sha256"] == protected["sha256"]

    notes: list[str] = []
    if ai:
        if ai["original_attempts"] == ai["protected_attempts"]:
            rounds = f"median of {ai['attempts']} rounds" if ai["attempts"] > 1 else "one round"
        else:
            rounds = f"{ai['original_attempts']} vs {ai['protected_attempts']} rounds"
        notes.append(
            f"AI measured {ai['original_seconds']:.2f}s -> {ai['protected_seconds']:.2f}s "
            f"({ai['delta_seconds']:+.2f}s, {rounds}, tool time excluded)"
        )
        ai_confirms = (
            "no longer yields a find" in ai["verdict"]
            or ai["verdict"].startswith("measured: protected copy took")
        )
        if static_verdict == "better" and not ai_confirms:
            notes.append("live measurement does not confirm the static improvement")
    elif measured_original or measured_protected:
        notes.append("AI measurement present on one side only; use --ai on both files")
    if same_file:
        notes.append(
            "both paths have the same sha256: nothing was protected, the zero delta is by construction"
        )
    if fixed:
        notes.append(
            f"{len(fixed)} leak(s) removed; the score effect is in the delta above"
        )
    if removed:
        notes.append(
            f"{len(removed)} protection finding(s) disappeared from the protected copy"
        )
    new_markers = [m for m in protected["markers"] if m not in original["markers"]]
    if new_markers:
        # `deception-active` is only emitted when the payload text is readable at
        # level 1; an encrypted TK2 blob has no finding of its own, so name the
        # marker instead of pretending the protected copy has no protection.
        notes.append(
            "protected copy carries new marker(s): "
            + ", ".join(new_markers)
            + " (protection bytes present; scoring effect is in the delta above)"
        )
    if not added and not fixed and not changed and delta["seconds_best"] <= SECONDS_TOLERANCE \
            and delta["p_success"] >= -P_TOLERANCE and not new_markers:
        notes.append("no new protection detected and no score change")

    result = {
        "ok": True,
        "original": original,
        "protected": protected,
        "delta": delta,
        "ai": ai,
        "fixed_findings": fixed,
        "new_findings": new,
        "protection_added": added,
        "changed_findings": changed,
        "protection_removed": removed,
        "same_file": same_file,
        "verdict": static_verdict,
        "notes": notes,
    }
    return result


def compare(original_path: str, protected_path: str, measure: bool = False, repeat: int = 1) -> dict:
    original_ev, original_est, original_measured = load_side(original_path, measure, repeat)
    protected_ev, protected_est, protected_measured = load_side(protected_path, measure, repeat)
    return build(
        original_ev,
        original_est,
        protected_ev,
        protected_est,
        original_measured,
        protected_measured,
    )


# ------------------------------------------------------------------- rendering

def _finding_lines(title: str, findings: list[dict], empty: str, fixed: bool = False) -> list[str]:
    lines = [title]
    if not findings:
        lines.append(f"  {empty}")
        return lines
    for f in findings:
        # A fixed leak used the same "-15" prefix as a live leak, so the reader
        # could not tell whether the row was good or bad.
        sign = "✓" if fixed else ("+" if f["weight"] <= 0 else "-")
        lines.append(f"  {sign}{abs(f['weight']):<3} {f['id']:<18} {f['detail']}")
        lines.append(f"         fix: {f['fix']}")
    return lines


def _side_lines(label: str, side: dict) -> list[str]:
    markers = ", ".join(side["markers"]) if side["markers"] else "none"
    lines = [
        f"{label:<10} {side['file']}",
        f"           {side['kind']} · {side['size']:,} bytes · sha256 {side['sha256'][:16]}…",
        f"           crack ~{human_duration(side['crack_seconds_best'])}"
        f" .. ~{human_duration(side['crack_seconds_worst'])} (best..worst, cost model)"
        f" · p={side['p_success']} · risk {side['risk']}/100",
        f"           read budget {side['read_budget_tokens']:,} tokens"
        f" · {len(side['findings'])} finding(s) · markers: {markers}",
    ]
    measured = side.get("measured")
    if measured:
        lines.append(
            f"           AI measured {measured['seconds']}s"
            f" · success={bool(measured.get('success'))}"
            f" · {measured.get('model') or 'model'}"
        )
    return lines


def render(result: dict) -> str:
    delta = result["delta"]
    width = 72
    lines = [
        "TrapKey compare — original vs protected",
        "─" * width,
    ]
    lines += _side_lines("original", result["original"])
    lines.append("")
    lines += _side_lines("protected", result["protected"])
    lines.append("")
    lines.append(
        f"delta      seconds_best {delta['seconds_best']:+.1f}s"
        f" · seconds_worst {delta['seconds_worst']:+.1f}s"
        f" · p_success {delta['p_success']:+.2f}"
        f" · risk {delta['risk']:+d}"
    )
    lines.append(
        "           (positive seconds = more work for the agent; negative risk = better)"
    )
    ai = result.get("ai")
    if ai:
        lines.append(
            f"ai measured {ai['original_seconds']:.2f}s -> {ai['protected_seconds']:.2f}s"
            f" ({ai['delta_seconds']:+.2f}s)"
            f" · success {ai['original_success']} -> {ai['protected_success']}"
            f" · {ai['model'] or 'model'}"
        )
        lines.append(f"           ({ai['note']})")
        lines.append(f"ai verdict {ai['verdict']}")
    lines.append("")
    lines += _finding_lines(
        "fixed findings (leaks gone from the protected copy):",
        result["fixed_findings"],
        "none",
        fixed=True,
    )
    lines.append("")
    lines += _finding_lines(
        "new findings (only in the protected copy):",
        result["new_findings"],
        "none",
    )
    lines.append("")
    lines += _finding_lines(
        "protection added (weight <= 0, only in the protected copy):",
        result["protection_added"],
        "none",
    )
    if result.get("changed_findings"):
        lines.append("")
        lines.append("changed findings (same id, different weight):")
        for change in result["changed_findings"]:
            before = change["before"]
            after = change["after"]
            lines.append(
                f"  {change['id']:<18} {before['weight']:+d} -> {after['weight']:+d}"
                f" ({change['delta_weight']:+d})"
            )
    if result.get("protection_removed"):
        lines.append("")
        lines += _finding_lines(
            "protection removed (was present in the original only):",
            result["protection_removed"],
            "none",
        )
    lines.append("")
    lines.append(f"verdict    {verdict_sentence(result)}")
    # The CLI already printed the same-file caveat on stderr (so `--json` stays
    # a single object). Drop that one note by position, not by substring: a
    # wording change must not silently bring the duplicate back.
    notes = result["notes"][1:] if result.get("same_file") else result["notes"]
    for note in notes:
        lines.append(f"note       {note}")
    lines.append("")
    lines.append("This is a cost model, not a measurement. Measure with: python3 scan.py <file> --ai")
    return "\n".join(lines)


def render_json(result: dict) -> str:
    # One object only: the web/CI parses stdout as a whole.
    return json.dumps(result, indent=2, ensure_ascii=False)
