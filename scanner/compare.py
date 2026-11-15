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


# --------------------------------------------------------------------- loading

def load_side(path: str) -> tuple[Evidence, Estimate]:
    """Collect + estimate one file, failing loudly when it is not a PE.

    `collect()` deliberately swallows PEError and reports a headerless file as
    "native" (the web must still produce a report for odd inputs). A diff has no
    meaning in that case, so re-parse to surface the precise reason.
    """
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
    return ev, estimate(ev)


# --------------------------------------------------------------------- shaping

def display_findings(ev: Evidence) -> list[dict]:
    """Only what a report/human reader needs; internal severity stays internal."""
    return [
        {"id": f["id"], "detail": f["detail"], "weight": f["weight"], "fix": f["fix"]}
        for f in sorted(ev.findings, key=lambda x: -x["weight"])
    ]


def summarize(ev: Evidence, est: Estimate) -> dict:
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
) -> dict:
    return _build_from_summaries(
        summarize(original_ev, original_est),
        summarize(protected_ev, protected_est),
    )


def _build_from_summaries(original: dict, protected: dict) -> dict:
    delta = {
        "seconds_best": round(protected["crack_seconds_best"] - original["crack_seconds_best"], 1),
        "seconds_worst": round(protected["crack_seconds_worst"] - original["crack_seconds_worst"], 1),
        "p_success": round(protected["p_success"] - original["p_success"], 2),
        "risk": protected["risk"] - original["risk"],
    }

    fixed, new, added, changed, removed = classify_findings(
        original["findings"], protected["findings"]
    )
    # Missing hashes are not evidence that the files are identical; otherwise
    # two hand-written report stubs both default to "" and falsely say so.
    same_file = bool(original["sha256"]) and original["sha256"] == protected["sha256"]

    notes: list[str] = []
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
        "fixed_findings": fixed,
        "new_findings": new,
        "protection_added": added,
        "changed_findings": changed,
        "protection_removed": removed,
        "same_file": same_file,
        "verdict": verdict_for(delta),
        "notes": notes,
    }
    return result


def compare(original_path: str, protected_path: str) -> dict:
    original_ev, original_est = load_side(original_path)
    protected_ev, protected_est = load_side(protected_path)
    return build(original_ev, original_est, protected_ev, protected_est)


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
    return [
        f"{label:<10} {side['file']}",
        f"           {side['kind']} · {side['size']:,} bytes · sha256 {side['sha256'][:16]}…",
        f"           crack ~{human_duration(side['crack_seconds_best'])}"
        f" .. ~{human_duration(side['crack_seconds_worst'])} (best..worst, cost model)"
        f" · p={side['p_success']} · risk {side['risk']}/100",
        f"           read budget {side['read_budget_tokens']:,} tokens"
        f" · {len(side['findings'])} finding(s) · markers: {markers}",
    ]


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
    for note in result["notes"]:
        if "same sha256" not in note:  # already warned on stderr by the CLI
            lines.append(f"note       {note}")
    lines.append("")
    lines.append("This is a cost model, not a measurement. Measure with: python3 scan.py <file> --ai")
    return "\n".join(lines)


def render_json(result: dict) -> str:
    # One object only: the web/CI parses stdout as a whole.
    return json.dumps(result, indent=2, ensure_ascii=False)
