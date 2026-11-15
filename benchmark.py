#!/usr/bin/env python3
"""Ground-truth benchmark: score TrapKey against labels, not against its own claims.

    python3 benchmark.py --corpus DIR --labels FILE --static
    python3 benchmark.py --corpus DIR --labels FILE --ai

`--static` scores `scanner.evidence.named_license_functions` + license strings
(no network). `--ai` calls `scanner.ai.measure()` per file and scores the
FUNCTION value against the labels. `ai.measure()["success"]` and `["grounded"]`
are printed as diagnostics but are never used as correctness: the labels decide.

Labels say what the real licence check is (function name or address), or that
the binary has none. Without that we cannot claim the model "found" anything.

Exit codes: 0 run completed · 2 bad input / no labels / no files.
A low hit rate is a result, not an error, so it still exits 0.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner import collect  # noqa: E402
from scanner.peinfo import PEError  # noqa: E402

EXTS = {".exe", ".dll", ".bin", ".sys"}
MIN_SIZE = 20_000

RESULT_HIT = "hit"
RESULT_MISS = "miss"
RESULT_FALSE_POSITIVE = "false_positive"
RESULT_SKIPPED = "skipped"

# Same spirit as scanner.ai's failure set. An answer of "unknown" is not an
# answer; it is an admission, so it is scored like `none`.
NONE_TOKENS = {
    "none", "unknown", "undetermined", "unidentified", "n/a", "null", "unable",
    "insufficient", "inconclusive", "unclear", "ambiguous", "cannot", "not",
    "no", "nothing", "nil",
}

_TRAILING = " \t\r\n`\"'()[]{}<>.,;:!?*&"
_HEX = re.compile(r"[0-9a-f]+")
_GENERIC_ARITY = re.compile(r"`\d+$")


class LabelError(ValueError):
    """The labels file is missing or does not follow the documented schema."""


# ---------------------------------------------------------------- normalization


def normalize_name(value: str) -> str:
    """Canonical token for comparison.

    Handles the forms that actually appear in evidence and labels:
    `Type::Method`, `Namespace.Type.Method`, `module.dll!Export`, `0x140012340`,
    mixed case, generic arity (`Method`1`) and trailing punctuation. Addresses
    are canonicalised numerically so `0x000140012340` == `0x140012340`.
    """
    text = (value or "").strip()
    if not text:
        return ""
    # A label or model answer may be "Name (see notes)" or a C-style signature
    # ("CheckLicense(int)"); the identifier is the first chunk before whitespace
    # or an opening parenthesis.
    text = text.split()[0].strip(_TRAILING)
    text = re.sub(r"\(.*$", "", text)
    text = _GENERIC_ARITY.sub("", text).strip(_TRAILING)

    for separator in ("!", "::"):
        if separator in text:
            text = text.rsplit(separator, 1)[1]
    if "." in text:
        text = text.rsplit(".", 1)[1]
    text = text.strip(_TRAILING).lower()
    if not text:
        return ""

    if text.startswith("0x"):
        digits = text[2:].strip("_")
        if digits and _HEX.fullmatch(digits):
            # Numeric canonicalisation, but keep it a string: `.hex()` style.
            return format(int(digits, 16), "x")
        return digits
    return text


def is_none_answer(value: str) -> bool:
    token = normalize_name(value)
    if not token:
        return True
    if token in NONE_TOKENS:
        return True
    return token.startswith(
        ("unknown", "undetermined", "unidentified", "insufficient", "inconclusive", "n/a")
    )


_FUNCTION_LINE = re.compile(r"^function\s*[:\-]\s*(.*)$", re.I)


def parse_function_value(text: str) -> str:
    """Extract the value after the first `FUNCTION:` line, or '' if absent.

    Models format headers in several ways: `**FUNCTION:** X`, `1. FUNCTION: X`,
    `FUNCTION : X`, `FUNCTION - X`. A strict startswith("FUNCTION:") check
    silently scored a correct bolded answer as `none`, which directly deflated
    recall in the benchmark.
    """
    for line in (text or "").splitlines():
        # Remove markdown decoration and list numbering before matching, but
        # keep the value after the separator intact.
        # Strip markdown emphasis from the header, but keep backticks in the
        # value: `Validate`1 is a legitimate generic-arity name and normalize
        # removes the arity itself.
        cleaned = line.strip().replace("*", "")
        cleaned = re.sub(r"^[>#\s_~-]+", "", cleaned)
        cleaned = re.sub(r"^\d+[.)]\s*", "", cleaned)
        match = _FUNCTION_LINE.match(cleaned)
        if match:
            return match.group(1).strip(" _~-").strip("`").strip()
    return ""


def match_expected(expected: list[str], answer: str) -> bool:
    """True when the model's answer is one of the labelled tokens."""
    if is_none_answer(answer):
        return False
    target = normalize_name(answer)
    return any(normalize_name(item) == target for item in expected)


def _word_contains(haystack: str, needle: str) -> bool:
    """Identifier containment without matching `Test` inside `latest`."""
    if not needle:
        return False
    pattern = r"(?<![0-9a-z_])" + re.escape(needle) + r"(?![0-9a-z_])"
    return re.search(pattern, haystack) is not None


def match_static(expected: list[str], named_names: list[str], strings: list[str]) -> dict | None:
    """Find a labelled token in the static evidence.

    Named functions are compared as whole identifiers after normalization.
    License strings are literals: a phrase label must appear whole, and an
    identifier label must appear on word boundaries (not inside `latest`).
    """
    normalised_named = [(normalize_name(name), name) for name in named_names if name]
    for item in expected:
        needle = normalize_name(item)
        if not needle:
            continue
        for norm, raw in normalised_named:
            if norm and norm == needle:
                return {"source": "named_functions", "value": raw}
        # Addresses cannot live in a string; only look for name-like tokens.
        raw = (item or "").strip()
        if raw and not raw.lower().startswith("0x"):
            raw_lower = raw.lower()
            for text in strings:
                lowered = (text or "").lower()
                # A label with spaces is a literal phrase; a phrase label must
                # match whole, never fall back to its first word. A label that
                # is an identifier is matched on word boundaries so "Test"
                # cannot hit "latest".
                if " " in raw:
                    if raw_lower in lowered:
                        return {"source": "license_strings", "value": text}
                elif len(needle) >= 4 and _word_contains(lowered, needle):
                    return {"source": "license_strings", "value": text}
    return None


def classify_answer(expected: list[str], allow_none: bool, answer: str) -> tuple[str, str]:
    """Map one answer to (result, note). Used by both modes.

    hit            matched a label, or correctly answered none (expected [])
    miss           answered none while a check was expected
    false_positive answered a name that is not a label
    """
    usable = [item for item in (expected or []) if normalize_name(item)]
    if match_expected(usable, answer):
        return RESULT_HIT, ""
    if is_none_answer(answer):
        if not usable and allow_none:
            return RESULT_HIT, "correct none: labels say this binary has no licence check"
        if usable:
            return RESULT_MISS, "returned none while the labels name a licence check"
        return RESULT_MISS, "returned none but allow_none is false"
    return RESULT_FALSE_POSITIVE, "answered a name that is not in the labels"


# ---------------------------------------------------------------------- labels


def load_labels(path: str | Path) -> dict[str, dict]:
    """Load and validate the labels file.

    Accepted per file:
        "App.exe": ["CheckLicense", "0x140012340"]
        "App.exe": {"expect": ["CheckLicense"], "allow_none": false}
    A list form with [] means "no licence check", so allow_none defaults to
    True when the expected list is empty.
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError as err:
        raise LabelError(f"labels file not found: {p}") from err
    except OSError as err:
        raise LabelError(f"cannot read labels file {p}: {err}") from err
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as err:
        raise LabelError(f"labels file is not valid JSON: {err}") from err
    if not isinstance(data, dict):
        raise LabelError("labels must be a JSON object with a 'files' mapping")
    files = data.get("files")
    if not isinstance(files, dict):
        raise LabelError("labels must contain a 'files' object mapping filenames to expectations")

    labels: dict[str, dict] = {}
    for name, spec in files.items():
        if not isinstance(name, str) or not name.strip():
            raise LabelError("every label key must be a non-empty filename")
        if isinstance(spec, list):
            expect = spec
            allow_none = len(expect) == 0
        elif isinstance(spec, dict):
            if "expect" not in spec:
                raise LabelError(f"label for {name!r} has no 'expect' field")
            expect = spec["expect"]
            allow_none = spec.get("allow_none", isinstance(expect, list) and len(expect) == 0)
            if not isinstance(allow_none, bool):
                raise LabelError(f"label for {name!r}: 'allow_none' must be true or false")
        else:
            raise LabelError(
                f"label for {name!r} must be a list or an object with 'expect'/'allow_none'"
            )
        if not isinstance(expect, list) or not all(
            isinstance(item, str) and item.strip() for item in expect
        ):
            raise LabelError(f"label for {name!r}: 'expect' must be a list of non-empty strings")
        if allow_none and expect:
            # `none` cannot be both correct and incorrect for the same file.
            raise LabelError(
                f"label for {name!r}: 'allow_none' is only valid when 'expect' is empty"
            )
        labels[name] = {"expect": list(expect), "allow_none": allow_none}
    return labels


def _clean_label_key(key: str) -> str:
    cleaned = key.replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned.lstrip("/")


def _label_index(labels: dict[str, dict]) -> tuple[dict, dict]:
    by_path: dict[str, tuple[str, dict]] = {}
    by_name: dict[str, list[tuple[str, dict]]] = {}
    for key, spec in labels.items():
        cleaned = _clean_label_key(key)
        by_path[cleaned.casefold()] = (key, spec)
        # Only a basename-only key may act as a basename fallback. Otherwise a
        # label for `sub/App.exe` would silently become ground truth for every
        # other App.exe in the corpus.
        if "/" not in cleaned:
            by_name.setdefault(cleaned.casefold(), []).append((key, spec))
    return by_path, by_name


def find_label(path: Path, root: Path, index: tuple[dict, dict]) -> tuple[str, dict] | None:
    """Match by relative path first, then by basename (the documented form)."""
    by_path, by_name = index
    try:
        rel = path.relative_to(root).as_posix().casefold()
    except ValueError:
        rel = path.name.casefold()
    if rel in by_path:
        return by_path[rel]
    entries = by_name.get(path.name.casefold())
    return entries[0] if entries else None


# ---------------------------------------------------------------------- corpus


def discover_corpus(directory: str | Path, limit: int | None = None) -> list[Path]:
    """Walk DIR for PE-ish binaries, sorted deterministically, then apply --limit."""
    root = Path(directory)
    files: list[Path] = []
    for candidate in root.rglob("*"):
        if not candidate.is_file() or candidate.suffix.lower() not in EXTS:
            continue
        try:
            if candidate.stat().st_size < MIN_SIZE:
                continue
        except OSError:
            continue
        files.append(candidate)
    def sort_key(item: Path) -> tuple[str, str]:
        rel = item.relative_to(root).as_posix()
        return (rel.lower(), rel)

    files.sort(key=sort_key)
    if limit is not None and limit > 0:
        files = files[:limit]
    return files


# ---------------------------------------------------------------------- scoring


def percentile(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile; no numpy dependency."""
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 3)
    rank = math.ceil(pct / 100 * len(ordered))
    index = min(max(rank - 1, 0), len(ordered) - 1)
    return round(ordered[index], 3)


def summarize(rows: list[dict]) -> dict:
    evaluated = [row for row in rows if row.get("result") != RESULT_SKIPPED]
    hits = [row for row in evaluated if row["result"] == RESULT_HIT]
    false_positives = [row for row in evaluated if row["result"] == RESULT_FALSE_POSITIVE]
    misses = [row for row in evaluated if row["result"] == RESULT_MISS]
    # "returned none/non-expected while expected" — a wrong name is both a false
    # positive and a false negative, so these two counters can overlap.
    false_negatives = [row for row in evaluated if row.get("expected") and row["result"] != RESULT_HIT]
    correct_none = [row for row in evaluated if row["result"] == RESULT_HIT and not row.get("expected")]
    latencies = [
        float(row["latency"])
        for row in evaluated
        if isinstance(row.get("latency"), (int, float))
    ]
    return {
        "evaluated": len(evaluated),
        "hits": len(hits),
        "hit_rate": round(len(hits) / len(evaluated), 4) if evaluated else None,
        "false_positives": len(false_positives),
        "false_negatives": len(false_negatives),
        "misses": len(misses),
        "correct_none": len(correct_none),
        "skipped": len(rows) - len(evaluated),
        "median_latency_seconds": round(statistics.median(latencies), 3) if latencies else None,
        "p95_latency_seconds": percentile(latencies, 95),
        "prompt_tokens": sum(int(row.get("prompt_tokens") or 0) for row in evaluated),
        "completion_tokens": sum(int(row.get("completion_tokens") or 0) for row in evaluated),
    }


def _row(path: Path, root: Path, mode: str, spec: dict) -> dict:
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        rel = path.name
    return {
        "file": rel,
        "name": path.name,
        "mode": mode,
        "expected": list(spec["expect"]),
        "allow_none": spec["allow_none"],
        "answer": None,
        "result": RESULT_SKIPPED,
        "source": None,
        "latency": None,
        "grounded": None,
        "notes": [],
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }


def _short(value: str, limit: int = 80) -> str:
    value = (value or "").strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


def evaluate_static(path: Path, spec: dict, ev, root: Path) -> dict:
    """Score one file with the static scanner's own evidence lists."""
    row = _row(path, root, "static", spec)
    named = [item.get("name", "") for item in ev.named_license_functions]
    strings = ev.license_strings
    expected = spec["expect"]

    matched = match_static(expected, named, strings)
    if matched:
        row["answer"] = _short(matched["value"])
        row["source"] = matched["source"]
        row["result"] = RESULT_HIT
        return row

    if named:
        # Only a named function counts as "answering a function"; a license
        # string is evidence, not an answer, so it cannot be a false positive.
        answer = named[0]
        result, note = classify_answer(expected, spec["allow_none"], answer)
        row.update(answer=_short(answer), result=result, source="named_functions")
        if note:
            row["notes"].append(note)
        if len(named) > 1:
            row["notes"].append(f"{len(named)} named licence function(s) reported")
        if strings:
            row["notes"].append(f"{len(strings)} license string(s) visible")
        return row

    result, note = classify_answer(expected, spec["allow_none"], "none")
    row.update(answer="none", result=result, source="none")
    if note:
        row["notes"].append(note)
    if strings:
        row["notes"].append(f"{len(strings)} license string(s) visible but no named function")
    return row


def evaluate_ai(path: Path, spec: dict, ev, root: Path) -> dict:
    """Score one file with a real model call. Never use success/grounded as truth."""
    from scanner.ai import measure

    row = _row(path, root, "ai", spec)
    try:
        result = measure(ev)
    except Exception as err:  # a broken pack must not abort the whole paid run
        row["notes"].append(f"AI_ERROR: {type(err).__name__}: {err}")
        return row
    if result.get("error"):
        row["notes"].append(f"{result.get('error_code') or 'AI_ERROR'}: {result['error']}")
        return row

    value = parse_function_value(result.get("output_sample", ""))
    code, note = classify_answer(spec["expect"], spec["allow_none"], value)
    row.update(
        answer=_short(value) if value else "none",
        result=code,
        source="ai",
        latency=result.get("seconds"),
        grounded=result.get("grounded"),
    )
    if note:
        row["notes"].append(note)
    if not value:
        row["notes"].append(
            "no FUNCTION: value in output_sample (measure() exposes only the first 400 chars)"
        )
    usage = result.get("usage") or {}
    row["prompt_tokens"] = usage.get("prompt_tokens") or usage.get("input_tokens") or 0
    row["completion_tokens"] = usage.get("completion_tokens") or usage.get("output_tokens") or 0
    # Diagnostic only: ai.py's `success` means "named something grounded", not
    # "named the labelled check". Keep the disagreement visible.
    ai_success = bool(result.get("success"))
    if ai_success != (code == RESULT_HIT):
        row["notes"].append(
            f"diagnostic only: ai.py success={ai_success} grounded={result.get('grounded')} "
            f"disagrees with label result={code}"
        )
    return row


# ----------------------------------------------------------------------- output


def _pct(rate: float | None) -> str:
    return "n/a" if rate is None else f"{rate * 100:.1f}%"


def _pad(text: str, width: int) -> str:
    text = str(text)
    if len(text) > width:
        text = text[: max(0, width - 1)] + "…"
    return text.ljust(width)


def _summary_line(label: str, summary: dict) -> str:
    return (
        f"{label:<8} evaluated {summary['evaluated']} · hit {summary['hits']} · "
        f"hit_rate {_pct(summary['hit_rate'])} · FP {summary['false_positives']} · "
        f"FN {summary['false_negatives']} · correct_none {summary['correct_none']} · "
        f"skipped {summary['skipped']}"
    )


def render_human(payload: dict) -> str:
    lines = [
        "TrapKey ground-truth benchmark",
        f"corpus: {payload['corpus']}",
        f"labels: {payload['labels']}",
        f"modes:  {', '.join(payload['modes'])}",
    ]
    if payload.get("provider"):
        lines.append(f"model:  {payload['provider']}")
    lines.append("")

    table = [("file", "mode", "expected", "answer", "result", "source", "grounded", "latency")]
    for row in payload["rows"]:
        expected = row.get("expected")
        if expected is None:
            expected_text = "(unlabeled)"
        elif expected:
            expected_text = ", ".join(expected)
        else:
            expected_text = "(none)"
        grounded = row.get("grounded")
        grounded_text = "—" if grounded is None else ("yes" if grounded else "no")
        table.append(
            (
                row["file"],
                row["mode"],
                expected_text,
                row.get("answer") or "—",
                row["result"],
                row.get("source") or "—",
                grounded_text,
                f"{row['latency']:.2f}s" if isinstance(row.get("latency"), (int, float)) else "—",
            )
        )
    caps = (34, 7, 30, 30, 15, 22, 8, 9)
    widths = [
        min(max(len(row[column]) for row in table), caps[column])
        for column in range(len(caps))
    ]
    lines.append("  ".join(_pad(table[0][column], widths[column]) for column in range(len(caps))).rstrip())
    lines.append("  ".join("-" * widths[column] for column in range(len(caps))))
    for row in table[1:]:
        lines.append("  ".join(_pad(row[column], widths[column]) for column in range(len(caps))).rstrip())
    lines.append("")

    noted = [row for row in payload["rows"] if row.get("notes")]
    if noted:
        lines.append("notes:")
        for row in noted[:20]:
            lines.append(f"  {row['file']} [{row['mode']}]: " + "; ".join(row["notes"]))
        if len(noted) > 20:
            lines.append(f"  ... {len(noted) - 20} more rows with notes (see --json)")
        lines.append("")

    for mode in payload["modes"]:
        summary = payload["by_mode"][mode]
        lines.append(_summary_line(mode, summary))
        if mode == "ai" and summary.get("median_latency_seconds") is not None:
            lines.append(
                f"         latency median {summary['median_latency_seconds']:.2f}s · "
                f"p95 {summary['p95_latency_seconds']:.2f}s · "
                f"prompt {summary['prompt_tokens']:,} tok · "
                f"completion {summary['completion_tokens']:,} tok"
            )
    if len(payload["modes"]) > 1:
        lines.append(_summary_line("overall", payload["summary"]))
        overall = payload["summary"]
        if overall.get("prompt_tokens") or overall.get("completion_tokens"):
            lines.append(
                f"tokens   prompt {overall['prompt_tokens']:,} · "
                f"completion {overall['completion_tokens']:,}"
            )
    lines.append("")
    lines.append(
        "legend: hit = matched a label (or correctly said none when labels expect no check) · "
        "miss = none while a check was expected · false_positive = named something not in the labels"
    )
    lines.append(
        "correctness comes from the labels; ai.py success/grounded are diagnostics only."
    )

    warnings = payload.get("warnings") or []
    if warnings:
        lines.append("")
        lines.append(f"warnings ({len(warnings)}):")
        for warning in warnings[:20]:
            lines.append(f"  - {warning}")
        if len(warnings) > 20:
            lines.append(f"  ... {len(warnings) - 20} more (see --json)")
    return "\n".join(lines)


# -------------------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--corpus", required=True, help="directory to walk for .exe/.dll/.bin/.sys")
    ap.add_argument("--labels", required=True, help="labels JSON (see benchmarks/README.md)")
    ap.add_argument("--static", action="store_true", help="score named functions + license strings")
    ap.add_argument("--ai", action="store_true", help="call scanner.ai.measure() per file")
    ap.add_argument("--limit", type=int, default=None, help="evaluate at most N discovered files")
    ap.add_argument("--json", action="store_true", help="print one JSON object")
    ap.add_argument("--out", help="write the same JSON object to this file")
    args = ap.parse_args(argv)

    # "Default static": only an explicit --ai switches the default off.
    modes = [mode for mode, enabled in (("static", args.static or not args.ai), ("ai", args.ai)) if enabled]
    if args.limit is not None and args.limit < 1:
        print("error: --limit must be >= 1", file=sys.stderr)
        return 2

    corpus = Path(args.corpus)
    if not corpus.is_dir():
        print(f"error: corpus directory not found: {corpus}", file=sys.stderr)
        return 2

    try:
        labels = load_labels(args.labels)
    except LabelError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    files = discover_corpus(corpus, args.limit)
    if not files:
        print(
            f"error: no .exe/.dll/.bin/.sys files >= {MIN_SIZE:,} bytes under {corpus}",
            file=sys.stderr,
        )
        return 2

    provider = None
    if "ai" in modes:
        from scanner.ai import AIConfigError, resolve_config

        try:
            cfg = resolve_config()
        except AIConfigError as err:
            print(f"error: {err}", file=sys.stderr)
            return 2
        provider = f"{cfg['provider']}:{cfg['model']}" + (" (local)" if cfg["local"] else "")

    index = _label_index(labels)
    warnings: list[str] = []
    for base, entries in index[1].items():
        if len(entries) > 1:
            keys = ", ".join(repr(key) for key, _ in entries)
            warnings.append(
                f"labels share the basename {base!r} ({keys}); use relative paths to disambiguate"
            )
    rows: list[dict] = []
    labelled_files = 0

    for path in files:
        entry = find_label(path, corpus, index)
        if entry is None:
            warnings.append(f"no labels for {path.relative_to(corpus).as_posix()} (skipped)")
            for mode in modes:
                row = _row(path, corpus, mode, {"expect": [], "allow_none": False})
                # Null (not []) so the output cannot be read as "ground truth:
                # this binary has no licence check" when it simply has no label.
                row["expected"] = None
                row["allow_none"] = None
                row["notes"].append("no labels for this file")
                rows.append(row)
            continue

        labelled_files += 1
        _label_key, spec = entry
        try:
            ev = collect(str(path))
        except (PEError, OSError) as err:
            warnings.append(f"cannot read {path.relative_to(corpus).as_posix()}: {err}")
            for mode in modes:
                row = _row(path, corpus, mode, spec)
                row["notes"].append(f"engine could not read this file: {err}")
                rows.append(row)
            continue

        # `collect()` turns a non-PE into a "native" evidence object so the web
        # can still show something. In a ground-truth benchmark that would be
        # scored as a miss (and sent to a paid provider); skip it instead.
        if ev.pe is None:
            warnings.append(f"not a PE file: {path.relative_to(corpus).as_posix()}")
            for mode in modes:
                row = _row(path, corpus, mode, spec)
                row["notes"].append("not a PE file")
                rows.append(row)
            continue

        # Collect once, score with whichever modes were asked for.
        if "static" in modes:
            rows.append(evaluate_static(path, spec, ev, corpus))
        if "ai" in modes:
            rows.append(evaluate_ai(path, spec, ev, corpus))
            if rows[-1]["result"] == RESULT_SKIPPED:
                warnings.append(
                    f"AI call skipped {path.relative_to(corpus).as_posix()}: "
                    f"{rows[-1]['notes'][0] if rows[-1]['notes'] else 'unknown error'}"
                )

    if labelled_files == 0:
        print(
            "error: none of the discovered files has a label entry "
            "(labels must be keyed by relative path or basename)",
            file=sys.stderr,
        )
        return 2

    discovered_rel = {path.relative_to(corpus).as_posix().casefold() for path in files}
    discovered_names = {path.name.casefold() for path in files}
    for key in labels:
        cleaned = _clean_label_key(key)
        if cleaned.casefold() not in discovered_rel and cleaned.rsplit("/", 1)[-1].casefold() not in discovered_names:
            suffix = " (discovery was cut by --limit)" if args.limit else ""
            warnings.append(f"label {key!r} does not match any discovered file{suffix}")

    by_mode = {mode: summarize([row for row in rows if row["mode"] == mode]) for mode in modes}
    payload = {
        "ok": True,
        "corpus": str(corpus),
        "labels": str(args.labels),
        "modes": modes,
        "provider": provider,
        "summary": summarize(rows),
        "by_mode": by_mode,
        "rows": rows,
        "warnings": warnings,
    }

    if args.out:
        try:
            Path(args.out).write_text(
                json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except OSError as err:
            print(f"error: cannot write {args.out}: {err}", file=sys.stderr)
            return 2
        print(f"wrote {args.out}", file=sys.stderr)

    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(render_human(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
