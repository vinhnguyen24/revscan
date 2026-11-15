"""Native code evidence: the functions that touch licence strings.

The evidence pack used to stop at strings and import names, so a frontier model
would answer "insufficient evidence" on any native binary (see
docs/CALIBRATION.md §8). This module gives it actual instructions.

No Python dependency is added: GNU objdump is used when it is installed, and
the feature degrades to "no code evidence" when it is not. The selection is
xref-driven on purpose — dumping the whole .text section would blow the token
budget and tell the model nothing about where to look:

    licence strings -> their virtual addresses -> instructions that reference
    them (rip-relative) -> the function containing that instruction

The same pass annotates calls into the import table, so
`call QWORD PTR [rip+0x...]` becomes `; ->CRYPT32!CryptVerifySignatureA`.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from collections import deque

from .evidence import CRYPTO_IMPORTS, LICENSE_WORDS
from .ident import is_license_ident
from .peinfo import PEInfo

MAX_SCAN_BYTES = 6_000_000
MAX_FUNCTIONS = 4
MAX_LINES_PER_FUNCTION = 70
MAX_STRINGS = 24
WINDOW_BACK = 0x100
WINDOW_FORWARD = 0x300

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\s+(.+?)\s*$")
COMMENT_RE = re.compile(r"#\s*0x([0-9a-fA-F]+)")


def engine() -> str | None:
    return shutil.which("objdump")


def _text_sections(pe: PEInfo) -> list[dict]:
    return [
        s for s in pe.sections
        if s["executable"] and s["name"] not in (".pdata", ".reloc", ".textbss")
        and s["rawsize"] > 0 and s["vsize"] > 0
    ]


def _string_addresses(pe: PEInfo, strings: list[str]) -> dict[int, str]:
    """Virtual address -> string, for licence strings that live in data."""
    data = pe.data
    out: dict[int, str] = {}
    sections = [s for s in pe.sections if not s["executable"] and s["rawsize"] > 0]
    for text in strings:
        if len(out) >= MAX_STRINGS:
            break
        if len(text) < 6 or not LICENSE_WORDS.search(text):
            continue
        needles = [text.encode("latin-1", "ignore"), text.encode("utf-16-le", "ignore")]
        found = False
        for section in sections:
            start = section["rawptr"]
            raw = data[start:start + section["rawsize"]]
            for needle in needles:
                if len(needle) < 6:
                    continue
                idx = raw.find(needle)
                if idx >= 0:
                    out[pe.image_base + section["vaddr"] + idx] = text
                    found = True
                    break
            if found:
                break
    return out


def _containing(ranges: list[tuple[int, int]], rva: int) -> tuple[int, int] | None:
    lo, hi = 0, len(ranges) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        begin, end = ranges[mid]
        if rva < begin:
            hi = mid - 1
        elif rva >= end:
            lo = mid + 1
        else:
            return begin, end
    return None


def _comment_target(text: str) -> int | None:
    match = COMMENT_RE.search(text)
    return int(match.group(1), 16) if match else None


def _window(ranges: list[tuple[int, int]], rva: int) -> tuple[int, int]:
    hit = _containing(ranges, rva)
    if hit:
        return hit
    return (max(0, rva - WINDOW_BACK), rva + WINDOW_FORWARD)


def _run_objdump(path: str, start_va: int, stop_va: int, timeout: float) -> list[str]:
    exe = engine()
    if not exe:
        return []
    cmd = [
        exe, "-d", "--no-show-raw-insn", "-M", "intel",
        f"--start-address=0x{start_va:x}", f"--stop-address=0x{stop_va:x}", path,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return []
    if proc.returncode != 0 and not proc.stdout:
        return []
    return proc.stdout.decode("utf-8", "ignore").splitlines()


def _render_range(
    pe: PEInfo, path: str, begin: int, end: int, timeout: float,
) -> list[tuple[int, str]]:
    if end <= begin:
        return []
    out: list[tuple[int, str]] = []
    for line in _run_objdump(path, pe.image_base + begin, pe.image_base + end, timeout):
        match = LINE_RE.match(line)
        if not match:
            continue
        text = match.group(2)
        if text.startswith("<") and text.endswith(">:"):
            continue
        out.append((int(match.group(1), 16) - pe.image_base, text))
        if len(out) >= MAX_LINES_PER_FUNCTION:
            break
    return out


def _printable(text: str) -> bool:
    if not text:
        return False
    good = sum(1 for ch in text if 0x20 <= ord(ch) < 0x7F)
    return good / len(text) >= 0.9


def _target_text(pe: PEInfo, va: int, limit: int = 90) -> str:
    """Best-effort string at a referenced address (ASCII, then UTF-16LE).

    Annotating only the licence string leaves the surrounding format strings
    opaque; those are usually what the check compares against.
    """
    rva = va - pe.image_base
    if rva <= 0:
        return ""
    section = pe.section_for_rva(rva)
    if not section or section["executable"] or section.get("writable"):
        return ""
    text = pe.cstring_at_rva(rva, limit)
    if len(text) >= 4 and _printable(text):
        return text
    off = pe.rva_to_offset(rva)
    if off is None:
        return ""
    raw = pe.data[off:off + limit * 2]
    chars: list[str] = []
    for i in range(0, len(raw) - 1, 2):
        lo, hi = raw[i], raw[i + 1]
        if lo == 0 and hi == 0:
            break
        if hi != 0 or not (0x20 <= lo < 0x7F):
            return ""
        chars.append(chr(lo))
    return "".join(chars) if len(chars) >= 4 else ""


def _annotate(
    text: str, pe: PEInfo, strings: dict[int, str], iat: dict[int, str], exports: dict[int, str],
) -> str:
    match = COMMENT_RE.search(text)
    if not match:
        return text
    target = int(match.group(1), 16)
    if target in strings:
        return f"{text}  ; {strings[target][:120]!r}"
    if target in iat:
        return f"{text}  ; -> {iat[target]}"
    if target in exports:
        return f"{text}  ; -> {exports[target]}"
    literal = _target_text(pe, target)
    if literal:
        return f"{text}  ; {literal[:120]!r}"
    return text


def disassemble(pe: PEInfo, strings: list[str], path: str, timeout: float = 20.0) -> dict:
    """Return {'engine', 'functions': [{'name','reason','lines'}], 'scanned_bytes'}."""
    if not engine() or not pe:
        return {"engine": None, "functions": [], "scanned_bytes": 0}

    string_vas = _string_addresses(pe, strings)
    iat = {pe.image_base + slot: name for slot, name in pe.import_slots().items()}
    exports = {
        pe.image_base + rva: name
        for name, rva in pe.export_entries() if rva
    }
    ranges = pe.function_ranges()

    sections = _text_sections(pe)
    scanned = 0
    deadline = time.monotonic() + timeout
    hits: dict[int, dict] = {}  # function begin (rva) -> {end, reason, lines}
    active: dict[int, dict] = {}
    recent: deque[tuple[int, str]] = deque(maxlen=600)
    # Functions that call into the crypto API are the next best pointer when
    # the licence strings are encrypted or built at runtime.
    crypto_iat = {
        va: name for va, name in iat.items()
        if any(c in name.lower() for c in CRYPTO_IMPORTS)
    }
    crypto_candidates: list[tuple[int, str]] = []

    def finish(now_va: int | None = None) -> None:
        for begin in list(active):
            entry = active[begin]
            if now_va is None or now_va >= entry["end_va"]:
                if entry["lines"]:
                    hits[begin] = entry
                del active[begin]

    for section in sections:
        remaining = deadline - time.monotonic()
        if scanned >= MAX_SCAN_BYTES or len(hits) >= MAX_FUNCTIONS or remaining <= 0:
            break
        span = min(max(section["vsize"], section["rawsize"]), MAX_SCAN_BYTES - scanned)
        start_va = pe.image_base + section["vaddr"]
        stop_va = start_va + span
        for line in _run_objdump(path, start_va, stop_va, remaining):
            match = LINE_RE.match(line)
            if not match:
                continue
            addr = int(match.group(1), 16)
            text = match.group(2)
            if text.startswith("<") and text.endswith(">:"):
                continue  # symbol label emitted by objdump, not an instruction
            rva = addr - pe.image_base
            recent.append((rva, text))

            target = _comment_target(text)
            if target is not None and target in crypto_iat and len(crypto_candidates) < 8:
                crypto_candidates.append((rva, crypto_iat[target]))

            finish(addr)

            if target is not None and target in string_vas and len(hits) + len(active) < MAX_FUNCTIONS:
                begin, end = _window(ranges, rva)
                end = min(end, begin + 0x2000)
                if begin not in hits and begin not in active:
                    seeded = [
                        (a, t) for a, t in recent
                        if begin <= a < end
                    ]
                    active[begin] = {
                        "end_va": pe.image_base + end,
                        "begin_rva": begin,
                        "reason": f"references {string_vas[target][:80]!r}",
                        "lines": seeded,
                    }
                    continue

            for entry in active.values():
                if entry["begin_rva"] <= rva < entry["end_va"] - pe.image_base:
                    if len(entry["lines"]) < MAX_LINES_PER_FUNCTION:
                        entry["lines"].append((rva, text))
                    break

        scanned += span
        if len(hits) >= MAX_FUNCTIONS:
            break

    finish()

    if len(hits) < MAX_FUNCTIONS:
        # Fill the remaining slots in order of signal: crypto API calls, then a
        # named export, then the entry point. When a string xref already hit, the
        # crypto function is still useful context and does not push it out.
        fallback: list[tuple[str, int]] = []
        for rva, name in crypto_candidates:
            fallback.append((f"calls {name}", rva))
            if len(fallback) >= 2:
                break
        if not hits:
            for name, rva in licence_export_candidates(pe):
                fallback.append((f"named export {name}", rva))
                if len(fallback) >= MAX_FUNCTIONS:
                    break
            if not fallback and pe.entry_rva:
                fallback.append(("process entry point", pe.entry_rva))

        for reason, rva in fallback[:MAX_FUNCTIONS - len(hits)]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            begin, end = _window(ranges, rva)
            if begin in hits:
                continue
            end = min(end, begin + 0x800)
            entry_lines = _render_range(pe, path, begin, end, remaining)
            if entry_lines:
                hits[begin] = {
                    "begin_rva": begin,
                    "reason": reason,
                    "lines": entry_lines,
                }

    def render(entry: dict) -> dict:
        lines = entry["lines"][:MAX_LINES_PER_FUNCTION]
        rendered = [
            f"{pe.image_base + a:x}: {_annotate(t, pe, string_vas, iat, exports)}"
            for a, t in lines
        ]
        if len(entry["lines"]) > MAX_LINES_PER_FUNCTION:
            rendered.append(f"  ... ({len(entry['lines']) - MAX_LINES_PER_FUNCTION} more lines)")
        return {
            "name": f"sub_{entry['begin_rva']:x}",
            "reason": entry["reason"],
            "lines": rendered,
        }

    functions = [render(hits[k]) for k in sorted(hits)[:MAX_FUNCTIONS]]
    return {"engine": "objdump", "functions": functions, "scanned_bytes": scanned}


def native_code(pe: PEInfo, strings: list[str], path: str, budget_chars: int = 20_000,
                timeout: float = 20.0) -> str:
    """Text block for the AI evidence pack. Empty when nothing can be read."""
    try:
        result = disassemble(pe, strings, path, timeout=timeout)
    except Exception:
        # Evidence collection must never break a scan: a malformed PE or a
        # missing objdump just means "no code in the pack".
        return ""
    functions = result.get("functions") or []
    if not functions:
        return ""

    header = (
        f"code (native, objdump; {result['scanned_bytes'] / 1e6:.1f} MB of executable "
        f"sections scanned):"
    )
    blocks = [header]
    used = len(header)
    for fn in functions:
        block = [f"function {fn['name']} — {fn['reason']}"]
        block += ["  " + line for line in fn["lines"]]
        text = "\n".join(block)
        if used + len(text) > budget_chars:
            break
        blocks.append(text)
        used += len(text) + 2
    return "\n\n".join(blocks)


def licence_export_candidates(pe: PEInfo) -> list[tuple[str, int]]:
    """Exports named after licensing: a native grep hit that needs no xref."""
    return [(name, rva) for name, rva in pe.export_entries() if rva and is_license_ident(name)]
