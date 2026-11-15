"""Minimal IL decoder for the evidence pack.

An agent that is handed only strings + method *names* still has to guess what a
method does. Frontier models refuse to invent a licence check from names alone,
so the pack now carries the decoded bodies of the methods that reference
licensing strings. This is not a full disassembler: it decodes every opcode and
resolves metadata tokens (strings, methods, fields), and that is enough for a
model to recognise `ldstr "licence is invalid"` followed by a comparison and a
branch.
"""

from __future__ import annotations

from typing import Callable

# operand kinds: None, i8, u16, i32, i64, r4, r8, token, br8, br32, switch
ONE: dict[int, tuple[str, str | None]] = {}


def _ops(start: int, rows: list[tuple[str, str | None]]) -> None:
    for i, row in enumerate(rows):
        ONE[start + i] = row


_ops(0x00, [
    ("nop", None), ("break", None), ("ldarg.0", None), ("ldarg.1", None),
    ("ldarg.2", None), ("ldarg.3", None), ("ldloc.0", None), ("ldloc.1", None),
    ("ldloc.2", None), ("ldloc.3", None), ("stloc.0", None), ("stloc.1", None),
    ("stloc.2", None), ("stloc.3", None), ("ldarg.s", "u8"), ("ldarga.s", "u8"),
    ("starg.s", "u8"), ("ldloc.s", "u8"), ("ldloca.s", "u8"), ("stloc.s", "u8"),
    ("ldnull", None), ("ldc.i4.m1", None), ("ldc.i4.0", None), ("ldc.i4.1", None),
    ("ldc.i4.2", None), ("ldc.i4.3", None), ("ldc.i4.4", None), ("ldc.i4.5", None),
    ("ldc.i4.6", None), ("ldc.i4.7", None), ("ldc.i4.8", None), ("ldc.i4.s", "i8"),
    ("ldc.i4", "i32"), ("ldc.i8", "i64"), ("ldc.r4", "r4"), ("ldc.r8", "r8"),
])
ONE[0x24] = ("unused", None)
_ops(0x25, [
    ("dup", None), ("pop", None), ("jmp", "token"), ("call", "token"),
    ("calli", "token"), ("ret", None), ("br.s", "br8"), ("brfalse.s", "br8"),
    ("brtrue.s", "br8"), ("beq.s", "br8"), ("bge.s", "br8"), ("bgt.s", "br8"),
    ("ble.s", "br8"), ("blt.s", "br8"), ("bne.un.s", "br8"), ("bge.un.s", "br8"),
    ("bgt.un.s", "br8"), ("ble.un.s", "br8"), ("blt.un.s", "br8"), ("br", "br32"),
])
_ops(0x39, [
    ("brfalse", "br32"), ("brtrue", "br32"), ("beq", "br32"), ("bge", "br32"),
    ("bgt", "br32"), ("ble", "br32"), ("blt", "br32"), ("bne.un", "br32"),
    ("bge.un", "br32"), ("bgt.un", "br32"), ("ble.un", "br32"), ("blt.un", "br32"),
    ("switch", "switch"),
])
_ops(0x46, [
    ("ldind.i1", None), ("ldind.u1", None), ("ldind.i2", None), ("ldind.u2", None),
    ("ldind.i4", None), ("ldind.u4", None), ("ldind.i8", None), ("ldind.i", None),
    ("ldind.r4", None), ("ldind.r8", None), ("ldind.ref", None), ("stind.ref", None),
    ("stind.i1", None), ("stind.i2", None), ("stind.i4", None), ("stind.i8", None),
    ("stind.r4", None), ("stind.r8", None), ("add", None), ("sub", None),
    ("mul", None), ("div", None), ("div.un", None), ("rem", None),
    ("rem.un", None), ("and", None), ("or", None), ("xor", None),
    ("shl", None), ("shr", None), ("shr.un", None), ("neg", None),
    ("not", None), ("conv.i1", None), ("conv.i2", None), ("conv.i4", None),
    ("conv.i8", None), ("conv.r4", None), ("conv.r8", None), ("conv.u4", None),
    ("conv.u8", None),
])
_ops(0x6F, [
    ("callvirt", "token"), ("cpobj", "token"), ("ldobj", "token"),
    ("ldstr", "token"), ("newobj", "token"), ("castclass", "token"),
    ("isinst", "token"), ("conv.r.un", None), ("unused", None), ("unused", None),
    ("unbox", "token"), ("throw", None), ("ldfld", "token"), ("ldflda", "token"),
    ("stfld", "token"), ("ldsfld", "token"), ("ldsflda", "token"), ("stsfld", "token"),
    ("stobj", "token"),
])
_ops(0x82, [
    ("conv.ovf.i1.un", None), ("conv.ovf.i2.un", None), ("conv.ovf.i4.un", None),
    ("conv.ovf.i8.un", None), ("conv.ovf.u1.un", None), ("conv.ovf.u2.un", None),
    ("conv.ovf.u4.un", None), ("conv.ovf.u8.un", None), ("conv.ovf.i.un", None),
    ("conv.ovf.u.un", None), ("box", "token"), ("newarr", "token"), ("ldlen", None),
    ("ldelema", "token"),
])
_ops(0x90, [
    ("ldelem.i1", None), ("ldelem.u1", None), ("ldelem.i2", None), ("ldelem.u2", None),
    ("ldelem.i4", None), ("ldelem.u4", None), ("ldelem.i8", None), ("ldelem.i", None),
    ("ldelem.r4", None), ("ldelem.r8", None), ("ldelem.ref", None), ("stelem.i", None),
    ("stelem.i1", None), ("stelem.i2", None), ("stelem.i4", None), ("stelem.i8", None),
    ("stelem.r4", None), ("stelem.r8", None), ("stelem.ref", None),
    ("ldelem", "token"), ("stelem", "token"), ("unbox.any", "token"),
])
_ops(0xB3, [
    ("conv.ovf.i1", None), ("conv.ovf.u1", None), ("conv.ovf.i2", None),
    ("conv.ovf.u2", None), ("conv.ovf.i4", None), ("conv.ovf.u4", None),
    ("conv.ovf.i8", None), ("conv.ovf.u8", None),
])
_ops(0xC2, [("refanyval", "token"), ("ckfinite", None), ("unused", None), ("unused", None)])
_ops(0xC6, [("mkrefany", "token")])
_ops(0xD0, [
    ("ldtoken", "token"), ("conv.u2", None), ("conv.u1", None), ("conv.i", None),
    ("conv.ovf.i", None), ("conv.ovf.u", None), ("add.ovf", None), ("add.ovf.un", None),
    ("mul.ovf", None), ("mul.ovf.un", None), ("sub.ovf", None), ("sub.ovf.un", None),
    ("endfinally", None), ("leave", "br32"), ("leave.s", "br8"), ("stind.i", None),
    ("conv.u", None),
])

TWO: dict[int, tuple[str, str | None]] = {}


def _ops2(start: int, rows: list[tuple[str, str | None]]) -> None:
    for i, row in enumerate(rows):
        TWO[start + i] = row


_ops2(0x00, [
    ("arglist", None), ("ceq", None), ("cgt", None), ("cgt.un", None),
    ("clt", None), ("clt.un", None), ("ldftn", "token"), ("ldvirtftn", "token"),
    ("unused", None), ("ldarg", "u16"), ("ldarga", "u16"), ("starg", "u16"),
    ("ldloc", "u16"), ("ldloca", "u16"), ("stloc", "u16"), ("localloc", None),
    ("unused", None), ("endfilter", None), ("unaligned.", "u8"), ("volatile.", None),
    ("tail.", None), ("initobj", "token"), ("constrained.", "token"), ("cpblk", None),
    ("initblk", None), ("no.", "u8"), ("rethrow", None), ("unused", None),
    ("sizeof", "token"), ("refanytype", None), ("readonly.", None),
])


def _quote(text: str, limit: int = 160) -> str:
    out = []
    for ch in text[:limit]:
        if ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ord(ch) < 0x20:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    if len(text) > limit:
        out.append("...")
    return '"' + "".join(out) + '"'


def disassemble(
    body: bytes,
    resolve: Callable[[int], str],
    max_instructions: int = 400,
) -> list[str]:
    """Decode IL into `IL_0000: opcode operand` lines.

    Unknown bytes stop decoding instead of being guessed: a wrong decode is worse
    evidence than a short, truthful one.
    """
    out: list[str] = []
    i = 0
    n = len(body)
    while i < n and len(out) < max_instructions:
        start = i
        op = body[i]
        i += 1
        kind = None
        if op == 0xFE:
            if i >= n:
                break
            op2 = body[i]
            i += 1
            entry = TWO.get(op2)
            if not entry:
                out.append(f"IL_{start:04x}: .byte 0xfe 0x{op2:02x}")
                break
            name, kind = entry
        else:
            entry = ONE.get(op)
            if not entry:
                out.append(f"IL_{start:04x}: .byte 0x{op:02x}")
                break
            name, kind = entry

        text = f"IL_{start:04x}: {name}"
        if kind is None:
            out.append(text)
            continue

        # Slices past the end are silently short in Python, which decoded garbage
        # tokens at the end of a body. Fail loudly instead.
        def take(width: int) -> bytes:
            if i + width > n:
                raise ValueError("truncated operand")
            return body[i:i + width]

        try:
            if kind == "u8":
                operand = take(1)[0]
                i += 1
                text += f" {operand}"
            elif kind == "i8":
                value = take(1)[0]
                i += 1
                text += f" {value - 256 if value >= 128 else value}"
            elif kind == "u16":
                value = int.from_bytes(take(2), "little")
                i += 2
                text += f" {value}"
            elif kind == "i32":
                value = int.from_bytes(take(4), "little", signed=True)
                i += 4
                text += f" {value}"
            elif kind == "i64":
                value = int.from_bytes(take(8), "little", signed=True)
                i += 8
                text += f" {value}"
            elif kind in ("r4", "r8"):
                import struct

                raw = take(4 if kind == "r4" else 8)
                i += len(raw)
                value = struct.unpack("<f" if kind == "r4" else "<d", raw)[0]
                text += f" {value:g}"
            elif kind in ("br8", "br32"):
                width = 1 if kind == "br8" else 4
                delta = int.from_bytes(take(width), "little", signed=True)
                i += width
                text += f" IL_{i + delta:04x}"
            elif kind == "switch":
                count = int.from_bytes(take(4), "little", signed=True)
                i += 4
                targets = []
                for _ in range(max(0, min(count, 256))):
                    delta = int.from_bytes(take(4), "little", signed=True)
                    i += 4
                    targets.append(f"IL_{i + delta:04x}")
                text += " (" + ", ".join(targets) + ")"
            elif kind == "token":
                token = int.from_bytes(take(4), "little")
                i += 4
                resolved = resolve(token)
                if name == "ldstr" and resolved:
                    text += " " + _quote(resolved)
                else:
                    text += " " + (resolved or f"token(0x{token:08x})")
        except ValueError:
            out.append(text + " <truncated>")
            break
        out.append(text)
    if i < n and len(out) >= max_instructions:
        out.append(f"IL_{i:04x}: ... ({n - i} bytes truncated)")
    return out


# --------------------------------------------------------------------------- #
# Method selection for the evidence pack
# --------------------------------------------------------------------------- #

MAX_CODE_METHODS = 4
MAX_SCAN_BYTES = 8_000_000


def _licence_string_tokens(dotnet) -> dict[int, str]:
    """#US tokens whose text mentions licensing. These are the operands an agent
    would grep for, so a body containing one is worth showing."""
    from .evidence import LICENSE_WORDS

    tokens: dict[int, str] = {}
    for token, text in dotnet.user_strings(8000):
        if LICENSE_WORDS.search(text):
            tokens[token] = text
            if len(tokens) >= 400:
                break
    return tokens


def _string_refs(body: bytes, tokens: dict[int, str]) -> list[int]:
    """Find `ldstr` (0x72) operands that point at licensing strings."""
    hits: list[int] = []
    pos = body.find(b"\x72")
    while pos >= 0 and len(hits) < 3:
        raw = body[pos + 1:pos + 5]
        if len(raw) == 4:
            token = int.from_bytes(raw, "little")
            if token in tokens:
                hits.append(token)
        pos = body.find(b"\x72", pos + 1)
    return hits


def dotnet_code(
    dotnet,
    budget_chars: int = 18_000,
    max_methods: int = MAX_CODE_METHODS,
    max_scan_bytes: int = MAX_SCAN_BYTES,
) -> str:
    """Render the most licence-relevant .NET method bodies for the AI pack.

    Selection is what an agent does with a decompiler: grep the name table, then
    grep the user-string heap for licence text and follow the `ldstr` tokens.
    """
    if not dotnet or not dotnet.ok or not dotnet.methods:
        return ""

    by_rva = {m["rva"]: i + 1 for i, m in enumerate(dotnet.methods) if m["rva"]}
    chosen: list[tuple[int, str]] = []  # (method index, why)
    seen: set[int] = set()

    # A body that loads a licensing string is stronger evidence than a name that
    # merely looks like licensing (`TrialDivision` in mscorlib is maths), so
    # xrefs are selected first and names only fill the remaining slots.
    tokens = _licence_string_tokens(dotnet)
    scanned = 0
    if tokens:
        for idx, m in enumerate(dotnet.methods, start=1):
            if len(chosen) >= max_methods or scanned >= max_scan_bytes:
                break
            if idx in seen or not m["rva"]:
                continue
            body = dotnet.method_body(m["rva"])
            if not body:
                continue
            scanned += len(body)
            refs = _string_refs(body, tokens)
            if refs:
                chosen.append((idx, f"references {tokens[refs[0]][:80]!r}"))
                seen.add(idx)

    for m in dotnet.license_methods():
        if len(chosen) >= max_methods:
            break
        idx = by_rva.get(m["rva"])
        if idx and idx not in seen:
            chosen.append((idx, "named after licensing"))
            seen.add(idx)

    if not chosen:
        return ""

    header = (
        f"code (.NET IL; {len(chosen)} method bodies, selected by name and by "
        f"licence-string xrefs):"
    )
    blocks = [header]
    used = len(header)
    for idx, reason in chosen:
        body = dotnet.method_body(dotnet.methods[idx - 1]["rva"])
        if not body:
            continue
        lines = disassemble(body, dotnet.resolve_token, max_instructions=120)
        name = dotnet.resolve_token(0x06000000 | idx)
        block = "\n".join(
            [f"method: {name} — {reason} ({len(body)} IL bytes)"]
            + ["  " + line for line in lines]
        )
        if used + len(block) > budget_chars:
            break
        blocks.append(block)
        used += len(block) + 2
    return "\n\n".join(blocks)

