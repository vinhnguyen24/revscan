"""Minimal ECMA-335 metadata reader.

Why this matters for the scan: a .NET assembly carries the *names* of every
method. An AI agent does not need to disassemble anything — it reads the method
table, greps for "License"/"Verify", and jumps straight there. Counting those
methods and their IL bytes gives us a real (not guessed) reading budget.

Only the tables needed to reach MethodDef (0x06) and TypeDef (0x02) are decoded
for the scan. TypeRef (0x01) / Field (0x04) / MemberRef (0x0A) are decoded too
because the evidence pack now carries actual method bodies: a `call` token is
useless to a model unless it says `System.String::op_Equality`.
"""

from __future__ import annotations

import struct

from .ident import is_license_ident
from .peinfo import PEInfo, u16, u32

# Coded index kinds: (tag bits, tables referenced)
CODED = {
    "TypeDefOrRef": (2, [0x02, 0x01, 0x1B]),
    "HasConstant": (2, [0x04, 0x08, 0x17]),
    "HasFieldMarshal": (1, [0x04, 0x08]),
    "HasDeclSecurity": (2, [0x02, 0x06, 0x20]),
    "MemberRefParent": (3, [0x02, 0x01, 0x1A, 0x06, 0x1B]),
    "HasSemantics": (1, [0x14, 0x17]),
    "MethodDefOrRef": (1, [0x06, 0x0A]),
    "MemberForwarded": (1, [0x04, 0x06]),
    "Implementation": (2, [0x26, 0x23, 0x27]),
    "CustomAttributeType": (3, [0x06, 0x0A, 0x00, 0x00, 0x00]),
    "ResolutionScope": (2, [0x00, 0x1A, 0x23, 0x01]),
    "TypeOrMethodDef": (1, [0x02, 0x06]),
}

U2, U4, STR, GUID, BLOB = "u2", "u4", "str", "guid", "blob"

TABLES = {
    0x00: [U2, STR, GUID, GUID, GUID],                                    # Module
    0x01: [("coded", "ResolutionScope"), STR, STR],                       # TypeRef
    0x02: [U4, STR, STR, ("coded", "TypeDefOrRef"), ("idx", 0x04), ("idx", 0x06)],  # TypeDef
    0x03: [("idx", 0x04)],                                                # FieldPtr
    0x04: [U2, STR, BLOB],                                                # Field
    0x05: [("idx", 0x06)],                                                # MethodPtr
    0x06: [U4, U2, U2, STR, BLOB, ("idx", 0x08)],                         # MethodDef
    0x07: [("idx", 0x08)],                                                # ParamPtr
    0x08: [U2, U2, STR],                                                  # Param
    0x09: [("idx", 0x02), ("coded", "TypeDefOrRef")],                     # InterfaceImpl
    0x0A: [("coded", "MemberRefParent"), STR, BLOB],                      # MemberRef
}

# The old name is kept: tests/other modules import SCHEMA.
SCHEMA = TABLES


class DotNetInfo:
    def __init__(self, pe: PEInfo):
        self.ok = False
        self.method_count = 0
        self.type_count = 0
        self.total_il_bytes = 0
        self.methods: list[dict] = []
        self.types: list[str] = []
        self._pe = pe
        self._meta = b""
        self._strings = b""
        self._heaps: dict[str, tuple[int, int]] = {}
        self._rows: dict[int, int] = {}
        self._tables: dict[int, tuple[int, int]] = {}
        self._heap_w = {"str": 2, "guid": 2, "blob": 2}
        self._typedefs: list[dict] = []
        self._typerefs: list[dict] = []
        self._memberrefs: list[dict] = []
        self._fields: list[str] = []
        try:
            self._parse()
            self.ok = True
        except Exception:
            self.ok = False

    # ------------------------------------------------------------------ parse

    def _parse(self) -> None:
        pe = self._pe
        cli_rva, cli_size = pe.data_dir(14)
        header = pe.read_rva(cli_rva, 72)
        if not header or len(header) < 72:
            raise ValueError("truncated CLI header")
        meta_rva = u32(header, 8)
        meta_size = u32(header, 12)
        meta = pe.read_rva(meta_rva, meta_size)
        if not meta or meta[:4] != b"BSJB":
            raise ValueError("bad metadata signature")

        pos = 12
        ver_len = u32(meta, pos)
        pos += 4 + ver_len
        pos += 2  # flags
        streams = u16(meta, pos)
        pos += 2

        found: dict[str, tuple[int, int]] = {}
        for _ in range(streams):
            offset = u32(meta, pos)
            size = u32(meta, pos + 4)
            pos += 8
            end = meta.index(b"\0", pos)
            name = meta[pos:end].decode("latin-1")
            pos = end + 1
            pos = (pos + 3) & ~3
            found[name] = (offset, size)

        tables_stream = found.get("#~") or found.get("#-")
        strings_stream = found.get("#Strings")
        if not tables_stream or not strings_stream:
            raise ValueError("missing metadata streams")

        self._meta = meta
        self._heaps = found
        strings = meta[strings_stream[0]:strings_stream[0] + strings_stream[1]]
        self._strings = strings
        self._parse_tables(meta, tables_stream[0], tables_stream[1])

    def _string(self, index: int) -> str:
        if index <= 0 or index >= len(self._strings):
            return ""
        end = self._strings.find(b"\0", index)
        if end < 0:
            end = len(self._strings)
        return self._strings[index:end].decode("utf-8", "ignore")

    def _field_width(self, field) -> int:
        if field == U2:
            return 2
        if field == U4:
            return 4
        if field == STR:
            return self._heap_w["str"]
        if field == GUID:
            return self._heap_w["guid"]
        if field == BLOB:
            return self._heap_w["blob"]
        kind, arg = field
        if kind == "idx":
            return 4 if self._rows.get(arg, 0) >= 0x10000 else 2
        tag_bits, tables = CODED[arg]
        biggest = max((self._rows.get(t, 0) for t in tables), default=0)
        return 2 if biggest < (1 << (16 - tag_bits)) else 4

    def _parse_tables(self, meta: bytes, start: int, size: int) -> None:
        base = start
        # ECMA-335 II.24.2.6: Reserved(4) Major(1) Minor(1) HeapSizes(1)
        # Reserved(1) Valid(8) Sorted(8). The old base+7 read the reserved byte
        # (always 0x01) and gave every index the wrong width on large heaps.
        heap_sizes = meta[base + 6]
        valid = struct.unpack_from("<Q", meta, base + 8)[0]

        rows: dict[int, int] = {}
        pos = base + 24
        for table in range(64):
            if valid & (1 << table):
                rows[table] = u32(meta, pos)
                pos += 4

        self._rows = rows
        self._heap_w = {
            "str": 4 if heap_sizes & 1 else 2,
            "guid": 4 if heap_sizes & 2 else 2,
            "blob": 4 if heap_sizes & 4 else 2,
        }

        # Walk tables in order. Every table before MemberRef must have a known
        # row size, otherwise the MemberRef offsets (needed by `call` tokens)
        # would be wrong.
        self._tables = {}
        table_pos = pos
        for table in range(0, 0x0B):
            if table not in TABLES:
                break
            row_size = sum(self._field_width(f) for f in TABLES[table])
            self._tables[table] = (table_pos, row_size)
            table_pos += row_size * rows.get(table, 0)

        self.method_count = rows.get(0x06, 0)
        self.type_count = rows.get(0x02, 0)

        if 0x02 in self._tables:
            self._read_typedefs()
        if 0x01 in self._tables:
            self._read_typerefs()
        if 0x04 in self._tables:
            self._read_fields()
        if 0x06 in self._tables:
            self._read_methods()
        if 0x0A in self._tables:
            self._read_memberrefs()

    def _cell(self, table: int, row: int, col: int) -> tuple[int, int]:
        start, row_size = self._tables[table]
        pos = start + row * row_size
        columns = TABLES[table]
        for i in range(col):
            pos += self._field_width(columns[i])
        return pos, self._field_width(columns[col])

    def _value(self, table: int, row: int, col: int) -> int:
        pos, width = self._cell(table, row, col)
        if width == 4:
            return u32(self._meta, pos)
        if width == 2:
            return u16(self._meta, pos)
        return 0

    def _decode_coded(self, value: int, kind: str) -> tuple[int, int]:
        tag_bits, tables = CODED[kind]
        return tables[value & ((1 << tag_bits) - 1)], value >> tag_bits

    def _read_typedefs(self) -> None:
        count = self._rows.get(0x02, 0)
        typedefs = []
        for i in range(min(count, 20_000)):
            name = self._string(self._value(0x02, i, 1))
            namespace = self._string(self._value(0x02, i, 2))
            method_start = self._value(0x02, i, 5)
            typedefs.append({"name": name, "namespace": namespace, "method_start": method_start})
        self._typedefs = typedefs
        self.types = [t["name"] for t in typedefs if t["name"]]

    def _read_typerefs(self) -> None:
        count = self._rows.get(0x01, 0)
        refs = []
        for i in range(min(count, 20_000)):
            refs.append({
                "name": self._string(self._value(0x01, i, 1)),
                "namespace": self._string(self._value(0x01, i, 2)),
            })
        self._typerefs = refs

    def _read_fields(self) -> None:
        count = self._rows.get(0x04, 0)
        self._fields = [self._string(self._value(0x04, i, 1)) for i in range(min(count, 40_000))]

    def _read_memberrefs(self) -> None:
        count = self._rows.get(0x0A, 0)
        refs = []
        for i in range(min(count, 40_000)):
            parent = self._decode_coded(self._value(0x0A, i, 0), "MemberRefParent")
            refs.append({
                "parent": parent,
                "name": self._string(self._value(0x0A, i, 1)),
            })
        self._memberrefs = refs

    def _read_methods(self) -> None:
        count = self._rows.get(0x06, 0)
        raw: list[tuple[int, str]] = []
        for i in range(count):
            rva = self._value(0x06, i, 0)
            name = self._string(self._value(0x06, i, 3))
            raw.append((rva, name))

        def section_end(rva: int) -> int:
            for s in self._pe.sections:
                if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                    return s["vaddr"] + max(s["vsize"], s["rawsize"])
            return -1

        # IL size = distance to the next method body, bounded by its own section and
        # by a sanity cap (methods are never 64KB of IL in practice).
        rvas = sorted({rva for rva, _ in raw if rva})
        next_rva = {rvas[i]: (rvas[i + 1] if i + 1 < len(rvas) else rvas[i]) for i in range(len(rvas))}
        total = 0
        methods = []
        for rva, name in raw:
            size = 0
            if rva:
                end = min(next_rva.get(rva, rva), section_end(rva))
                if 0 < end - rva <= 65_536:
                    size = end - rva
                total += size
            methods.append({"name": name or f"method@0x{rva:x}", "rva": rva, "il_bytes": size})
        self.total_il_bytes = total
        self.methods = methods

    # ------------------------------------------------------------- IL support

    def method_body(self, rva: int) -> bytes | None:
        """Return the raw IL bytes of a method body (ECMA-335 II.25.4)."""
        if not rva:
            return None
        head = self._pe.read_rva(rva, 12)
        if not head:
            return None
        kind = head[0] & 0x3
        if kind == 0x2:  # tiny format: size in the high 6 bits
            return self._pe.read_rva(rva + 1, head[0] >> 2)
        if kind == 0x3:  # fat format: 12-byte header, size at +4
            flags = u16(head, 0)
            header_size = (flags >> 12) * 4
            code_size = u32(head, 4)
            if 12 <= header_size <= 64 and 0 < code_size <= 1_000_000:
                return self._pe.read_rva(rva + header_size, code_size)
        return None

    def _us_string(self, index: int) -> str:
        """Resolve a user-string heap offset (the operand of `ldstr`)."""
        heap = self._heaps.get("#US")
        if not heap or index <= 0:
            return ""
        meta = self._meta
        pos = heap[0] + index
        if pos >= len(meta):
            return ""
        b0 = meta[pos]
        if b0 & 0x80 == 0:
            length, pos = b0, pos + 1
        elif b0 & 0xC0 == 0x80:
            if pos + 1 >= len(meta):
                return ""
            length, pos = ((b0 & 0x3F) << 8) | meta[pos + 1], pos + 2
        else:
            if pos + 3 >= len(meta):
                return ""
            length = ((b0 & 0x1F) << 24) | (meta[pos + 1] << 16) | (meta[pos + 2] << 8) | meta[pos + 3]
            pos += 4
        if length <= 1:
            return ""
        blob = meta[pos:pos + length - 1]  # last byte is the "has special chars" flag
        return blob.decode("utf-16-le", "ignore")

    def user_strings(self, limit: int = 4000) -> list[tuple[int, str]]:
        """All #US heap entries as (token, text). The heap is a linear list of
        length-prefixed UTF-16 strings, so walking it is cheap and gives us the
        exact tokens that appear as `ldstr` operands."""
        heap = self._heaps.get("#US")
        if not heap:
            return []
        meta = self._meta
        end = min(heap[0] + heap[1], len(meta))
        pos = heap[0] + 1  # offset 0 is the empty string
        out: list[tuple[int, str]] = []
        while pos < end and len(out) < limit:
            start = pos
            b0 = meta[pos]
            if b0 & 0x80 == 0:
                length, pos = b0, pos + 1
            elif b0 & 0xC0 == 0x80:
                if pos + 1 >= end:
                    break
                length, pos = ((b0 & 0x3F) << 8) | meta[pos + 1], pos + 2
            else:
                if pos + 3 >= end:
                    break
                length = ((b0 & 0x1F) << 24) | (meta[pos + 1] << 16) | (meta[pos + 2] << 8) | meta[pos + 3]
                pos += 4
            if length <= 0 or pos + length > end:
                break
            text = meta[pos:pos + length - 1].decode("utf-16-le", "ignore")
            if text:
                out.append((0x70000000 | (start - heap[0]), text))
            pos += length
        return out

    def _typedef_name(self, index: int) -> str:
        if 1 <= index <= len(self._typedefs):
            t = self._typedefs[index - 1]
            return f"{t['namespace']}.{t['name']}" if t["namespace"] else t["name"]
        return ""

    def _typeref_name(self, index: int) -> str:
        if 1 <= index <= len(self._typerefs):
            t = self._typerefs[index - 1]
            return f"{t['namespace']}.{t['name']}" if t["namespace"] else t["name"]
        return ""

    def _method_owner(self, index: int) -> str:
        # MethodList is 1-based and types are ordered; the owner is the *last*
        # type whose method list starts at or before the method. Types with no
        # methods share the next type's start value, so "last" matters.
        best = ""
        for t in self._typedefs:
            start = t["method_start"]
            if start and start <= index:
                best = f"{t['namespace']}.{t['name']}" if t["namespace"] else t["name"]
        return best

    def _method_display(self, index: int) -> str:
        if not (1 <= index <= len(self.methods)):
            return ""
        name = self.methods[index - 1]["name"]
        owner = self._method_owner(index)
        return f"{owner}::{name}" if owner else name

    def _memberref_display(self, index: int) -> str:
        if not (1 <= index <= len(self._memberrefs)):
            return ""
        ref = self._memberrefs[index - 1]
        table, row = ref["parent"]
        parent = ""
        if table == 0x02:
            parent = self._typedef_name(row)
        elif table == 0x01:
            parent = self._typeref_name(row)
        elif table == 0x06:
            parent = self._method_display(row)
        return f"{parent}::{ref['name']}" if parent else ref["name"]

    def resolve_token(self, token: int) -> str:
        """Turn a metadata token into readable text for the evidence pack."""
        table, index = token >> 24, token & 0xFFFFFF
        if table == 0x70:
            return self._us_string(index)
        if table == 0x06:
            return self._method_display(index)
        if table == 0x0A:
            return self._memberref_display(index)
        if table == 0x01:
            return self._typeref_name(index)
        if table == 0x02:
            return self._typedef_name(index)
        if table == 0x04:
            return self._fields[index - 1] if 1 <= index <= len(self._fields) else ""
        if table == 0x1B:
            return "<typespec>"
        if table == 0x11:
            return "<sig>"
        return f"token(0x{token:08x})"

    # --------------------------------------------------------------- features

    def license_methods(self) -> list[dict]:
        return [m for m in self.methods if is_license_ident(m["name"])]

    def license_types(self) -> list[str]:
        return [t for t in self.types if is_license_ident(t)]
