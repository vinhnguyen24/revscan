"""PE structure reader used by the scanner.

Everything here is factual: section table, entropy, import/export names,
x64 unwind entries (a real function count), and CLI/.NET detection.
No guessing in this module — estimation happens in `estimate.py`.
"""

from __future__ import annotations

import math
import struct

SECTION_SCN_MEM_EXECUTE = 0x20000000
SECTION_SCN_MEM_WRITE = 0x80000000


def u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def align_up(v: int, a: int) -> int:
    return v if a <= 0 else (v + a - 1) // a * a


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return round(entropy, 2)


class PEError(ValueError):
    pass


class PEInfo:
    def __init__(self, data: bytes, path: str = ""):
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PEError("not a PE file (no MZ header)")
        self.data = data
        self.path = path
        self.lfanew = u32(data, 0x3C)
        if data[self.lfanew:self.lfanew + 4] != b"PE\0\0":
            raise PEError("not a PE file (no PE signature)")

        coff = self.lfanew + 4
        self.machine = u16(data, coff)
        self.nsec = u16(data, coff + 2)
        self.timestamp = u32(data, coff + 4)
        self.opt_size = u16(data, coff + 16)
        self.characteristics = u16(data, coff + 18)
        self.opt = coff + 20
        self.magic = u16(data, self.opt)
        if self.magic == 0x20B:
            self.is64 = True
            self.image_base = u64(data, self.opt + 24)
            self.data_dirs = self.opt + 112
            self.num_dirs = u32(data, self.opt + 108)
        elif self.magic == 0x10B:
            self.is64 = False
            self.image_base = u32(data, self.opt + 28)
            self.data_dirs = self.opt + 96
            self.num_dirs = u32(data, self.opt + 92)
        else:
            raise PEError(f"unknown optional header magic 0x{self.magic:x}")

        self.section_align = u32(data, self.opt + 32)
        self.file_align = u32(data, self.opt + 36)
        self.size_image = u32(data, self.opt + 56)
        self.size_headers = u32(data, self.opt + 60)
        self.subsystem = u16(data, self.opt + 68)
        self.sec_table = self.opt + self.opt_size
        self.sections = [self._section(i) for i in range(self.nsec)]

    # ------------------------------------------------------------------ parse

    def _section(self, i: int) -> dict:
        off = self.sec_table + 40 * i
        name = bytes(self.data[off:off + 8]).rstrip(b"\0").decode("latin-1")
        vsize = u32(self.data, off + 8)
        vaddr = u32(self.data, off + 12)
        rawsize = u32(self.data, off + 16)
        rawptr = u32(self.data, off + 20)
        chars = u32(self.data, off + 36)
        raw = self.data[rawptr:rawptr + min(rawsize, max(vsize, 0))]
        return {
            "name": name,
            "vsize": vsize,
            "vaddr": vaddr,
            "rawsize": rawsize,
            "rawptr": rawptr,
            "characteristics": chars,
            "executable": bool(chars & SECTION_SCN_MEM_EXECUTE),
            "writable": bool(chars & SECTION_SCN_MEM_WRITE),
            "entropy": shannon_entropy(raw[:2_000_000]),
        }

    def rva_to_offset(self, rva: int) -> int | None:
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                return s["rawptr"] + (rva - s["vaddr"])
        return None

    def read_rva(self, rva: int, size: int) -> bytes | None:
        off = self.rva_to_offset(rva)
        if off is None:
            return None
        return self.data[off:off + size]

    def cstring_at_rva(self, rva: int, limit: int = 256) -> str:
        off = self.rva_to_offset(rva)
        if off is None:
            return ""
        end = self.data.find(b"\0", off, min(off + limit, len(self.data)))
        if end < 0:
            return ""
        return self.data[off:end].decode("latin-1", "ignore")

    def data_dir(self, index: int) -> tuple[int, int]:
        if index >= self.num_dirs:
            return (0, 0)
        off = self.data_dirs + index * 8
        return (u32(self.data, off), u32(self.data, off + 4))

    # --------------------------------------------------------------- features

    @property
    def section_names(self) -> list[str]:
        return [s["name"] for s in self.sections]

    @property
    def is_dotnet(self) -> bool:
        rva, size = self.data_dir(14)
        return rva != 0 and size >= 0x48

    @property
    def executable_section(self) -> dict | None:
        for s in self.sections:
            if s["executable"] and s["name"] not in (".pdata", ".textbss"):
                return s
        return None

    @property
    def code_bytes(self) -> int:
        return sum(s["rawsize"] for s in self.sections if s["executable"])

    def imports(self, limit: int = 4000) -> list[dict]:
        rva, _ = self.data_dir(1)
        if not rva:
            return []
        out: list[dict] = []
        for i in range(64):
            desc = self.read_rva(rva + i * 20, 20)
            if not desc or desc == b"\0" * 20:
                break
            name_rva = u32(desc, 12)
            oft = u32(desc, 0)
            thunk_rva = oft or u32(desc, 16)
            dll = self.cstring_at_rva(name_rva, 128)
            entry = {"dll": dll, "functions": []}
            if thunk_rva:
                width = 8 if self.is64 else 4
                for j in range(2048):
                    raw = self.read_rva(thunk_rva + j * width, width)
                    if not raw:
                        break
                    value = u64(raw, 0) if self.is64 else u32(raw, 0)
                    if value == 0:
                        break
                    # High bit set => import by ordinal
                    if value & (1 << (63 if self.is64 else 31)):
                        entry["functions"].append(f"ord#{value & 0xFFFF}")
                    else:
                        entry["functions"].append(self.cstring_at_rva((value & 0x7FFFFFFF) + 2, 128))
                    if len(out) * 8 + len(entry["functions"]) > limit:
                        break
            out.append(entry)
            if len(out) >= 256:
                break
        return out

    def exports(self) -> list[str]:
        return [name for name, _rva in self.export_entries()]

    def export_entries(self) -> list[tuple[str, int]]:
        """Exported names *with* the RVA of their code.

        Names alone were enough for the cost model (a named export is a grep hit),
        but a native disassembler needs the address to read the function.
        """
        rva, size = self.data_dir(0)
        if not rva or size < 40:
            return []
        header = self.read_rva(rva, 40)
        if not header:
            return []
        num_names = u32(header, 24)
        funcs_rva = u32(header, 28)
        names_rva = u32(header, 32)
        ords_rva = u32(header, 36)
        if not num_names or not names_rva or num_names > 20_000:
            return []
        out: list[tuple[str, int]] = []
        for i in range(min(num_names, 2000)):
            raw = self.read_rva(names_rva + i * 4, 4)
            if not raw:
                break
            name = self.cstring_at_rva(u32(raw, 0), 200)
            if not name:
                continue
            func_rva = 0
            if funcs_rva and ords_rva:
                ord_raw = self.read_rva(ords_rva + i * 2, 2)
                if ord_raw:
                    slot = self.read_rva(funcs_rva + u16(ord_raw, 0) * 4, 4)
                    if slot:
                        func_rva = u32(slot, 0)
            out.append((name, func_rva))
        return out

    def import_slots(self, limit: int = 4000) -> dict[int, str]:
        """IAT slot RVA -> imported function name.

        A disassembled `call QWORD PTR [rip+0x1234]` is only useful evidence if
        the reader can see it lands on CryptVerifySignatureA, not on an anonymous
        thunk. `imports()` drops the slot address; this keeps it.
        """
        rva, _ = self.data_dir(1)
        if not rva:
            return {}
        width = 8 if self.is64 else 4
        high = 1 << (63 if self.is64 else 31)
        out: dict[int, str] = {}
        for i in range(64):
            desc = self.read_rva(rva + i * 20, 20)
            if not desc or desc == b"\0" * 20:
                break
            oft = u32(desc, 0)
            name_rva = u32(desc, 12)
            first_thunk = u32(desc, 16)
            if not first_thunk:
                continue
            dll = self.cstring_at_rva(name_rva, 128)
            for j in range(2048):
                slot = first_thunk + j * width
                raw = self.read_rva(slot, width)
                if not raw:
                    break
                value = u64(raw, 0) if self.is64 else u32(raw, 0)
                if value == 0:
                    break
                if value & high:
                    out[slot] = f"{dll}!ord#{value & 0xFFFF}"
                else:
                    # The name lives in the original thunk table; when it is absent
                    # the IAT was bound at build time and holds an absolute address.
                    hint_rva = oft + j * width if oft else 0
                    fname = ""
                    if hint_rva:
                        hint = self.read_rva(hint_rva, width)
                        if hint:
                            hv = u64(hint, 0) if self.is64 else u32(hint, 0)
                            if hv and not (hv & high):
                                fname = self.cstring_at_rva((hv & 0x7FFFFFFF) + 2, 128)
                    if not fname:
                        fname = self.cstring_at_rva((value & 0x7FFFFFFF) + 2, 128)
                    out[slot] = f"{dll}!{fname}" if fname else dll
                if len(out) >= limit:
                    return out
        return out

    @property
    def entry_rva(self) -> int:
        return u32(self.data, self.opt + 16)

    def function_ranges(self, limit: int = 200_000) -> list[tuple[int, int]]:
        """Function boundaries from .pdata (x64). Exact, unlike gap heuristics."""
        for s in self.sections:
            if s["name"] != ".pdata" or s["vsize"] < 12:
                continue
            raw = self.data[s["rawptr"]:s["rawptr"] + s["rawsize"]]
            if len(raw) < 12:
                return []
            out = []
            for i in range(min(len(raw) // 12, limit)):
                begin, end, _unwind = struct.unpack_from("<III", raw, i * 12)
                # Unwind-only entries have begin==0; junk entries can span the
                # whole image (same class of bug as the 1.6GB IL size).
                if begin and end > begin and begin < self.size_image and end - begin <= 2_000_000:
                    out.append((begin, end))
            return out
        return []

    def section_for_rva(self, rva: int) -> dict | None:
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                return s
        return None

    def function_count(self) -> int | None:
        """x64 binaries carry one 12-byte RUNTIME_FUNCTION per function in .pdata.
        That is an exact count, not an estimate."""
        for s in self.sections:
            if s["name"] == ".pdata" and s["vsize"]:
                return s["vsize"] // 12
        return None

    def summary(self) -> dict:
        return {
            "format": "PE32+" if self.is64 else "PE32",
            "dotnet": self.is_dotnet,
            "sections": self.section_names,
            "code_bytes": self.code_bytes,
            "function_count": self.function_count(),
            "entropy_by_section": {s["name"]: s["entropy"] for s in self.sections},
            "timestamp": self.timestamp,
        }


def open_pe(path: str) -> PEInfo:
    with open(path, "rb") as fh:
        return PEInfo(fh.read(), path)
