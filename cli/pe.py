"""Minimal PE reader / payload injector.

Only what RevScan needs: read the section table and append a data blob without
changing program behaviour. Supports PE32 and PE32+.

Injection strategy
------------------
1. Slack of the last section: the loader only maps up to VirtualSize, so the gap
   between VirtualSize and SizeOfRawData is dead space. If it is big enough and
   all zeroes, write there. No header changes at all -> lowest possible risk.
2. Otherwise append a new read-only section (.tkdata) aligned to FileAlignment,
   bump NumberOfSections and SizeOfImage.
3. If the header table is already full (common in linker-tight .NET assemblies),
   append the blob as an overlay at EOF: no header change, never mapped.

The blob is never referenced by code; it exists to be seen by `strings`,
`dumpbin` and decompiler string tables.
"""

from __future__ import annotations

import struct

MZ = b"MZ"
PE_SIG = b"PE\0\0"


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return (value + alignment - 1) // alignment * alignment


class PEError(ValueError):
    pass


class PE:
    """Parsed view of a PE file. Mutates `self.data` (bytearray) on inject()."""

    def __init__(self, data: bytes | bytearray):
        if len(data) < 0x40:
            raise PEError("file too small to be a PE")
        if bytes(data[:2]) != MZ:
            raise PEError("missing MZ header (not a Windows executable)")
        self.data = bytearray(data)
        self.lfanew = _u32(self.data, 0x3C)
        if bytes(self.data[self.lfanew:self.lfanew + 4]) != PE_SIG:
            raise PEError("missing PE signature")

        self.coff = self.lfanew + 4
        self.nsec = _u16(self.data, self.coff + 2)
        self.opt_size = _u16(self.data, self.coff + 16)
        self.opt = self.coff + 20
        self.magic = _u16(self.data, self.opt)
        if self.magic == 0x20B:
            self.is64 = True
        elif self.magic == 0x10B:
            self.is64 = False
        else:
            raise PEError(f"unknown optional header magic 0x{self.magic:x}")

        self.section_align = _u32(self.data, self.opt + 32)
        self.file_align = _u32(self.data, self.opt + 36)
        self.size_image = _u32(self.data, self.opt + 56)
        self.size_headers = _u32(self.data, self.opt + 60)
        self.num_dirs = _u32(self.data, self.opt + (108 if self.is64 else 92))
        self.data_dir = self.opt + (112 if self.is64 else 96)
        self.sec_table = self.opt + self.opt_size
        self.sections = [self._section(i) for i in range(self.nsec)]

    def _section(self, index: int) -> dict:
        off = self.sec_table + 40 * index
        if off + 40 > len(self.data):
            raise PEError("truncated section table")
        name = bytes(self.data[off:off + 8]).rstrip(b"\0").decode("latin-1")
        return {
            "index": index,
            "offset": off,
            "name": name,
            "vsize": _u32(self.data, off + 8),
            "vaddr": _u32(self.data, off + 12),
            "rawsize": _u32(self.data, off + 16),
            "rawptr": _u32(self.data, off + 20),
            "chars": _u32(self.data, off + 36),
        }

    # ------------------------------------------------------------------ info

    def summary(self) -> dict:
        return {
            "format": "PE32+" if self.is64 else "PE32",
            "sections": [s["name"] for s in self.sections],
            "size_image": self.size_image,
            "size_headers": self.size_headers,
            "section_align": self.section_align,
            "file_align": self.file_align,
        }

    def has_payload_marker(self) -> bool:
        return b"\0TK1\0" in self.data or b"\0TK2\0" in self.data

    def has_authenticode(self) -> bool:
        """True if IMAGE_DIRECTORY_ENTRY_SECURITY (index 4) carries a signature."""
        entry = self.dir_entry(4)
        return bool(entry and entry[0] and entry[1])

    def rva_to_offset(self, rva: int) -> int | None:
        for section in self.sections:
            span = max(section["vsize"], section["rawsize"])
            if section["vaddr"] <= rva < section["vaddr"] + span:
                delta = rva - section["vaddr"]
                if delta < section["rawsize"]:
                    return section["rawptr"] + delta
                return None  # in virtual-only space, no file bytes
        return None

    def dir_entry(self, index: int) -> tuple[int, int] | None:
        """(offset, size) of a data directory entry, or None if absent."""
        if index >= self.num_dirs:
            return None
        offset = self.data_dir + index * 8
        if offset + 8 > len(self.data):
            return None
        return _u32(self.data, offset), _u32(self.data, offset + 4)

    # ---------------------------------------------------------------- strip

    def strip_debug(self) -> dict:
        """Remove the debug directory and its CodeView (PDB) records.

        A build path like `C:\\build\\agent\\bin\\release\\MyApp.pdb` hands an
        agent the project layout and symbol names for free, and `.pdb` strings
        are one of the cheapest signals to grep for. Zeroing the directory entry
        hides it from tools; zeroing the CodeView payload removes it from
        `strings`.
        """
        entry = self.dir_entry(6)
        if entry is None:
            return {"present": False, "records": 0, "bytes": 0}
        rva, size = entry
        if not rva or not size:
            return {"present": False, "records": 0, "bytes": 0}

        start = self.rva_to_offset(rva)
        records = 0
        cleared = 0
        if start is not None:
            for index in range(size // 28):
                record = start + index * 28
                if record + 28 > len(self.data):
                    break
                data_size = _u32(self.data, record + 16)
                data_ptr = _u32(self.data, record + 24)
                if not data_size or not data_ptr:
                    continue
                end = data_ptr + data_size
                if end > len(self.data):
                    continue
                blob = bytes(self.data[data_ptr:end])
                # RSDS (PDB 7.0) / NB10 (PDB 2.0) / any record that carries a .pdb path.
                if blob[:4] in (b"RSDS", b"NB10") or b".pdb" in blob.lower():
                    self.data[data_ptr:end] = b"\0" * data_size
                    records += 1
                    cleared += data_size

        # Zero the directory entry even if no CodeView record was found: the
        # loader/tools must not see a debug directory at all.
        entry_off = self.data_dir + 6 * 8
        struct.pack_into("<II", self.data, entry_off, 0, 0)
        return {"present": True, "records": records, "bytes": cleared}

    # --------------------------------------------------------------- inject

    def inject(self, blob: bytes) -> tuple[str, int]:
        """Append `blob` to the image. Returns (method, file_offset)."""
        if not blob:
            raise PEError("empty payload")
        if self.has_payload_marker():
            # Idempotency guard: protecting twice must be refused, not stacked.
            raise PEError("payload already present (file was already protected)")

        offset = self._inject_into_slack(blob)
        if offset is not None:
            return "section-slack", offset

        try:
            return "new-section", self._inject_new_section(blob)
        except PEError as err:
            if "no room" not in str(err):
                raise
            # Header table is full (common for linker-tight .NET assemblies).
            # Appending at EOF needs no header change at all and stays out of memory.
            offset = len(self.data)
            self.data += blob
            return "overlay", offset

    def _inject_into_slack(self, blob: bytes) -> int | None:
        if not self.sections:
            return None
        last = self.sections[-1]
        start = last["rawptr"] + last["vsize"]
        end = last["rawptr"] + last["rawsize"]
        need = align_up(len(blob), 8)
        if end <= start or end - start < need:
            return None
        if any(self.data[start:start + need]):
            return None  # real data there; do not touch it
        self.data[start:start + need] = blob + b"\0" * (need - len(blob))
        return start

    def _inject_new_section(self, blob: bytes) -> int:
        # Free header slot is right after the last existing section header.
        new_header = self.sec_table + 40 * self.nsec
        table_end = new_header + 40
        first_raw = min((s["rawptr"] for s in self.sections if s["rawptr"]), default=self.size_headers)
        header_limit = min(self.size_headers, first_raw)
        if table_end > header_limit:
            raise PEError(
                "no room for a new section header (header area is full); "
                "try --mode=slack-only on a differently linked binary"
            )

        new_rva = align_up(self.size_image, self.section_align)
        raw_ptr = align_up(len(self.data), self.file_align)
        raw_size = align_up(len(blob), self.file_align)

        if raw_ptr > len(self.data):
            self.data += b"\0" * (raw_ptr - len(self.data))
        self.data += blob + b"\0" * (raw_size - len(blob))

        struct.pack_into(
            "<8sIIIIIIHHI",
            self.data,
            new_header,
            b".tkdata",
            len(blob),
            new_rva,
            raw_size,
            raw_ptr,
            0,  # PointerToRelocations
            0,  # PointerToLinenumbers
            0,  # NumberOfRelocations
            0,  # NumberOfLinenumbers
            0x40000040,  # INITIALIZED_DATA | MEM_READ
        )

        struct.pack_into("<H", self.data, self.coff + 2, self.nsec + 1)
        new_size_image = new_rva + align_up(len(blob), self.section_align)
        struct.pack_into("<I", self.data, self.opt + 56, new_size_image)
        self.size_image = new_size_image
        self.nsec += 1
        self.sections = [self._section(i) for i in range(self.nsec)]
        return raw_ptr


def open_pe(path: str) -> PE:
    with open(path, "rb") as handle:
        return PE(handle.read())
