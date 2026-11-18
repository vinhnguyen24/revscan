"""Disassembly / IL evidence tests.

    python3 tests/test_disasm.py

Pure decoder tests run everywhere; binary-backed tests skip when the PE/.NET
sample or objdump is missing (same policy as test_scan.py).
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanner import collect  # noqa: E402
from scanner import native  # noqa: E402
from scanner.ai import build_pack  # noqa: E402
from scanner.dotnet import DotNetInfo  # noqa: E402
from scanner.il import disassemble, dotnet_code  # noqa: E402
from scanner.peinfo import PEInfo  # noqa: E402


def _first_existing(candidates: list[Path]) -> str:
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[-1])


def _find_windows_binary(name: str, env_var: str) -> str:
    candidates: list[Path] = []
    if os.environ.get(env_var):
        candidates.append(Path(os.environ[env_var]))
    if os.environ.get("TRAPKEY_TEST_BINARIES"):
        candidates.append(Path(os.environ["TRAPKEY_TEST_BINARIES"]) / name)
    win = Path(os.environ.get("WINDIR") or "C:/Windows")
    candidates += [win / "System32" / name, Path("/mnt/c/Windows/System32") / name]
    return _first_existing(candidates)


def _find_dotnet_assembly() -> str:
    candidates: list[Path] = []
    if os.environ.get("TRAPKEY_TEST_DOTNET"):
        candidates.append(Path(os.environ["TRAPKEY_TEST_DOTNET"]))
    if os.environ.get("TRAPKEY_TEST_BINARIES"):
        candidates.append(Path(os.environ["TRAPKEY_TEST_BINARIES"]) / "mscorlib.dll")
    win = Path(os.environ.get("WINDIR") or "C:/Windows")
    candidates += [
        Path("/mnt/c/Code/game_dlls/mscorlib.dll"),
        win / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "mscorlib.dll",
        win / "Microsoft.NET" / "Framework" / "v4.0.30319" / "mscorlib.dll",
    ]
    return _first_existing(candidates)


WINDOWS_EXE = _find_windows_binary("notepad.exe", "TRAPKEY_TEST_EXE")
DOTNET_DLL = _find_dotnet_assembly()


class ILDecoderTests(unittest.TestCase):
    def resolve(self, token: int) -> str:
        return {0x70000001: "Licence key is invalid", 0x0A000001: "Checker::Verify"}.get(
            token, f"token(0x{token:08x})"
        )

    def test_ldstr_and_call(self):
        body = bytes([0x72, 0x01, 0x00, 0x00, 0x70, 0x28, 0x01, 0x00, 0x00, 0x0A, 0x2A])
        lines = disassemble(body, self.resolve)
        self.assertEqual(lines[0], 'IL_0000: ldstr "Licence key is invalid"')
        self.assertEqual(lines[1], "IL_0005: call Checker::Verify")
        self.assertEqual(lines[2], "IL_000a: ret")

    def test_branch_target_is_computed_from_instruction_end(self):
        body = bytes([0x2B, 0x02, 0x2A])  # br.s +2 -> IL_0004
        lines = disassemble(body, self.resolve)
        self.assertEqual(lines[0], "IL_0000: br.s IL_0004")

    def test_truncated_operand_does_not_decode_garbage(self):
        lines = disassemble(bytes([0x20, 0x01]), self.resolve)  # ldc.i4 needs 4 bytes
        self.assertTrue(lines[-1].endswith("<truncated>"), lines)

    def test_unknown_opcode_stops(self):
        lines = disassemble(bytes([0x2A, 0xFF]), self.resolve)  # 0xFF is not an opcode
        self.assertEqual(lines[0], "IL_0000: ret")
        self.assertEqual(lines[1], "IL_0001: .byte 0xff")
        self.assertEqual(len(lines), 2)

    def test_two_byte_opcodes(self):
        body = bytes([0xFE, 0x01, 0xFE, 0x16, 0x01, 0x00, 0x00, 0x0A])
        lines = disassemble(body, self.resolve)
        self.assertEqual(lines[0], "IL_0000: ceq")
        self.assertEqual(lines[1], "IL_0002: constrained. Checker::Verify")

    def test_throw_is_not_ldfld(self):
        # Regression: the 0x76 group was one slot short, so `throw` decoded as
        # `ldfld` and every token after it was garbage.
        self.assertEqual(disassemble(bytes([0x7A]), self.resolve), ["IL_0000: throw"])


class DotNetMetadataTests(unittest.TestCase):
    def setUp(self):
        if not Path(DOTNET_DLL).exists():
            self.skipTest("no .NET assembly available")
        self.pe = PEInfo(Path(DOTNET_DLL).read_bytes(), DOTNET_DLL)
        self.dotnet = DotNetInfo(self.pe)
        if not self.dotnet.ok:
            self.skipTest("assembly metadata unreadable")

    def test_type_and_method_tables_are_aligned(self):
        # Regression: HeapSizes was read at base+7 (the reserved byte) instead of
        # base+6, which shifted every table on assemblies with 4-byte heaps.
        self.assertEqual(self.dotnet.types[0], "<Module>")
        first_names = [m["name"] for m in self.dotnet.methods[:10]]
        self.assertTrue(any(name in (".ctor", ".cctor") for name in first_names))

    def test_method_body_and_tokens_resolve(self):
        method = next(m for m in self.dotnet.methods if m["rva"] and m["il_bytes"])
        body = self.dotnet.method_body(method["rva"])
        self.assertTrue(body)
        lines = disassemble(body, self.dotnet.resolve_token)
        self.assertTrue(lines[0].startswith("IL_0000:"))
        self.assertNotIn("token(0x", "\n".join(lines[:5]) + "".join(lines[:1]))

    def test_licence_string_tokens_and_code_block(self):
        text = dotnet_code(self.dotnet)
        if not text:
            self.skipTest("assembly has no licensing-looking user strings")
        self.assertIn("code (.NET IL", text)
        self.assertIn("method: ", text)
        self.assertIn("IL_0000:", text)


class NativeDisassemblyTests(unittest.TestCase):
    def setUp(self):
        if not native.engine():
            self.skipTest("objdump not installed")
        if not Path(WINDOWS_EXE).exists():
            self.skipTest("no PE sample available")
        self.ev = collect(WINDOWS_EXE)

    def test_function_ranges_come_from_pdata(self):
        ranges = self.ev.pe.function_ranges()
        if not self.ev.pe.is64:
            self.skipTest("no .pdata in a 32-bit image")
        self.assertGreater(len(ranges), 10)
        for begin, end in ranges[:100]:
            self.assertLess(begin, end)

    def test_import_slots_carry_names(self):
        slots = self.ev.pe.import_slots()
        self.assertTrue(slots)
        self.assertTrue(any("!" in name for name in slots.values()))

    def test_entry_point_is_disassembled_when_nothing_else_matches(self):
        result = native.disassemble(self.ev.pe, self.ev.strings, self.ev.path)
        self.assertEqual(result["engine"], "objdump")
        self.assertTrue(result["functions"])
        self.assertTrue(result["functions"][0]["lines"])
        self.assertIn(":", result["functions"][0]["lines"][0])


class EvidencePackTests(unittest.TestCase):
    def setUp(self):
        if not Path(WINDOWS_EXE).exists():
            self.skipTest("no PE sample available")
        self.ev = collect(WINDOWS_EXE)

    def test_pack_respects_char_budget(self):
        meta: dict = {}
        pack = build_pack(self.ev, max_chars=5_000, meta=meta)
        self.assertLessEqual(len(pack), 5_000)
        self.assertIn("file:", pack)

    def test_code_can_be_disabled(self):
        old = os.environ.get("TRAPKEY_AI_CODE")
        os.environ["TRAPKEY_AI_CODE"] = "0"
        try:
            meta: dict = {}
            pack = build_pack(self.ev, meta=meta)
            self.assertEqual(meta["code_chars"], 0)
            self.assertNotIn("code (native", pack)
        finally:
            if old is None:
                os.environ.pop("TRAPKEY_AI_CODE", None)
            else:
                os.environ["TRAPKEY_AI_CODE"] = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
