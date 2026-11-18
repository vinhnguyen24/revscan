"""Crack simulation (Round 2) tests. Plain unittest, no dependencies.

    python3 tests/test_crack_sim.py
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanner.ai import (  # noqa: E402
    PROMPT_ROUND2,
    _assess_difficulty,
    _build_round2_pack,
    _parse_round2,
    verify_patch,
)
from scanner.estimate import Estimate  # noqa: E402
from scanner.evidence import Evidence  # noqa: E402
from scanner.report import render, to_dict  # noqa: E402
from scanner import estimate  # noqa: E402


def _find_dotnet_assembly() -> str:
    candidates: list[Path] = []
    if os.environ.get("TRAPKEY_TEST_DOTNET"):
        candidates.append(Path(os.environ["TRAPKEY_TEST_DOTNET"]))
    if os.environ.get("TRAPKEY_TEST_BINARIES"):
        candidates.append(Path(os.environ["TRAPKEY_TEST_BINARIES"]) / "mscorlib.dll")
    win = Path(os.environ.get("WINDIR") or "C:/Windows")
    candidates += [
        win / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "mscorlib.dll",
        win / "Microsoft.NET" / "Framework" / "v4.0.30319" / "mscorlib.dll",
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    return str(candidates[-1])


DOTNET_DLL = _find_dotnet_assembly()


# ---------------------------------------------------------------------------
# 1. _parse_round2 — structured output parsing
# ---------------------------------------------------------------------------

class ParseRound2Tests(unittest.TestCase):
    def test_valid_response_is_parsed(self):
        text = """\
STRATEGY: patch-branch
OFFSET: 0x0006
ORIGINAL: 2C05
PATCHED: 2D05
EXPLANATION: flip brfalse.s to brtrue.s to bypass licence check
CONFIDENCE: high
"""
        result = _parse_round2(text)
        self.assertIsNotNone(result)
        self.assertEqual(result["strategy"], "patch-branch")
        self.assertEqual(result["offset"], 6)
        self.assertEqual(result["original"], "2c05")
        self.assertEqual(result["patched"], "2d05")
        self.assertEqual(result["patch_size"], 2)
        self.assertEqual(result["confidence"], "high")
        self.assertIn("brfalse", result["explanation"])

    def test_strategy_none_returns_none(self):
        text = "STRATEGY: none\nOFFSET: 0x0\nORIGINAL: 00\nPATCHED: 00\n"
        self.assertIsNone(_parse_round2(text))

    def test_mismatched_lengths_rejected(self):
        text = """\
STRATEGY: patch-nop
OFFSET: 0x0006
ORIGINAL: 2C05
PATCHED: 002D0500
EXPLANATION: test
CONFIDENCE: low
"""
        self.assertIsNone(_parse_round2(text))

    def test_empty_hex_rejected(self):
        text = "STRATEGY: patch-branch\nOFFSET: 0x0\nORIGINAL:\nPATCHED: 2D\n"
        self.assertIsNone(_parse_round2(text))

    def test_bad_hex_rejected(self):
        text = "STRATEGY: patch-branch\nOFFSET: 0x0\nORIGINAL: ZZZZ\nPATCHED: 2D05\n"
        self.assertIsNone(_parse_round2(text))

    def test_oversized_patch_rejected(self):
        # 17 bytes > 16 limit
        text = (
            "STRATEGY: patch-nop\nOFFSET: 0x0\n"
            f"ORIGINAL: {'00' * 17}\nPATCHED: {'90' * 17}\n"
            "EXPLANATION: too many bytes\nCONFIDENCE: low\n"
        )
        self.assertIsNone(_parse_round2(text))

    def test_model_prefix_in_lines_is_handled(self):
        """Models sometimes prepend markdown or numbering to lines."""
        text = """\
Here is my analysis:

STRATEGY: patch-return
OFFSET: 0x0000
ORIGINAL: 16
PATCHED: 17
EXPLANATION: change ldc.i4.0 to ldc.i4.1 (always return true)
CONFIDENCE: medium
"""
        result = _parse_round2(text)
        self.assertIsNotNone(result)
        self.assertEqual(result["strategy"], "patch-return")
        self.assertEqual(result["original"], "16")
        self.assertEqual(result["patched"], "17")


# ---------------------------------------------------------------------------
# 2. verify_patch — grounding against actual binary
# ---------------------------------------------------------------------------

class VerifyPatchTests(unittest.TestCase):
    def _evidence(self, **kw) -> Evidence:
        ev = Evidence(path="x.exe", size=1000, sha256="0" * 64, kind="native")
        ev.stats = {"strings_chars": 1000, "license_strings": 0}
        ev.pe = None
        for key, value in kw.items():
            setattr(ev, key, value)
        return ev

    @unittest.skipUnless(os.path.exists(DOTNET_DLL), "no .NET assembly available")
    def test_valid_il_patch_on_real_assembly(self):
        """Pick a real method body from mscorlib and verify bytes match."""
        from scanner import collect

        ev = collect(DOTNET_DLL)
        self.assertTrue(ev.dotnet and ev.dotnet.ok)

        # Find the first method with a body of at least 4 bytes
        for m in ev.dotnet.methods[:200]:
            if not m["rva"]:
                continue
            body = ev.dotnet.method_body(m["rva"])
            if body and len(body) >= 4:
                # Construct a patch that matches actual bytes at offset 0
                orig = body[0:2]
                fake_patched = bytes([orig[0] ^ 0xFF, orig[1]])
                patch = {
                    "strategy": "patch-branch",
                    "offset": 0,
                    "original": orig.hex(),
                    "patched": fake_patched.hex(),
                    "patch_size": 2,
                }
                result = verify_patch(ev, patch)
                self.assertTrue(result["valid"], f"Should match bytes in method {m['name']}")
                self.assertIn("match", result["reason"])
                self.assertEqual(result["method"], m["name"])
                return

        self.skipTest("No method with body >= 4 bytes found")

    def test_invalid_offset_fails_verification(self):
        """Bytes that don't exist at the given offset should fail."""
        ev = self._evidence()
        patch = {
            "strategy": "patch-branch",
            "offset": 0,
            "original": "deadbeef",
            "patched": "cafebabe",
            "patch_size": 4,
        }
        result = verify_patch(ev, patch)
        self.assertFalse(result["valid"])


# ---------------------------------------------------------------------------
# 3. _assess_difficulty
# ---------------------------------------------------------------------------

class DifficultyTests(unittest.TestCase):
    def test_one_byte_is_trivial(self):
        self.assertEqual(_assess_difficulty(b"\x2c", b"\x2d", "patch-branch"), "TRIVIAL")

    def test_two_bytes_is_trivial(self):
        self.assertEqual(_assess_difficulty(b"\x2c\x05", b"\x2d\x05", "patch-branch"), "TRIVIAL")

    def test_four_bytes_is_easy(self):
        self.assertEqual(_assess_difficulty(b"\x00" * 4, b"\x90" * 4, "patch-nop"), "EASY")

    def test_large_patch_is_moderate(self):
        self.assertEqual(_assess_difficulty(b"\x00" * 8, b"\x90" * 8, "patch-nop"), "MODERATE")


# ---------------------------------------------------------------------------
# 4. Report rendering with crack simulation
# ---------------------------------------------------------------------------

class ReportRenderTests(unittest.TestCase):
    def _evidence(self) -> Evidence:
        ev = Evidence(path="x.exe", size=1000, sha256="0" * 64, kind="dotnet")
        ev.stats = {"strings_chars": 20_000, "license_strings": 5}
        ev.pe = None
        return ev

    def test_to_dict_includes_crack_simulation(self):
        ev = self._evidence()
        est = estimate(ev)
        est.crack_simulation = {
            "seconds": 2.5,
            "model": "gpt-6-luna",
            "success": True,
            "patch": {
                "strategy": "patch-branch",
                "offset": 6,
                "original": "2c05",
                "patched": "2d05",
                "patch_size": 2,
                "explanation": "flip brfalse.s to brtrue.s",
                "confidence": "high",
                "verified": True,
                "verify_reason": "bytes match",
                "method": "LicenseManager::Validate",
                "difficulty": "TRIVIAL",
            },
        }
        d = to_dict(ev, est)
        self.assertIn("crack_simulation", d)
        self.assertTrue(d["crack_simulation"]["success"])
        self.assertEqual(d["crack_simulation"]["patch"]["strategy"], "patch-branch")
        # Must be valid JSON
        json.dumps(d)

    def test_to_dict_without_crack_simulation(self):
        ev = self._evidence()
        est = estimate(ev)
        d = to_dict(ev, est)
        self.assertNotIn("crack_simulation", d)
        json.dumps(d)

    def test_render_includes_crack_simulation_section(self):
        ev = self._evidence()
        est = estimate(ev)
        est.crack_simulation = {
            "seconds": 3.1,
            "model": "gpt-6-luna",
            "success": True,
            "patch": {
                "strategy": "patch-branch",
                "offset": 6,
                "original": "2c05",
                "patched": "2d05",
                "patch_size": 2,
                "explanation": "flip brfalse.s to brtrue.s",
                "confidence": "high",
                "verified": True,
                "verify_reason": "bytes match",
                "method": "LicenseManager::Validate",
                "difficulty": "TRIVIAL",
            },
        }
        text = render(ev, est)
        self.assertIn("CRACK SIMULATION", text)
        self.assertIn("patch-branch", text)
        self.assertIn("TRIVIAL", text)
        self.assertIn("2c05", text)
        self.assertIn("2d05", text)

    def test_render_crack_sim_error(self):
        ev = self._evidence()
        est = estimate(ev)
        est.crack_simulation = {
            "error": "Round 1 did not find a function",
        }
        text = render(ev, est)
        self.assertIn("CRACK SIMULATION", text)
        self.assertIn("error", text)

    def test_render_crack_sim_no_patch(self):
        ev = self._evidence()
        est = estimate(ev)
        est.crack_simulation = {
            "seconds": 2.0,
            "model": "gpt-6-luna",
            "success": False,
            "reason": "model could not propose a patch",
        }
        text = render(ev, est)
        self.assertIn("CRACK SIMULATION", text)
        self.assertIn("could not propose", text)


# ---------------------------------------------------------------------------
# 5. PROMPT_ROUND2 sanity
# ---------------------------------------------------------------------------

class PromptTests(unittest.TestCase):
    def test_prompt_round2_exists_and_has_format(self):
        self.assertIn("OFFSET", PROMPT_ROUND2)
        self.assertIn("KIND", PROMPT_ROUND2)
        self.assertIn("INSTRUCTION", PROMPT_ROUND2)
        self.assertIn("EXPLANATION", PROMPT_ROUND2)

    def test_build_round2_pack_includes_target(self):
        ev = Evidence(path="test.exe", size=500, sha256="0" * 64, kind="dotnet")
        ev.stats = {"strings_chars": 1000, "license_strings": 0}
        ev.pe = None
        ev.strings = []
        round1 = {"raw_function": "LicenseManager::Validate", "success": True}
        pack = _build_round2_pack(ev, round1)
        self.assertIn("LicenseManager::Validate", pack)
        self.assertIn("target_function", pack)

    def test_disassemble_show_bytes_emits_hex_encodings(self):
        from scanner.il import disassemble

        # ldarg.0 (02), brtrue.s +5 (2d 05), ldc.i4.0 (16), ret (2a)
        body = bytes([0x02, 0x2D, 0x05, 0x16, 0x2A])
        lines = disassemble(body, lambda t: "", show_bytes=True)
        self.assertEqual(lines[0], "IL_0000 [02]: ldarg.0")
        self.assertEqual(lines[1], "IL_0001 [2d05]: brtrue.s IL_0008")
        self.assertEqual(lines[2], "IL_0003 [16]: ldc.i4.0")
        self.assertEqual(lines[3], "IL_0004 [2a]: ret")

    @unittest.skipUnless(os.path.exists(DOTNET_DLL), "no .NET assembly available")
    def test_audit_format_derives_verified_branch_or_return_patch(self):
        from scanner import collect

        ev = collect(DOTNET_DLL)
        for m in ev.dotnet.methods[:400]:
            if not m["rva"]:
                continue
            body = ev.dotnet.method_body(m["rva"])
            if not body:
                continue
            # Find an IL offset with brfalse.s (0x2c) or brtrue.s (0x2d) or ldc.i4.0 (0x16)
            for off in range(len(body) - 1):
                if body[off] in (0x2C, 0x2D):
                    resp = (
                        f"OFFSET: 0x{off:04x}\n"
                        f"KIND: branch\n"
                        f"INSTRUCTION: {'brfalse.s' if body[off] == 0x2C else 'brtrue.s'} IL_0000\n"
                        f"EXPLANATION: branch check\n"
                        f"CONFIDENCE: high\n"
                    )
                    parsed = _parse_round2(resp, ev=ev, target_name=m["name"])
                    self.assertIsNotNone(parsed)
                    self.assertEqual(parsed["strategy"], "patch-branch")
                    self.assertEqual(parsed["offset"], off)
                    self.assertEqual(parsed["original"], body[off:off + 2].hex())
                    self.assertTrue(verify_patch(ev, parsed)["valid"])
                    return
        self.skipTest("No brfalse.s/brtrue.s found in first 400 methods")


if __name__ == "__main__":
    unittest.main(verbosity=2)
