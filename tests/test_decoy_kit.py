"""Decoy Kit tests (.NET compilation with real csc.exe + scanner + compare).

    python tests/test_decoy_kit.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanner import collect, estimate, scan  # noqa: E402
from scanner.compare import compare  # noqa: E402
from scanner.evidence import Evidence  # noqa: E402
from scanner.il import call_tokens  # noqa: E402

DECOY_CS = ROOT / "sdk" / "dotnet" / "TrapKeyDecoy.cs"
DECOY_H = ROOT / "sdk" / "cpp" / "trapkey_decoy.h"


def _find_csc() -> str | None:
    win = Path(os.environ.get("WINDIR") or "C:/Windows")
    for arch in ("Framework64", "Framework"):
        cand = win / "Microsoft.NET" / arch / "v4.0.30319" / "csc.exe"
        if cand.is_file():
            return str(cand)
    return None


CSC = _find_csc()

BASELINE_CS = """\
using System;

namespace DemoApp
{
    public static class Program
    {
        public static bool CheckLicense(string key)
        {
            return !string.IsNullOrEmpty(key) && key.StartsWith("PRO-");
        }

        public static int Main(string[] args)
        {
            string key = args.Length > 0 ? args[0] : "PRO-1234";
            if (!CheckLicense(key))
            {
                Console.WriteLine("Invalid license");
                return 1;
            }
            Console.WriteLine("Licensed OK");
            return 0;
        }
    }
}
"""

PROTECTED_CS = """\
using System;
using TrapKey.Decoy;

namespace DemoApp
{
    public static class Program
    {
        public static bool CheckLicense(string key)
        {
            return !string.IsNullOrEmpty(key) && key.StartsWith("PRO-");
        }

        private static bool FeatureA(string key) { return TrapKeyDecoy.Verify(key, 1, (k, s) => CheckLicense(k)); }
        private static bool FeatureB(string key) { return TrapKeyDecoy.Verify(key, 2, (k, s) => CheckLicense(k)); }
        private static bool FeatureC(string key) { return TrapKeyDecoy.Verify(key, 3, (k, s) => CheckLicense(k)); }
        private static bool FeatureD(string key) { return TrapKeyDecoy.Verify(key, 4, (k, s) => CheckLicense(k)); }

        public static int Main(string[] args)
        {
            TrapKeyDecoy.Warmup();
            string key = args.Length > 0 ? args[0] : "PRO-1234";
            if (!TrapKeyDecoy.Verify(key, 0, (k, s) => CheckLicense(k)))
            {
                Console.WriteLine("Invalid license");
                return 1;
            }
            TrapKeyDecoy.ScheduleDelayedCheck(() => CheckLicense(key), () => Environment.Exit(1));
            if (FeatureA(key) && FeatureB(key) && FeatureC(key) && FeatureD(key))
            {
                Console.WriteLine("Licensed OK");
                return 0;
            }
            return 2;
        }
    }
}
"""

WEAK_CS = """\
using System;
using TrapKey.Decoy;

namespace DemoApp
{
    public static class Program
    {
        public static bool CheckLicense(string key)
        {
            return !string.IsNullOrEmpty(key) && key.StartsWith("PRO-");
        }

        public static int Main(string[] args)
        {
            TrapKeyDecoy.Warmup();
            string key = args.Length > 0 ? args[0] : "PRO-1234";
            return TrapKeyDecoy.Verify(key, 0, (k, s) => CheckLicense(k)) ? 0 : 1;
        }
    }
}
"""


class DecoyFilesExistTests(unittest.TestCase):
    def test_sdk_files_exist_with_expected_apis(self):
        self.assertTrue(DECOY_CS.is_file())
        cs = DECOY_CS.read_text(encoding="utf-8")
        for sym in (
            "TrapKeyDecoy",
            "Warmup",
            "Verify",
            "ScheduleDelayedCheck",
            "ValidateLicenseToken",
            "VerifyActivationSignature",
            "CheckTrialExpiration",
            "VerifyHardwareBinding",
            "VerifySubscriptionState",
            "CheckOfflineLease",
            "ValidateSerialChecksum",
            "VerifyEntitlementSlice",
            "MethodImplOptions.NoInlining",
        ):
            self.assertIn(sym, cs)

        self.assertTrue(DECOY_H.is_file())
        h = DECOY_H.read_text(encoding="utf-8")
        for sym in (
            "TK_DECOY_V1",
            "TK_DECOY_NOINLINE",
            "warmup",
            "verify_slice",
            "schedule_delayed_check",
            "validate_license_token",
            "verify_entitlement_slice",
        ):
            self.assertIn(sym, h)


class ILCallTokensTests(unittest.TestCase):
    def test_call_tokens_walks_opcodes_without_matching_constant_bytes(self):
        # ldarg.0 (0x02), ldc.i4 0x11223328 (0x20 + 0x28 0x33 0x22 0x11 -> contains 0x28!),
        # call 0x06000007 (0x28 + LE 0x06000007), ret (0x2A)
        body = bytes([0x02, 0x20, 0x28, 0x33, 0x22, 0x11, 0x28, 0x07, 0x00, 0x00, 0x06, 0x2A])
        self.assertEqual(call_tokens(body), [0x06000007])


class NativeDecoyDetectionTests(unittest.TestCase):
    def test_native_decoy_marker_triggers_protection_and_increases_cost(self):
        base = Evidence(path="native.exe", size=50_000, sha256="a" * 64, kind="native")
        base.stats = {"strings_chars": 5000, "license_strings": 2}

        decoy = Evidence(path="native_decoy.exe", size=50_000, sha256="b" * 64, kind="native")
        decoy.stats = {
            "strings_chars": 5000,
            "license_strings": 2,
            "decoy_kit": {
                "active": True,
                "kind": "native",
                "decoys": 8,
                "check_points": 5,
                "delayed": True,
            },
        }
        est_base = estimate(base)
        est_decoy = estimate(decoy)
        self.assertGreater(est_decoy.best, est_base.best)
        self.assertLess(est_decoy.p_success, est_base.p_success)
        self.assertTrue(any("Decoy Kit" in n for n in est_decoy.breakdown))


@unittest.skipUnless(CSC is not None, "csc.exe not installed")
class RealDotNetDecoyTests(unittest.TestCase):
    def _compile(self, tmp: Path, name: str, sources: list[Path]) -> Path:
        out = tmp / f"{name}.exe"
        cmd = [CSC, "/nologo", "/optimize+", f"/out:{out}", *[str(s) for s in sources]]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, f"csc failed:\n{proc.stdout}\n{proc.stderr}")
        return out

    def test_compiled_decoy_kit_detected_and_beats_baseline_in_compare(self):
        with tempfile.TemporaryDirectory(prefix="tk-decoy-") as td:
            tmp = Path(td)
            base_cs = tmp / "Base.cs"
            prot_cs = tmp / "Prot.cs"
            weak_cs = tmp / "Weak.cs"
            base_cs.write_text(BASELINE_CS, encoding="utf-8")
            prot_cs.write_text(PROTECTED_CS, encoding="utf-8")
            weak_cs.write_text(WEAK_CS, encoding="utf-8")

            base_exe = self._compile(tmp, "Base", [base_cs])
            prot_exe = self._compile(tmp, "Prot", [prot_cs, DECOY_CS])
            weak_exe = self._compile(tmp, "Weak", [weak_cs, DECOY_CS])

            # 1. Baseline has no decoy kit
            base_rep = scan(str(base_exe))
            self.assertIsNone(base_rep["evidence"].get("decoy_kit"))

            # 2. Protected exe has 8 decoys, >=5 check points, and delayed check
            prot_ev = collect(str(prot_exe))
            dk = prot_ev.stats.get("decoy_kit")
            self.assertIsNotNone(dk)
            self.assertTrue(dk["active"])
            self.assertEqual(dk["decoys"], 8)
            self.assertGreaterEqual(dk["check_points"], 5)
            self.assertTrue(dk["delayed"])
            self.assertIn("decoy-kit", prot_ev.markers)
            self.assertTrue(prot_ev.has("decoy-kit"))
            self.assertFalse(prot_ev.has("decoy-weak-coverage"))

            # 3. Weak integration (only 1 Verify call) triggers decoy-weak-coverage
            weak_ev = collect(str(weak_exe))
            self.assertEqual(weak_ev.stats["decoy_kit"]["check_points"], 1)
            self.assertTrue(weak_ev.has("decoy-weak-coverage"))

            # 4. Compare baseline vs protected -> verdict "better"
            diff = compare(str(base_exe), str(prot_exe))
            self.assertEqual(diff["verdict"], "better", diff)
            self.assertGreater(diff["delta"]["seconds_best"], 0)
            self.assertLess(diff["delta"]["p_success"], 0)
            self.assertLess(diff["delta"]["risk"], 0)
            added_ids = [f["id"] for f in diff["protection_added"]]
            self.assertIn("decoy-kit", added_ids)

            # 5. Execute the compiled Protected exe to prove it still runs cleanly
            run_ok = subprocess.run([str(prot_exe), "PRO-9999"], capture_output=True, text=True, check=False)
            self.assertEqual(run_ok.returncode, 0, run_ok.stdout + run_ok.stderr)
            self.assertIn("Licensed OK", run_ok.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
