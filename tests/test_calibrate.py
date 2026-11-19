"""Calibration tests: the fitting math and the CLI (static mode, no network).

    python3 tests/test_calibrate.py
"""

from __future__ import annotations

import os
import math
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from calibrate import collect_files, fit_multiplier, model_key_for, summarize_attempts  # noqa: E402
from scanner import collect, estimate  # noqa: E402


def _find_binary(name: str, env_var: str) -> str:
    candidates: list[Path] = []
    if os.environ.get(env_var):
        candidates.append(Path(os.environ[env_var]))
    if os.environ.get("TRAPKEY_TEST_BINARIES"):
        candidates.append(Path(os.environ["TRAPKEY_TEST_BINARIES"]) / name)
    win = Path(os.environ.get("WINDIR") or "C:/Windows")
    candidates += [win / "System32" / name, Path("/mnt/c/Windows/System32") / name]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[-1])

NOTEPAD = _find_binary("notepad.exe", "TRAPKEY_TEST_EXE")
HOSTNAME = _find_binary("hostname.exe", "TRAPKEY_TEST_HOSTNAME")


class FitTests(unittest.TestCase):
    def row(self, model, measured, tool=20.0, success=True):
        return {
            "model_seconds": model,
            "measured": measured,
            "tool_seconds": tool,
            "success": success,
        }

    def test_no_measurements(self):
        fit = fit_multiplier([self.row(70, None), self.row(60, None)])
        self.assertIsNone(fit["k"])
        self.assertEqual(fit["n"], 0)

    def test_perfect_match_is_k_one(self):
        # variable part 50s; measured excludes tool time, so 50s -> k=1
        fit = fit_multiplier([self.row(70, 50, tool=20), self.row(120, 100, tool=20)])
        self.assertAlmostEqual(fit["k"], 1.0, places=2)

    def test_model_too_fast_needs_k_above_one(self):
        # model variable 50s, measured 120s -> k=2.4
        fit = fit_multiplier([self.row(70, 120, tool=20)])
        self.assertAlmostEqual(fit["k"], 2.4, places=2)

    def test_model_too_slow_needs_k_below_one(self):
        # model variable 100s, measured 70s -> k=0.7
        fit = fit_multiplier([self.row(120, 70, tool=20)])
        self.assertAlmostEqual(fit["k"], 0.7, places=2)

    def test_measurement_faster_than_tool_time_does_not_collapse(self):
        # Regression: measured used to have tool time subtracted from it, so a
        # 15s call on a 22s-tool binary clamped to k=0.02.
        fit = fit_multiplier([self.row(72, 15, tool=22)])
        self.assertAlmostEqual(fit["k"], 15 / 50, places=2)
        self.assertGreater(fit["k"], 0.25)

    def test_geometric_mean_not_arithmetic(self):
        # ratios 2.0 and 0.5 -> geomean 1.0, arithmetic would be 1.25
        fit = fit_multiplier([self.row(70, 100, tool=20), self.row(70, 25, tool=20)])
        self.assertAlmostEqual(fit["k"], 1.0, places=2)
        self.assertEqual(fit["n"], 2)

    def test_failures_are_excluded(self):
        fit = fit_multiplier([self.row(70, 120, tool=20), self.row(80, 5, tool=20, success=False)])
        self.assertEqual(fit["n"], 1)
        self.assertAlmostEqual(fit["k"], 2.4, places=2)

    def test_tool_time_is_not_scaled(self):
        # Same variable part (40s) and the same measured call (70s); only the
        # fixed tool cost differs -> identical k.
        a = fit_multiplier([self.row(50, 70, tool=10)])
        b = fit_multiplier([self.row(90, 70, tool=50)])
        self.assertAlmostEqual(a["k"], b["k"], places=2)
        self.assertAlmostEqual(a["k"], 1.75, places=2)

    def test_local_model_fits_the_local_band(self):
        self.assertEqual(model_key_for({"local": True}), "local-20b")
        self.assertEqual(model_key_for({"local": False}), "cloud-fast")

    def test_fit_uses_the_measured_workload(self):
        # 10s measured vs 20s of predicted work for the same token count -> k=0.5.
        fit = fit_multiplier(
            [{
                "model_seconds": 70,
                "measured": 10,
                "tool_seconds": 20,
                "workload_seconds": 20,
                "success": True,
            }]
        )
        self.assertAlmostEqual(fit["k"], 0.5, places=2)

    def test_repeats_use_the_median(self):
        results = [
            {"seconds": 4.0, "success": True, "model": "m",
             "usage": {"prompt_tokens": 8000, "completion_tokens": 100}},
            {"seconds": 2.0, "success": True, "model": "m",
             "usage": {"prompt_tokens": 8000, "completion_tokens": 200}},
            {"seconds": 2.2, "success": True, "model": "m",
             "usage": {"prompt_tokens": 9000, "completion_tokens": 300}},
        ]
        summary = summarize_attempts(results)
        self.assertAlmostEqual(summary["seconds"], 2.2, places=2)
        self.assertEqual(summary["successes"], 3)
        self.assertEqual(summary["input_tokens"], 9000)
        self.assertEqual(summary["output_tokens"], 300)
        self.assertTrue(summary["success"])

    def test_error_attempts_are_dropped(self):
        results = [
            {"error": "boom"},
            {"seconds": 3.0, "success": True, "model": "m"},
            {"seconds": 3.4, "success": True, "model": "m"},
        ]
        summary = summarize_attempts(results)
        self.assertAlmostEqual(summary["seconds"], 3.2, places=2)
        self.assertEqual(summary["attempts"], 2)

    def test_all_errors_are_reported(self):
        self.assertIn("error", summarize_attempts([{"error": "down"}]))


class CalibrationKFitsEstimateTests(unittest.TestCase):
    ENV = ("TRAPKEY_CALIBRATION_K", "TRAPKEY_CALIBRATION_MODEL")

    def setUp(self):
        self.saved = {k: os.environ.get(k) for k in self.ENV}

    def tearDown(self):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _clear(self):
        for key in self.ENV:
            os.environ.pop(key, None)

    def test_k_scales_only_the_variable_part(self):
        if not os.path.exists(NOTEPAD):
            self.skipTest("no notepad.exe")
        ev = collect(NOTEPAD)

        self._clear()
        base = estimate(ev)

        os.environ["TRAPKEY_CALIBRATION_K"] = "2"
        doubled = estimate(ev)

        tool = base.tool_seconds
        expected = tool + 2 * (base.best - tool)
        self.assertAlmostEqual(doubled.best, expected, delta=0.3)
        self.assertTrue(any("k=2" in note for note in doubled.breakdown))

    def test_k_only_scales_the_measured_band(self):
        if not os.path.exists(NOTEPAD):
            self.skipTest("no notepad.exe")
        ev = collect(NOTEPAD)

        self._clear()
        base = estimate(ev)

        os.environ["TRAPKEY_CALIBRATION_K"] = "2"
        os.environ["TRAPKEY_CALIBRATION_MODEL"] = "cloud-fast"
        scaled = estimate(ev)

        tool = base.tool_seconds
        self.assertAlmostEqual(
            scaled.seconds["cloud-fast"],
            tool + 2 * (base.seconds["cloud-fast"] - tool),
            delta=0.3,
        )
        for other in ("cloud-cheap", "local-20b"):
            self.assertAlmostEqual(scaled.seconds[other], base.seconds[other], delta=0.2)

    def test_invalid_k_is_neutralised(self):
        if not os.path.exists(NOTEPAD):
            self.skipTest("no notepad.exe")
        ev = collect(NOTEPAD)
        self._clear()
        base = estimate(ev)
        for bad in ("-2", "nan", "inf", "abc", "0"):
            os.environ["TRAPKEY_CALIBRATION_K"] = bad
            est = estimate(ev)
            for value in est.seconds.values():
                self.assertTrue(math.isfinite(value), f"{bad} produced {value}")
                self.assertGreaterEqual(value, 0, f"{bad} produced {value}")
            if bad == "abc":
                self.assertAlmostEqual(est.best, base.best, delta=0.1)


@unittest.skipUnless(os.path.exists(NOTEPAD), "no Windows binaries")
class CliTests(unittest.TestCase):
    def test_static_mode_over_a_directory(self):
        tmp = tempfile.mkdtemp(prefix="revscan-cal-")
        try:
            shutil.copy(NOTEPAD, Path(tmp) / "a.exe")
            if os.path.exists(HOSTNAME):
                shutil.copy(HOSTNAME, Path(tmp) / "b.exe")
            out = Path(tmp) / "result.json"
            proc = subprocess.run(
                [sys.executable, str(ROOT / "calibrate.py"), tmp, "--limit", "3", "--out", str(out)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("files:", proc.stdout)
            self.assertTrue(out.exists())
            import json

            payload = json.loads(out.read_text())
            self.assertGreaterEqual(len(payload["rows"]), 1)
            self.assertIn("fit", payload)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_empty_directory_exits_two(self):
        tmp = tempfile.mkdtemp(prefix="revscan-cal-empty-")
        try:
            proc = subprocess.run(
                [sys.executable, str(ROOT / "calibrate.py"), tmp],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(proc.returncode, 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
