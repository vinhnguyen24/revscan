"""Tests for `trapkey compare` — the protect -> rescan -> diff loop.

    python3 tests/test_compare.py

The CLI tests need a Windows binary; without one they skip. Nothing here talks
to a network or an AI provider: compare is the static cost model on both sides.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "cli"))

from scanner.compare import (  # noqa: E402
    classify_findings,
    from_reports,
    render,
    verdict_for,
    verdict_sentence,
)


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


def run_cli(*args: str, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / "cli" / "trapkey.py"), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def finding(fid: str, weight: int) -> dict:
    return {"id": fid, "detail": f"{fid} detail", "weight": weight, "fix": f"fix {fid}"}


class CompareLogicTests(unittest.TestCase):
    def test_classify_findings_splits_fixed_new_and_added(self):
        original = [finding("pdb-path", 15), finding("anti-debug", -8)]
        protected = [finding("anti-debug", -8), finding("deception-active", -15)]

        fixed, new, added, changed, removed = classify_findings(original, protected)
        self.assertEqual([f["id"] for f in fixed], ["pdb-path"])
        self.assertEqual(new, [], "new_findings is new leaks only")
        self.assertEqual([f["id"] for f in added], ["deception-active"])
        self.assertEqual(changed, [])
        self.assertEqual(removed, [])

    def test_classify_findings_ignores_surviving_and_positive_only_protection(self):
        original = [finding("license-literals", 12)]
        protected = [finding("license-literals", 12), finding("packed", -20)]
        fixed, new, added, changed, removed = classify_findings(original, protected)
        self.assertEqual(fixed, [])
        self.assertEqual(new, [])
        self.assertEqual([f["id"] for f in added], ["packed"])
        self.assertEqual(changed, [])
        self.assertEqual(removed, [])

    def test_classify_findings_surfaces_weight_changes_and_removed_guards(self):
        original = [finding("license-literals", 4), finding("anti-debug", -8)]
        protected = [finding("license-literals", 20)]
        fixed, new, added, changed, removed = classify_findings(original, protected)
        self.assertEqual(fixed, [])
        self.assertEqual(new, [])
        self.assertEqual(added, [])
        self.assertEqual([c["id"] for c in changed], ["license-literals"])
        self.assertEqual(changed[0]["delta_weight"], 16)
        self.assertEqual([f["id"] for f in removed], ["anti-debug"])

    def test_unchanged_score_with_a_fixed_leak_does_not_say_not_better(self):
        result = {
            "delta": {"seconds_best": 0.0, "p_success": 0.0, "risk": 0},
            "verdict": "unchanged",
            "original": {"p_success": 0.35, "markers": []},
            "protected": {"p_success": 0.35, "markers": []},
            "protection_added": [],
            "fixed_findings": [finding("pdb-path", 15)],
        }
        sentence = verdict_sentence(result)
        self.assertIn("leak", sentence)
        self.assertNotIn("not better protected", sentence)

    def test_verdict_three_states(self):
        cases = [
            ({"seconds_best": 0.0, "p_success": 0.0, "risk": 0}, "unchanged"),
            ({"seconds_best": 0.2, "p_success": 0.0, "risk": 0}, "unchanged"),  # rounding noise
            ({"seconds_best": 10.0, "p_success": 0.0, "risk": -10}, "better"),
            ({"seconds_best": -10.0, "p_success": 0.0, "risk": 10}, "worse"),
            ({"seconds_best": 0.0, "p_success": -0.30, "risk": -18}, "better"),
            ({"seconds_best": 0.0, "p_success": 0.30, "risk": 18}, "worse"),
            # Time and success disagree -> combined risk decides.
            ({"seconds_best": 10.0, "p_success": 0.30, "risk": -5}, "better"),
            ({"seconds_best": 10.0, "p_success": 0.30, "risk": 5}, "worse"),
        ]
        for delta, expected in cases:
            with self.subTest(delta=delta):
                self.assertEqual(verdict_for(delta), expected)


class CompareErrorTests(unittest.TestCase):
    def test_missing_file_exits_2(self):
        proc = run_cli("compare", "/nonexistent/original.exe", "/nonexistent/protected.exe")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("not found", proc.stderr)
        self.assertEqual(proc.stdout.strip(), "")

    def test_invalid_pe_exits_2(self):
        tmp = Path(tempfile.mkdtemp(prefix="trapkey-compare-bad-"))
        try:
            bad = tmp / "not-a-pe.exe"
            bad.write_bytes(b"this is not a PE file")
            proc = run_cli("compare", str(bad), str(bad))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("not a PE", proc.stderr)
            self.assertEqual(proc.stdout.strip(), "")

            empty = tmp / "empty.exe"
            empty.write_bytes(b"")
            proc = run_cli("compare", str(empty), str(empty))
            self.assertEqual(proc.returncode, 2)
            self.assertIn("not a PE", proc.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_directory_is_not_reported_as_missing(self):
        with tempfile.TemporaryDirectory(prefix="trapkey-compare-dir-") as tmp:
            proc = run_cli("compare", tmp, tmp)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("is not a file", proc.stderr)
        self.assertNotIn("not found", proc.stderr)


@unittest.skipUnless(os.path.exists(NOTEPAD), "no Windows binary")
def report(best: float, p: float, risk: int, sha: str, findings: list[dict]) -> dict:
    return {
        "file": f"{sha}.exe",
        "sha256": sha,
        "kind": "native",
        "size": 1234,
        "crack_seconds_best": best,
        "crack_seconds_worst": best * 3,
        "p_success": p,
        "risk": risk,
        "read_budget_tokens": 60000,
        "markers": [],
        "findings": findings,
    }


class CompareReportsTests(unittest.TestCase):
    def test_from_reports_diffs_two_scan_json_objects(self):
        before = report(70.0, 0.35, 21, "a" * 64, [finding("pdb-path", 15)])
        after = report(85.0, 0.05, 3, "b" * 64, [])
        data = from_reports(before, after)
        self.assertEqual(data["delta"]["seconds_best"], 15.0)
        self.assertEqual(data["delta"]["p_success"], -0.3)
        self.assertEqual(data["delta"]["risk"], -18)
        self.assertEqual([f["id"] for f in data["fixed_findings"]], ["pdb-path"])
        self.assertEqual(data["verdict"], "better")

    def test_measured_block_is_separate_from_the_cost_model(self):
        before = report(70.0, 0.35, 21, "a" * 64, [])
        after = report(85.0, 0.05, 3, "b" * 64, [])
        before["measured"] = {
            "seconds": 8.5,
            "provider": "openai",
            "model": "gpt-6-luna",
            "success": True,
            "grounded": True,
            "usage": {"prompt_tokens": 100, "completion_tokens": 7},
            "attempts": 3,
        }
        after["measured"] = {
            "seconds": 13.0,
            "provider": "openai",
            "model": "gpt-6-luna",
            "success": True,
            "grounded": True,
            "usage": {"prompt_tokens": 110, "completion_tokens": 9},
            "attempts": 3,
        }
        data = from_reports(before, after)
        self.assertEqual(data["ai"]["delta_seconds"], 4.5)
        self.assertTrue(data["ai"]["original_success"])
        self.assertTrue(data["ai"]["protected_success"])
        self.assertIn("took +4.50s longer", data["ai"]["verdict"])
        self.assertEqual(data["ai"]["attempts"], 3)
        self.assertTrue(any("median of 3 rounds" in n for n in data["notes"]))
        # The cost-model delta is untouched; the AI number is a separate axis.
        self.assertEqual(data["delta"]["seconds_best"], 15.0)
        text = render(data)
        self.assertIn("AI measured 8.5s", text)
        self.assertIn("ai measured 8.50s -> 13.00s", text)

    def test_ai_no_change_does_not_confirm_static_better(self):
        before = report(70.0, 0.35, 21, "a" * 64, [])
        after = report(85.0, 0.05, 3, "b" * 64, [])
        before["measured"] = {"seconds": 8.5, "model": "m", "success": True, "attempts": 3}
        after["measured"] = {"seconds": 8.9, "model": "m", "success": True, "attempts": 3}
        data = from_reports(before, after)
        self.assertIn("no meaningful change", data["ai"]["verdict"])
        self.assertTrue(any("does not confirm" in n for n in data["notes"]))

    def test_ai_one_round_is_not_a_significant_change(self):
        before = report(70.0, 0.35, 21, "a" * 64, [])
        after = report(85.0, 0.05, 3, "b" * 64, [])
        before["measured"] = {"seconds": 8.5, "model": "m", "success": True}
        after["measured"] = {"seconds": 20.0, "model": "m", "success": True}
        data = from_reports(before, after)
        self.assertIn("within noise", data["ai"]["verdict"])
        self.assertNotIn("longer", data["ai"]["verdict"])
        self.assertTrue(any("does not confirm" in n for n in data["notes"]))

    def test_measured_on_one_side_only_is_a_note(self):
        before = report(70.0, 0.35, 21, "a" * 64, [])
        after = report(85.0, 0.05, 3, "b" * 64, [])
        before["measured"] = {"seconds": 8.5, "model": "m", "success": True}
        data = from_reports(before, after)
        self.assertIsNone(data["ai"])
        self.assertTrue(any("one side only" in n for n in data["notes"]))

    def test_ai_protected_no_longer_finds_the_check(self):
        before = report(70.0, 0.35, 21, "a" * 64, [])
        after = report(85.0, 0.05, 3, "b" * 64, [])
        before["measured"] = {"seconds": 8.5, "model": "m", "success": True}
        after["measured"] = {"seconds": 2.0, "model": "m", "success": False}
        data = from_reports(before, after)
        self.assertIn("no longer yields a find", data["ai"]["verdict"])

    def test_bad_measured_block_is_ignored(self):
        before = report(70.0, 0.35, 21, "a" * 64, [])
        after = report(85.0, 0.05, 3, "b" * 64, [])
        before["measured"] = {"seconds": "not-a-number"}
        after["measured"] = {"seconds": 9.8}
        data = from_reports(before, after)
        self.assertIsNone(data["ai"])
        self.assertTrue(any("one side only" in n for n in data["notes"]))

    def test_bad_attempts_is_ignored_not_rejected(self):
        # `attempts` is display-only; int(dict)/int("many")/int(inf) used to
        # escape as a TypeError and reject a report that was otherwise valid.
        before = report(70.0, 0.35, 21, "a" * 64, [])
        after = report(85.0, 0.05, 3, "b" * 64, [])
        before["measured"] = {"seconds": 8.5, "attempts": {"x": 1}}
        after["measured"] = {"seconds": 9.0, "attempts": "many"}
        data = from_reports(before, after)
        self.assertIsNotNone(data["ai"])
        self.assertEqual(data["ai"]["attempts"], 1)

    def test_rounds_note_is_per_side(self):
        before = report(70.0, 0.35, 21, "a" * 64, [])
        after = report(85.0, 0.05, 3, "b" * 64, [])
        before["measured"] = {"seconds": 8.5, "success": True, "attempts": 1}
        after["measured"] = {"seconds": 20.0, "success": True, "attempts": 3}
        data = from_reports(before, after)
        self.assertTrue(any("1 vs 3 rounds" in n for n in data["notes"]))
        # One side has a single round, so the difference is not significant.
        self.assertIn("within noise", data["ai"]["verdict"])

    def test_measure_side_times_successful_rounds_only(self):
        import scanner.ai as ai_module
        from scanner.compare import _measure_side

        rounds = iter([
            {"seconds": 8.0, "success": True, "grounded": True, "model": "m"},
            {"seconds": 1.0, "success": False, "grounded": False, "model": "m"},
            {"seconds": 10.0, "success": True, "grounded": True, "model": "m"},
        ])
        saved = ai_module.measure
        ai_module.measure = lambda ev: next(rounds)
        try:
            combined = _measure_side(None, 3)
        finally:
            ai_module.measure = saved
        # Median of the two successful rounds, not [8, 1, 10] = 8.
        self.assertEqual(combined["seconds"], 9.0)
        self.assertTrue(combined["success"])
        self.assertEqual(combined["successes"], 2)
        self.assertEqual(combined["attempts"], 3)

    def test_from_reports_rejects_a_non_report(self):
        with self.assertRaises(ValueError):
            from_reports({"hello": "world"}, report(1, 0.1, 1, "a" * 64, []))

    def test_from_reports_rejects_non_numeric_fields(self):
        bad = report(70.0, 0.35, 21, "a" * 64, [])
        bad["crack_seconds_best"] = "abc"
        with self.assertRaises(ValueError):
            from_reports(bad, report(80.0, 0.05, 3, "b" * 64, []))
        bad = report(70.0, 0.35, 21, "a" * 64, [])
        bad["findings"] = ["not-an-object"]
        with self.assertRaises(ValueError):
            from_reports(bad, report(80.0, 0.05, 3, "b" * 64, []))

    def test_missing_sha_does_not_claim_same_file(self):
        before = report(70.0, 0.35, 21, "", [])
        after = report(85.0, 0.05, 3, "", [])
        data = from_reports(before, after)
        self.assertFalse(data["same_file"])
        self.assertFalse(any("same sha256" in n for n in data["notes"]))

    def test_cli_compare_reports_reads_json_files(self):
        before = report(70.0, 0.35, 21, "a" * 64, [finding("pdb-path", 15)])
        after = report(85.0, 0.05, 3, "b" * 64, [])
        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp) / "before.json"
            a = Path(tmp) / "after.json"
            b.write_text(json.dumps(before), encoding="utf-8")
            a.write_text(json.dumps(after), encoding="utf-8")
            proc = run_cli("compare-reports", str(b), str(a), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["delta"]["seconds_best"], 15.0)
        self.assertEqual(data["verdict"], "better")

    def test_cli_compare_reports_same_file_warns_on_stderr(self):
        one = report(70.0, 0.35, 21, "a" * 64, [])
        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp) / "before.json"
            a = Path(tmp) / "after.json"
            b.write_text(json.dumps(one), encoding="utf-8")
            a.write_text(json.dumps(one), encoding="utf-8")
            proc = run_cli("compare-reports", str(b), str(a), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["verdict"], "unchanged")
        self.assertIn("same sha256", proc.stderr)

    def test_cli_compare_reports_bad_json_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            b = Path(tmp) / "before.json"
            a = Path(tmp) / "after.json"
            b.write_text("{nope", encoding="utf-8")
            a.write_text("{}", encoding="utf-8")
            proc = run_cli("compare-reports", str(b), str(a), "--json")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")


class CompareCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="trapkey-compare-"))
        cls.src = cls.tmp / "app.exe"
        cls.protected = cls.tmp / "app.protected.exe"
        shutil.copy(NOTEPAD, cls.src)
        proc = run_cli("protect", str(cls.src), "--level", "3", "--out", str(cls.protected))
        if proc.returncode != 0:
            shutil.rmtree(cls.tmp, ignore_errors=True)
            raise unittest.SkipTest(f"protect failed here: {proc.stderr.strip()[:200]}")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_json_shape_and_delta(self):
        proc = run_cli("compare", str(self.src), str(self.protected), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)

        for key in (
            "ok", "original", "protected", "delta",
            "fixed_findings", "new_findings", "protection_added",
            "changed_findings", "protection_removed",
        ):
            self.assertIn(key, data)
        self.assertTrue(data["ok"])

        for side in ("original", "protected"):
            for key in (
                "file", "sha256", "kind", "size", "crack_seconds_best",
                "crack_seconds_worst", "p_success", "risk",
                "read_budget_tokens", "findings",
            ):
                self.assertIn(key, data[side])
            self.assertIsInstance(data[side]["size"], int)
            self.assertIsInstance(data[side]["risk"], int)
            self.assertIsInstance(data[side]["findings"], list)
            for f in data[side]["findings"]:
                self.assertEqual(set(f), {"id", "detail", "weight", "fix"})

        for key in ("seconds_best", "seconds_worst", "p_success", "risk"):
            self.assertIsInstance(data["delta"][key], (int, float))
            self.assertNotIsInstance(data["delta"][key], bool)

        self.assertNotEqual(data["original"]["sha256"], data["protected"]["sha256"])
        self.assertFalse(data["same_file"])
        self.assertIn(data["verdict"], ("better", "worse", "unchanged"))
        self.assertNotIn("NaN", proc.stdout)

        # Protect must not make the model think cracking is cheaper/easier.
        self.assertGreaterEqual(
            data["protected"]["crack_seconds_best"] + 0.05,
            data["original"]["crack_seconds_best"],
        )
        self.assertLessEqual(data["protected"]["risk"], data["original"]["risk"])

        # The delta must be consistent with the sides (rounded like the model).
        self.assertAlmostEqual(
            data["delta"]["seconds_best"],
            round(data["protected"]["crack_seconds_best"] - data["original"]["crack_seconds_best"], 1),
            places=6,
        )
        self.assertAlmostEqual(
            data["delta"]["p_success"],
            round(data["protected"]["p_success"] - data["original"]["p_success"], 2),
            places=6,
        )

    def test_json_is_exactly_one_object(self):
        proc = run_cli("compare", str(self.src), str(self.protected), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = proc.stdout.lstrip()
        obj, end = json.JSONDecoder().raw_decode(payload)
        self.assertIsInstance(obj, dict)
        self.assertEqual(payload[end:].strip(), "", "stdout must contain one JSON object only")

    def test_human_output_is_honest(self):
        proc = run_cli("compare", str(self.src), str(self.protected))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("delta", proc.stdout)
        self.assertIn("verdict", proc.stdout)
        self.assertIn("cost model", proc.stdout)
        self.assertNotIn("uncrackable", proc.stdout.lower())

    def test_same_file_twice_sets_same_file(self):
        proc = run_cli("compare", str(self.src), str(self.src), "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["same_file"])
        self.assertEqual(
            data["delta"],
            {"seconds_best": 0.0, "seconds_worst": 0.0, "p_success": 0.0, "risk": 0},
        )
        self.assertEqual(data["verdict"], "unchanged")
        self.assertTrue(any("same sha256" in n for n in data["notes"]))
        self.assertIn("same sha256", proc.stderr)

    def test_same_file_human_says_it_is_not_better_protected(self):
        proc = run_cli("compare", str(self.src), str(self.src))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("not better protected", proc.stdout)
        self.assertIn("same sha256", proc.stderr)
        # The caveat lives on stderr only; repeating it as a note was noise.
        self.assertNotIn("both paths have the same sha256", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
