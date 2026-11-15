"""Ground-truth benchmark harness tests. No network, no real AI provider.

    python3 tests/test_benchmark.py
"""

from __future__ import annotations

import json
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import benchmark as bm  # noqa: E402
from scanner import collect  # noqa: E402
from scanner.peinfo import PEError  # noqa: E402


def _find_dotnet_assembly(name: str = "System.dll", env_var: str = "TRAPKEY_TEST_SYSTEM_DLL") -> str:
    candidates: list[Path] = []
    if os.environ.get(env_var):
        candidates.append(Path(os.environ[env_var]))
    if os.environ.get("TRAPKEY_TEST_BINARIES"):
        candidates.append(Path(os.environ["TRAPKEY_TEST_BINARIES"]) / name)
    win = Path(os.environ.get("WINDIR") or "C:/Windows")
    candidates += [
        win / "Microsoft.NET" / "Framework64" / "v4.0.30319" / name,
        win / "Microsoft.NET" / "Framework" / "v4.0.30319" / name,
        Path("/mnt/c/Windows/Microsoft.NET/Framework64/v4.0.30319") / name,
        Path("/mnt/c/Windows/Microsoft.NET/Framework/v4.0.30319") / name,
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[-1])


SYSTEM_DLL = _find_dotnet_assembly()


class NormalizeTests(unittest.TestCase):
    def test_type_prefix(self):
        self.assertEqual(bm.normalize_name("Type::CheckLicense"), "checklicense")

    def test_namespace_dot(self):
        self.assertEqual(bm.normalize_name("Namespace.Type.CheckLicense"), "checklicense")

    def test_module_prefix(self):
        self.assertEqual(bm.normalize_name("foo.dll!CheckLicense"), "checklicense")

    def test_case_insensitive(self):
        self.assertEqual(bm.normalize_name("CHECKLICENSE"), bm.normalize_name("checklicense"))

    def test_hex_prefix_and_leading_zeros(self):
        self.assertEqual(bm.normalize_name("0x140012340"), "140012340")
        self.assertEqual(bm.normalize_name("0x000140012340"), bm.normalize_name("0x140012340"))
        self.assertEqual(bm.normalize_name("0X140012340"), "140012340")

    def test_trailing_punctuation_and_generic_arity(self):
        self.assertEqual(bm.normalize_name("CheckLicense,"), "checklicense")
        self.assertEqual(bm.normalize_name("`CheckLicense`"), "checklicense")
        self.assertEqual(bm.normalize_name("Check`1"), "check")

    def test_parse_function_value(self):
        text = "Thinking...\nFUNCTION: Checker::Validate\nALGORITHM: compares hashes"
        self.assertEqual(bm.parse_function_value(text), "Checker::Validate")
        self.assertEqual(bm.parse_function_value("no function here"), "")
        # Markdown/numbered/spaced headers are common model output; scoring
        # them as `none` silently deflated recall.
        for text in (
            "**FUNCTION:** CheckLicense",
            "**FUNCTION**: CheckLicense",
            "1. FUNCTION: CheckLicense",
            "FUNCTION : CheckLicense",
            "FUNCTION - CheckLicense",
        ):
            self.assertEqual(bm.parse_function_value(text), "CheckLicense", text)
        # Generic arity must survive parsing so normalize_name can strip it.
        self.assertEqual(bm.parse_function_value("FUNCTION: Validate`1"), "Validate`1")
        self.assertTrue(bm.match_expected(["Validate`1"], "Validate`1"))

    def test_none_detection(self):
        for value in ("none", "NONE.", "unknown", "n/a", "None (no check)"):
            self.assertTrue(bm.is_none_answer(value), value)
        self.assertFalse(bm.is_none_answer("CheckLicense"))


class MatchingTests(unittest.TestCase):
    def test_expected_hit(self):
        self.assertTrue(bm.match_expected(["CheckLicense"], "Type::CheckLicense"))
        self.assertTrue(bm.match_expected(["0x140012340"], "0x000140012340"))

    def test_wrong_name_is_not_hit(self):
        self.assertFalse(bm.match_expected(["CheckLicense"], "ValidateSerial"))

    def test_none_is_not_a_hit_against_expected(self):
        self.assertFalse(bm.match_expected(["CheckLicense"], "none"))

    def test_static_named_source(self):
        match = bm.match_static(["IsKeyValid"], ["get_LicenseKey", "IsKeyValid"], [])
        self.assertIsNotNone(match)
        self.assertEqual(match["source"], "named_functions")
        self.assertEqual(match["value"], "IsKeyValid")

    def test_static_license_string_source(self):
        match = bm.match_static(
            ["Licence key is invalid"], [], ["Licence key is invalid", "trial expired"]
        )
        self.assertIsNotNone(match)
        self.assertEqual(match["source"], "license_strings")

    def test_static_prefix_stripped_name_matches_string(self):
        match = bm.match_static(["Type::CheckLicense"], [], ["CheckLicense failed"])
        self.assertIsNotNone(match)
        self.assertEqual(match["source"], "license_strings")

    def test_static_address_does_not_match_strings(self):
        self.assertIsNone(bm.match_static(["0x140012340"], [], ["140012340"]))

    def test_static_no_evidence(self):
        self.assertIsNone(bm.match_static(["CheckLicense"], [], []))

    def test_static_identifier_does_not_hit_inside_a_word(self):
        self.assertIsNone(bm.match_static(["Test"], [], ["latest build"]))
        self.assertIsNone(bm.match_static(["IsKeyValid"], [], ["IsKeyValidated"]))


class ScoringTests(unittest.TestCase):
    def _row(self, expected, allow_none, answer, mode="ai", latency=None):
        result, note = bm.classify_answer(expected, allow_none, answer)
        return {
            "file": "x.exe",
            "mode": mode,
            "expected": expected,
            "allow_none": allow_none,
            "answer": answer,
            "result": result,
            "source": mode,
            "latency": latency,
            "notes": [note] if note else [],
            "prompt_tokens": 100 if mode == "ai" else 0,
            "completion_tokens": 10 if mode == "ai" else 0,
        }

    def test_one_hit_one_miss_one_fp_one_correct_none(self):
        rows = [
            self._row(["CheckLicense"], False, "CheckLicense", latency=2.0),
            self._row(["CheckLicense"], False, "none", latency=4.0),
            self._row(["CheckLicense"], False, "ValidateSerial", latency=6.0),
            self._row([], True, "none", latency=8.0),
        ]
        summary = bm.summarize(rows)
        self.assertEqual(summary["evaluated"], 4)
        self.assertEqual(summary["hits"], 2)          # found it + correctly said none
        self.assertEqual(summary["hit_rate"], 0.5)
        self.assertEqual(summary["false_positives"], 1)
        self.assertEqual(summary["false_negatives"], 2)  # none + wrong name, both while expected
        self.assertEqual(summary["misses"], 1)
        self.assertEqual(summary["correct_none"], 1)
        self.assertEqual(summary["skipped"], 0)
        self.assertEqual(summary["prompt_tokens"], 400)
        self.assertEqual(summary["completion_tokens"], 40)
        self.assertEqual(summary["median_latency_seconds"], 5.0)
        self.assertEqual(summary["p95_latency_seconds"], 8.0)

    def test_answered_name_when_none_expected_is_false_positive(self):
        result, _ = bm.classify_answer([], True, "CheckLicense")
        self.assertEqual(result, bm.RESULT_FALSE_POSITIVE)

    def test_none_when_allow_none_false_is_miss(self):
        result, _ = bm.classify_answer([], False, "none")
        self.assertEqual(result, bm.RESULT_MISS)

    def test_skipped_rows_are_excluded(self):
        rows = [
            self._row(["CheckLicense"], False, "CheckLicense"),
            {"file": "y.exe", "mode": "ai", "expected": ["CheckLicense"],
             "result": bm.RESULT_SKIPPED, "latency": None, "prompt_tokens": 0,
             "completion_tokens": 0},
        ]
        summary = bm.summarize(rows)
        self.assertEqual(summary["evaluated"], 1)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["hits"], 1)

    def test_percentile_nearest_rank(self):
        self.assertEqual(bm.percentile([], 95), None)
        self.assertEqual(bm.percentile([5.0], 95), 5.0)
        self.assertEqual(bm.percentile([1, 2, 3, 4], 50), 2)
        self.assertEqual(bm.percentile([1, 2, 3, 4], 95), 4)


class AiScoringTests(unittest.TestCase):
    """evaluate_ai() parsing/scoring with a fake measure() — never a provider."""

    def _evaluate(self, spec, result):
        with mock.patch("scanner.ai.measure", return_value=result):
            return bm.evaluate_ai(
                Path("/tmp/Corpus/App.exe"), spec, object(), Path("/tmp/Corpus")
            )

    def test_labels_override_ai_success_and_grounded(self):
        row = self._evaluate(
            {"expect": ["CheckLicense"], "allow_none": False},
            {
                "seconds": 1.5,
                "success": False,
                "grounded": False,
                "output_sample": "FUNCTION: CheckLicense\nALGORITHM: compares a hash",
                "usage": {"prompt_tokens": 100, "completion_tokens": 5},
            },
        )
        self.assertEqual(row["result"], bm.RESULT_HIT)
        self.assertEqual(row["answer"], "CheckLicense")
        self.assertEqual(row["latency"], 1.5)
        self.assertEqual(row["prompt_tokens"], 100)
        self.assertEqual(row["completion_tokens"], 5)
        self.assertTrue(any("diagnostic only" in note for note in row["notes"]))

    def test_grounded_but_wrong_name_is_false_positive(self):
        row = self._evaluate(
            {"expect": ["CheckLicense"], "allow_none": False},
            {
                "seconds": 2.0,
                "success": True,
                "grounded": True,
                "output_sample": "FUNCTION: ValidateSerial\nALGORITHM: x",
                "usage": {},
            },
        )
        self.assertEqual(row["result"], bm.RESULT_FALSE_POSITIVE)

    def test_none_is_correct_when_labels_expect_no_check(self):
        row = self._evaluate(
            {"expect": [], "allow_none": True},
            {
                "seconds": 1.0,
                "success": False,
                "grounded": False,
                "output_sample": "FUNCTION: none",
                "usage": {},
            },
        )
        self.assertEqual(row["result"], bm.RESULT_HIT)

    def test_missing_function_line_is_scored_as_none(self):
        row = self._evaluate(
            {"expect": ["CheckLicense"], "allow_none": False},
            {
                "seconds": 1.0,
                "success": False,
                "grounded": False,
                "output_sample": "I could not find it.",
                "usage": {},
            },
        )
        self.assertEqual(row["result"], bm.RESULT_MISS)
        self.assertTrue(any("no FUNCTION" in note for note in row["notes"]))

    def test_call_error_is_skipped_not_miss(self):
        row = self._evaluate(
            {"expect": ["CheckLicense"], "allow_none": False},
            {"error": "quota exhausted", "error_code": "AI_QUOTA"},
        )
        self.assertEqual(row["result"], bm.RESULT_SKIPPED)
        self.assertTrue(any("AI_QUOTA" in note for note in row["notes"]))


class LabelTests(unittest.TestCase):
    def _write(self, payload) -> str:
        tmp = tempfile.mkdtemp(prefix="trapkey-labels-")
        self.addCleanup(shutil.rmtree, tmp, True)
        path = Path(tmp) / "labels.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return str(path)

    def test_list_form(self):
        labels = bm.load_labels(self._write({"files": {"App.exe": ["CheckLicense"]}}))
        self.assertEqual(labels["App.exe"]["expect"], ["CheckLicense"])
        self.assertFalse(labels["App.exe"]["allow_none"])

    def test_object_form_with_allow_none(self):
        labels = bm.load_labels(
            self._write({"files": {"App.exe": {"expect": [], "allow_none": True}}})
        )
        self.assertEqual(labels["App.exe"], {"expect": [], "allow_none": True})

    def test_empty_list_means_no_license(self):
        labels = bm.load_labels(self._write({"files": {"NoLicense.exe": []}}))
        self.assertEqual(labels["NoLicense.exe"], {"expect": [], "allow_none": True})

    def test_shipped_example_labels_are_valid(self):
        path = ROOT / "benchmarks" / "labels.example.json"
        labels = bm.load_labels(path)
        self.assertIn("App.exe", labels)
        self.assertIn("NoLicense.exe", labels)
        self.assertTrue(labels["NoLicense.exe"]["allow_none"])

    def test_relative_label_does_not_leak_to_other_basenames(self):
        tmp = Path(tempfile.mkdtemp(prefix="trapkey-labels-rel-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "sub").mkdir()
        labels = bm.load_labels(
            self._write({"files": {"sub/App.exe": {"expect": ["CheckLicense"]}}})
        )
        index = bm._label_index(labels)
        self.assertIsNotNone(bm.find_label(tmp / "sub" / "App.exe", tmp, index))
        # A top-level App.exe was never labelled; it must not inherit sub/App.exe.
        self.assertIsNone(bm.find_label(tmp / "App.exe", tmp, index))

    def test_missing_file(self):
        with self.assertRaises(bm.LabelError):
            bm.load_labels("/nonexistent/does-not-exist.json")

    def test_invalid_json(self):
        tmp = tempfile.mkdtemp(prefix="trapkey-labels-bad-")
        self.addCleanup(shutil.rmtree, tmp, True)
        path = Path(tmp) / "labels.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(bm.LabelError):
            bm.load_labels(str(path))

    def test_invalid_schema(self):
        bad_payloads = [
            [],
            {"files": []},
            {},
            {"files": {"App.exe": {"expect": "CheckLicense"}}},
            {"files": {"App.exe": {"expect": [1]}}},
            {"files": {"App.exe": {"expect": [] , "allow_none": "yes"}}},
            {"files": {"App.exe": {"expect": ["CheckLicense"], "allow_none": True}}},
            {"files": {"App.exe": 3}},
        ]
        for payload in bad_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(bm.LabelError):
                    bm.load_labels(self._write(payload))


class CorpusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="trapkey-corpus-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "sub").mkdir()
        (self.tmp / "a.exe").write_bytes(b"x" * 20_001)
        (self.tmp / "b.dll").write_bytes(b"x" * 25_000)
        (self.tmp / "sub" / "c.sys").write_bytes(b"x" * 21_000)
        (self.tmp / "small.exe").write_bytes(b"x" * 100)
        (self.tmp / "notes.txt").write_bytes(b"x" * 30_000)

    def test_discovery_filters_and_sorts(self):
        found = [path.relative_to(self.tmp).as_posix() for path in bm.discover_corpus(self.tmp)]
        self.assertEqual(found, ["a.exe", "b.dll", "sub/c.sys"])

    def test_limit_applies_after_sort(self):
        found = [path.relative_to(self.tmp).as_posix() for path in bm.discover_corpus(self.tmp, 2)]
        self.assertEqual(found, ["a.exe", "b.dll"])


@unittest.skipUnless(Path(SYSTEM_DLL).exists(), "no System.dll available")
class RealDotNetStaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path(SYSTEM_DLL)
        try:
            cls.ev = collect(str(cls.path))
        except (PEError, OSError) as err:
            raise unittest.SkipTest(f"System.dll unreadable: {err}")
        if not cls.ev.dotnet or not cls.ev.dotnet.ok:
            raise unittest.SkipTest("System.dll metadata unreadable")
        cls.named = [item["name"] for item in cls.ev.named_license_functions]
        if "IsKeyValid" not in cls.named:
            raise unittest.SkipTest("System.dll has no IsKeyValid method")

    def test_known_method_is_a_hit(self):
        spec = {"expect": ["IsKeyValid"], "allow_none": False}
        row = bm.evaluate_static(self.path, spec, self.ev, self.path.parent)
        self.assertEqual(row["result"], bm.RESULT_HIT, row)
        self.assertEqual(row["source"], "named_functions")

    def test_address_label_cannot_be_resolved_statically(self):
        spec = {"expect": ["0x140012340"], "allow_none": False}
        row = bm.evaluate_static(self.path, spec, self.ev, self.path.parent)
        self.assertEqual(row["result"], bm.RESULT_FALSE_POSITIVE, row)

    def test_no_license_expected_but_static_named_something_is_fp(self):
        spec = {"expect": [], "allow_none": True}
        row = bm.evaluate_static(self.path, spec, self.ev, self.path.parent)
        self.assertEqual(row["result"], bm.RESULT_FALSE_POSITIVE, row)


@unittest.skipUnless(Path(SYSTEM_DLL).exists(), "no System.dll available")
class BothModesTests(unittest.TestCase):
    """End-to-end main() with a fake model: static + ai rows, one JSON object."""

    def test_static_and_ai_json(self):
        tmp = tempfile.mkdtemp(prefix="trapkey-bench-both-")
        self.addCleanup(shutil.rmtree, tmp, True)
        shutil.copy(SYSTEM_DLL, Path(tmp) / "System.dll")
        labels = Path(tmp) / "labels.json"
        labels.write_text(
            json.dumps({"files": {"System.dll": {"expect": ["IsKeyValid"], "allow_none": False}}}),
            encoding="utf-8",
        )
        fake_measure = {
            "seconds": 1.25,
            "provider": "fake",
            "model": "fake",
            "success": True,
            "grounded": True,
            "output_sample": "FUNCTION: IsKeyValid\nALGORITHM: checks a key blob",
            "usage": {"prompt_tokens": 100, "completion_tokens": 12},
        }
        out = io.StringIO()
        err = io.StringIO()
        with mock.patch(
            "scanner.ai.resolve_config",
            return_value={"provider": "fake", "model": "fake", "local": True},
        ), mock.patch("scanner.ai.measure", return_value=fake_measure), mock.patch(
            "sys.stdout", out
        ), mock.patch("sys.stderr", err):
            code = bm.main(
                [
                    "--corpus", tmp,
                    "--labels", str(labels),
                    "--static", "--ai", "--limit", "1", "--json",
                ]
            )
        self.assertEqual(code, 0, err.getvalue())
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["modes"], ["static", "ai"])
        self.assertEqual(payload["summary"]["evaluated"], 2)
        self.assertEqual(payload["summary"]["hits"], 2)
        self.assertEqual(payload["by_mode"]["ai"]["prompt_tokens"], 100)
        self.assertEqual(payload["by_mode"]["ai"]["completion_tokens"], 12)
        self.assertEqual(payload["by_mode"]["ai"]["median_latency_seconds"], 1.25)
        ai_row = next(row for row in payload["rows"] if row["mode"] == "ai")
        self.assertEqual(ai_row["result"], bm.RESULT_HIT)
        self.assertTrue(ai_row["grounded"])


class CliTests(unittest.TestCase):
    def _run(self, *args, env=None):
        return subprocess.run(
            [sys.executable, str(ROOT / "benchmark.py"), *args],
            capture_output=True,
            text=True,
            timeout=180,
            env=env,
        )

    def test_help_exits_zero(self):
        proc = self._run("--help")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--labels", proc.stdout)

    def test_missing_labels_exits_two(self):
        tmp = tempfile.mkdtemp(prefix="trapkey-bench-nolabels-")
        self.addCleanup(shutil.rmtree, tmp, True)
        proc = self._run(
            "--corpus", tmp, "--labels", str(Path(tmp) / "missing.json"), "--static"
        )
        self.assertEqual(proc.returncode, 2)

    def test_empty_corpus_exits_two(self):
        tmp = tempfile.mkdtemp(prefix="trapkey-bench-empty-")
        self.addCleanup(shutil.rmtree, tmp, True)
        labels = Path(tmp) / "labels.json"
        labels.write_text(json.dumps({"files": {"App.exe": ["CheckLicense"]}}), encoding="utf-8")
        proc = self._run("--corpus", tmp, "--labels", str(labels), "--static")
        self.assertEqual(proc.returncode, 2)

    def test_no_matching_label_exits_two(self):
        tmp = tempfile.mkdtemp(prefix="trapkey-bench-nomatch-")
        self.addCleanup(shutil.rmtree, tmp, True)
        (Path(tmp) / "Some.exe").write_bytes(b"x" * 21_000)
        labels = Path(tmp) / "labels.json"
        labels.write_text(json.dumps({"files": {"Other.exe": ["CheckLicense"]}}), encoding="utf-8")
        proc = self._run("--corpus", tmp, "--labels", str(labels), "--static")
        self.assertEqual(proc.returncode, 2)

    @unittest.skipUnless(Path(SYSTEM_DLL).exists(), "no System.dll available")
    def test_static_cli_on_real_dotnet_assembly(self):
        tmp = tempfile.mkdtemp(prefix="trapkey-bench-real-")
        self.addCleanup(shutil.rmtree, tmp, True)
        shutil.copy(SYSTEM_DLL, Path(tmp) / "System.dll")
        labels = Path(tmp) / "labels.json"
        labels.write_text(
            json.dumps({"files": {"System.dll": {"expect": ["IsKeyValid"], "allow_none": False}}}),
            encoding="utf-8",
        )
        proc = self._run(
            "--corpus", tmp, "--labels", str(labels), "--static", "--limit", "1", "--json"
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["summary"]["evaluated"], 1)
        self.assertEqual(payload["summary"]["hits"], 1)
        self.assertEqual(payload["rows"][0]["source"], "named_functions")


if __name__ == "__main__":
    unittest.main(verbosity=2)
