"""Scanner tests. Plain unittest, no dependencies.

    python3 tests/test_scan.py
"""

from __future__ import annotations

import os
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanner import collect, estimate, risk_score, scan  # noqa: E402
from scanner.ai import (  # noqa: E402
    AIConfigError,
    _call_gemini,
    _call_openai,
    classify_failure,
    gemini_thinking_budget,
    grounded_answer,
    resolve_config,
)
from scanner.estimate import MODELS  # noqa: E402
from scanner.evidence import Evidence  # noqa: E402
from scanner.ident import is_license_ident, words  # noqa: E402
from scanner.peinfo import PEInfo  # noqa: E402
from scanner.report import to_dict  # noqa: E402

def _first_existing(candidates: list[Path]) -> str:
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[-1])


def _find_windows_binary(name: str, env_var: str) -> str:
    """Locate a System32 binary on WSL, Windows or CI without hardcoding /mnt/c."""
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


class IdentTests(unittest.TestCase):
    def test_real_license_names_match(self):
        for name in ("LicenseManager", "CheckLicense", "ActivateTrial", "VerifySerialKey", "IsKeyValid"):
            self.assertTrue(is_license_ident(name), name)

    def test_noise_does_not_match(self):
        for name in ("m_userSerializationData", "Verify_v15", "ORACTIVATION", "SerializableMembers",
                     "get_Data", "ActivationContext", "UnlockFileEx", "GetBaseKeyFromKeyName",
                     "ValidateKeyName", "ValidateKeyRights", "ValidateKeyMode",
                     "VerifyValidPunctuation"):
            self.assertFalse(is_license_ident(name), name)

    def test_ambiguous_words_need_support(self):
        self.assertTrue(is_license_ident("ActivateLicense"))
        self.assertTrue(is_license_ident("ActivateTrial"))
        self.assertTrue(is_license_ident("UnlockWithKey"))
        self.assertFalse(is_license_ident("UnlockFileEx"))

    def test_word_split(self):
        self.assertIn("license", words("CheckLicenseExpiry"))
        self.assertIn("expiry", words("CheckLicenseExpiry"))


@unittest.skipUnless(os.path.exists(WINDOWS_EXE), "no Windows binaries available")
class NativeTests(unittest.TestCase):
    def test_pe_structure(self):
        pe = PEInfo(Path(WINDOWS_EXE).read_bytes())
        self.assertTrue(pe.is64)
        self.assertIn(".text", pe.section_names)
        self.assertIsNotNone(pe.function_count())
        self.assertGreater(pe.function_count(), 10)
        self.assertFalse(pe.is_dotnet)

    def test_scan_produces_a_number(self):
        result = scan(WINDOWS_EXE)
        self.assertGreater(result["crack_seconds_best"], 0)
        self.assertLess(result["crack_seconds_best"], 7200)
        self.assertTrue(0 <= result["risk"] <= 100)
        self.assertTrue(0 <= result["p_success"] <= 1)


@unittest.skipUnless(os.path.exists(DOTNET_DLL), "no .NET assembly available")
class DotNetTests(unittest.TestCase):
    def test_metadata_is_parsed(self):
        ev = collect(DOTNET_DLL)
        self.assertEqual(ev.kind, "dotnet")
        self.assertTrue(ev.dotnet and ev.dotnet.ok)
        self.assertGreater(ev.dotnet.method_count, 1000)
        self.assertGreater(ev.dotnet.total_il_bytes, 100_000)
        # Sanity: IL can never exceed the file size by an order of magnitude.
        self.assertLess(ev.dotnet.total_il_bytes, ev.size * 4)


class EstimateBehaviourTests(unittest.TestCase):
    def _evidence(self, cls=Evidence, **kw) -> Evidence:
        ev = cls(path="x.exe", size=1000, sha256="0" * 64, kind="native")
        ev.stats = {"strings_chars": 20_000, "license_strings": 5}
        ev.pe = None
        for key, value in kw.items():
            setattr(ev, key, value)
        return ev

    def test_named_functions_are_faster_than_unnamed(self):
        class Named(Evidence):
            @property
            def named_license_functions(self):
                return [{"name": "CheckLicense", "il_bytes": 4000}]

            @property
            def has_traps(self):
                return False

        unnamed = self._evidence()
        named = self._evidence(cls=Named)
        self.assertLess(estimate(named).best, estimate(unnamed).best)

    def test_traps_increase_time_and_lower_success(self):
        base = self._evidence()
        trapped = self._evidence(markers=["TK2", "traps:instruction-override"])
        self.assertGreater(estimate(trapped).best, estimate(base).best)
        self.assertLess(estimate(trapped).p_success, estimate(base).p_success)

    def test_risk_is_monotonic(self):
        self.assertGreater(risk_score(10, 0.9), risk_score(600, 0.9))
        self.assertGreater(risk_score(10, 0.9), risk_score(10, 0.1))


class EvidenceAndReportTests(unittest.TestCase):
    def _evidence(self, cls=Evidence, **kw) -> Evidence:
        ev = cls(path="x.exe", size=1000, sha256="0" * 64, kind="native")
        ev.stats = {"strings_chars": 20_000, "license_strings": 5}
        ev.pe = None
        for key, value in kw.items():
            setattr(ev, key, value)
        return ev

    def test_utf16_strings_are_not_starved_by_ascii(self):
        # Regression: the ASCII pass returned as soon as it hit 60k entries, so
        # a large DLL never had its UTF-16 (i.e. most Windows) strings read.
        from scanner.evidence import _extract_strings

        ascii_blob = b"\x01".join(b"STR%05d" % i for i in range(45_000))
        data = ascii_blob + b"\x00" + "License expired".encode("utf-16-le")
        out = _extract_strings(data)
        self.assertTrue(any("License expired" in s for s in out), "UTF-16 string must be read")

    def test_packed_section_names_are_case_insensitive(self):
        # Regression: the set held "UPX0" while section names were lowercased,
        # so the UPX/VMProtect branch was dead.
        class FakePE:
            section_names = ["upx0", ".text"]
            sections = []

        ev = self._evidence()
        ev.pe = FakePE()
        self.assertTrue(ev.packed)

    def test_electron_does_not_erase_protection(self):
        # Regression: the Electron branch used to run last and set p=0.97,
        # wiping the packed/trap penalties.
        plain = self._evidence(kind="electron")
        trapped = self._evidence(kind="electron", markers=["TK2", "traps:instruction-override"])
        self.assertLess(estimate(trapped).p_success, estimate(plain).p_success)
        self.assertLess(estimate(trapped).p_success, 0.8)

    def test_measured_is_not_a_model_band(self):
        # Regression: `measured` was merged into `est.seconds`, which crashed
        # to_dict with KeyError('measured') for --ai --json.
        ev = self._evidence()
        est = estimate(ev)
        est.measured = {
            "seconds": 12.5,
            "model": "stub",
            "provider": "openai",
            "success": True,
            "usage": {},
        }
        data = to_dict(ev, est)
        self.assertEqual(set(data["crack_seconds"]), set(MODELS))
        self.assertNotIn("measured", data["crack_seconds"])
        self.assertEqual(data["measured"]["seconds"], 12.5)
        json.dumps(data)  # must be valid JSON (no NaN/Infinity)

    def test_invalid_k_does_not_produce_nan_json(self):
        ev = self._evidence()
        saved = os.environ.get("TRAPKEY_CALIBRATION_K")
        try:
            for bad in ("-2", "nan", "inf"):
                os.environ["TRAPKEY_CALIBRATION_K"] = bad
                data = to_dict(ev, estimate(ev))
                self.assertTrue(all(v["seconds"] >= 0 for v in data["crack_seconds"].values()))
                json.dumps(data)
        finally:
            if saved is None:
                os.environ.pop("TRAPKEY_CALIBRATION_K", None)
            else:
                os.environ["TRAPKEY_CALIBRATION_K"] = saved


class AIConfigTests(unittest.TestCase):
    KEYS = (
        "OPENAI_API_KEY",
        "LLM_API_KEY",
        "ANTHROPIC_API_KEY",
        "OLLAMA_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_BASE_URL",
        "OPENAI_BASE_URL",
        "TRAPKEY_AI_PROVIDER",
        "TRAPKEY_AI_MODEL",
        "TRAPKEY_AI_THINKING_BUDGET",
    )

    def setUp(self):
        self.saved = {k: os.environ.get(k) for k in self.KEYS}
        for k in self.KEYS:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_openai_key(self):
        os.environ["OPENAI_API_KEY"] = "sk-x"
        cfg = resolve_config()
        self.assertEqual(cfg["provider"], "openai")
        self.assertEqual(cfg["base"], "https://api.openai.com/v1")
        self.assertFalse(cfg["local"])

    def test_ollama_needs_no_key(self):
        os.environ["TRAPKEY_AI_PROVIDER"] = "ollama"
        cfg = resolve_config()
        self.assertTrue(cfg["local"])
        self.assertIn("11434", cfg["base"])

    def test_ollama_cloud_key(self):
        os.environ["OLLAMA_API_KEY"] = "ok-x"
        os.environ["TRAPKEY_AI_MODEL"] = "gpt-oss:120b"
        cfg = resolve_config()
        self.assertEqual(cfg["provider"], "ollama")
        self.assertEqual(cfg["base"], "https://ollama.com/v1")
        self.assertFalse(cfg["local"])
        self.assertEqual(cfg["key"], "ok-x")

    def test_ollama_cloud_needs_a_model_name(self):
        os.environ["OLLAMA_API_KEY"] = "ok-x"
        with self.assertRaises(AIConfigError):
            resolve_config()

    def test_any_openai_compatible_base(self):
        os.environ["OPENAI_BASE_URL"] = "https://api.deepseek.com/v1"
        os.environ["OPENAI_API_KEY"] = "sk-d"
        os.environ["TRAPKEY_AI_MODEL"] = "deepseek-chat"
        cfg = resolve_config()
        self.assertEqual(cfg["base"], "https://api.deepseek.com/v1")
        self.assertEqual(cfg["model"], "deepseek-chat")

    def test_anthropic(self):
        os.environ["ANTHROPIC_API_KEY"] = "sk-a"
        cfg = resolve_config()
        self.assertEqual(cfg["style"], "anthropic")
        self.assertEqual(cfg["base"], "https://api.anthropic.com")

    def test_gemini_key_autodetects_google(self):
        os.environ["GEMINI_API_KEY"] = "AIza-x"
        cfg = resolve_config()
        self.assertEqual(cfg["provider"], "gemini")
        self.assertEqual(cfg["style"], "gemini")
        self.assertEqual(cfg["base"], "https://generativelanguage.googleapis.com/v1beta")
        self.assertEqual(cfg["model"], "gemini-3.1-flash-lite")
        self.assertEqual(cfg["key"], "AIza-x")

    def test_gemini_google_alias_and_model_prefix(self):
        os.environ["GOOGLE_API_KEY"] = "AIza-y"
        os.environ["TRAPKEY_AI_MODEL"] = "models/gemini-3.5-flash"
        cfg = resolve_config()
        self.assertEqual(cfg["provider"], "gemini")
        self.assertEqual(cfg["model"], "gemini-3.5-flash")

    def test_gemini_custom_base(self):
        os.environ["TRAPKEY_AI_PROVIDER"] = "gemini"
        os.environ["GEMINI_API_KEY"] = "AIza-x"
        os.environ["GEMINI_BASE_URL"] = "https://example.test/v1beta/"
        cfg = resolve_config()
        self.assertEqual(cfg["base"], "https://example.test/v1beta")

    def test_gemini_never_reuses_an_openai_key(self):
        os.environ["TRAPKEY_AI_PROVIDER"] = "gemini"
        os.environ["OPENAI_API_KEY"] = "sk-x"
        with self.assertRaises(AIConfigError):
            resolve_config()

    def test_opencode_go_sends_identity_headers(self):
        import scanner.ai as ai_module

        captured = {}

        def fake_post(url, body, headers, timeout):
            captured.update(headers=headers)
            return {"choices": [{"message": {"content": "FUNCTION: none"}}], "usage": {}}

        saved = ai_module._post
        ai_module._post = fake_post
        try:
            cfg = {
                "base": "https://opencode.ai/inference/go/openai/v1",
                "key": "k",
                "model": "deepseek-v4.1-flash",
                "local": False,
            }
            _call_openai(cfg, "PACK", 9)
        finally:
            ai_module._post = saved
        # Go returns Cloudflare 403/1010 for the default Python-urllib UA.
        self.assertEqual(captured["headers"]["user-agent"], "revscan/1.0")
        self.assertIn("x-opencode-session", captured["headers"])

    def test_unconfigured_is_an_error(self):
        with self.assertRaises(AIConfigError):
            resolve_config()


class GeminiCallTests(unittest.TestCase):
    def _cfg(self):
        return {
            "provider": "gemini",
            "style": "gemini",
            "base": "https://generativelanguage.googleapis.com/v1beta",
            "key": "AIza-test",
            "model": "gemini-3.6-flash",
            "local": False,
        }

    def test_request_and_response_are_mapped_to_the_common_shape(self):
        import scanner.ai as ai_module

        captured = {}

        def fake_sse(url, body, headers, timeout):
            captured.update(url=url, body=body, headers=headers, timeout=timeout)
            return "FUNCTION: IsKeyValid done", {
                "promptTokenCount": 120,
                "candidatesTokenCount": 7,
                "totalTokenCount": 127,
            }

        saved = ai_module._post_sse
        ai_module._post_sse = fake_sse
        try:
            text, usage = _call_gemini(self._cfg(), "PACK", 9)
        finally:
            ai_module._post_sse = saved

        self.assertTrue(captured["url"].endswith(":streamGenerateContent?alt=sse"))
        self.assertEqual(captured["headers"]["x-goog-api-key"], "AIza-test")
        self.assertEqual(captured["body"]["generationConfig"]["thinkingConfig"], {"thinkingBudget": 0})
        self.assertEqual(text, "FUNCTION: IsKeyValid done")
        self.assertEqual(usage["prompt_tokens"], 120)
        self.assertEqual(usage["completion_tokens"], 7)

    def test_thinking_can_be_left_to_the_model(self):
        import scanner.ai as ai_module

        saved_env = os.environ.get("TRAPKEY_AI_THINKING_BUDGET")
        captured = {}
        os.environ["TRAPKEY_AI_THINKING_BUDGET"] = "off"
        try:
            def fake_sse(url, body, headers, timeout):
                captured.update(body=body)
                return "OK", {}

            saved = ai_module._post_sse
            ai_module._post_sse = fake_sse
            try:
                _call_gemini(self._cfg(), "PACK", 9)
            finally:
                ai_module._post_sse = saved
            self.assertIsNone(gemini_thinking_budget())
        finally:
            if saved_env is None:
                os.environ.pop("TRAPKEY_AI_THINKING_BUDGET", None)
            else:
                os.environ["TRAPKEY_AI_THINKING_BUDGET"] = saved_env

        self.assertNotIn("thinkingConfig", captured["body"]["generationConfig"])


class AIFailureTests(unittest.TestCase):
    def test_provider_errors_get_actionable_codes(self):
        self.assertEqual(classify_failure(429, "weekly usage limit")[0], "AI_QUOTA")
        code, retry = classify_failure(
            503,
            "[ollama/gpt-oss:120b] [429]: weekly usage limit (reset after 4m 59s)",
        )
        self.assertEqual(code, "AI_QUOTA")
        self.assertEqual(retry, 299)
        self.assertEqual(classify_failure(401, "OAuth access token has expired")[0], "AI_AUTH")
        self.assertEqual(
            classify_failure(400, '{"error":{"message":"API key not valid. Please pass a valid API key."}}')[0],
            "AI_AUTH",
        )
        self.assertEqual(classify_failure(429, "RESOURCE_EXHAUSTED: quota exceeded")[0], "AI_QUOTA")
        self.assertEqual(classify_failure(410, "model has reached its end of life")[0], "AI_MODEL")
        self.assertEqual(classify_failure(500, "upstream broke")[0], "AI_PROVIDER")
        self.assertEqual(classify_failure(None, "connection reset")[0], "AI_NETWORK")


class GroundedAnswerTests(unittest.TestCase):
    PACK = "license_named_functions:\nLicenseManager::ValidateKey\nVerifySerialKey\nsub_6c620"

    def test_named_function_from_the_pack_is_grounded(self):
        self.assertTrue(grounded_answer("LicenseManager::ValidateKey", self.PACK, 0x140000000, 0x1000))

    def test_bare_method_name_is_grounded(self):
        self.assertTrue(grounded_answer("VerifySerialKey", self.PACK, 0x140000000, 0x1000))

    def test_hallucinated_name_is_not_grounded(self):
        self.assertFalse(grounded_answer("ValidateKeyName", self.PACK, 0x140000000, 0x1000))
        self.assertFalse(grounded_answer("none", self.PACK, 0x140000000, 0x1000))

    def test_address_must_be_inside_the_image(self):
        self.assertTrue(grounded_answer("0x140000100", self.PACK, 0x140000000, 0x1000))
        self.assertFalse(grounded_answer("0x140009999", self.PACK, 0x140000000, 0x1000))


if __name__ == "__main__":
    unittest.main(verbosity=2)
