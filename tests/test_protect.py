"""Protect v2 tests: payload encoding, PDB stripping, CLI on a real PE.

    python3 tests/test_protect.py

The strip/protect tests need a Windows binary; without one they skip.
"""

from __future__ import annotations

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

import trapkey  # noqa: E402
from pe import PE  # noqa: E402
from scanner import collect, estimate  # noqa: E402

PAYLOADS = (ROOT / "cli" / "payloads.json").read_bytes()


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

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - environment-dependent
    HAVE_CRYPTO = False


def real_chunks(decoded: dict) -> bytes:
    return b"".join(c["bytes"] for c in decoded["chunks"] if c["id"] not in trapkey.DECOY_IDS)


class PayloadEncodingTests(unittest.TestCase):
    def test_v2_round_trip(self):
        blob = trapkey.build_blob(b"build-A", 2, PAYLOADS)
        decoded = trapkey.decode_blob(blob)
        text = real_chunks(decoded)
        self.assertIn(b"crc32_table_driven", text)
        self.assertIn(b"payload v2 layout", text)
        self.assertFalse(decoded["decoys"])

    def test_plaintext_is_not_in_the_blob(self):
        blob = trapkey.build_blob(b"build-A", 2, PAYLOADS)
        self.assertNotIn(b"crc32_table_driven", blob)
        self.assertNotIn(b"BEGIN RECOVERED SOURCE", blob)
        self.assertNotIn(b"serial validation", blob)

    def test_seed_is_per_build(self):
        a = trapkey.build_blob(b"build-A", 2, PAYLOADS)
        b = trapkey.build_blob(b"build-B", 2, PAYLOADS)
        self.assertNotEqual(a, b)
        self.assertNotEqual(trapkey.decode_blob(a)["seed"], trapkey.decode_blob(b)["seed"])
        # Same build + same payloads -> identical bytes (reproducible builds).
        self.assertEqual(a, trapkey.build_blob(b"build-A", 2, PAYLOADS))

    def test_level3_adds_decoys(self):
        decoded = trapkey.decode_blob(trapkey.build_blob(b"build-A", 3, PAYLOADS))
        self.assertTrue(decoded["decoys"])
        ids = {c["id"] for c in decoded["chunks"]}
        self.assertTrue(set(trapkey.DECOY_IDS) <= ids)

    def test_level3_carries_a_plaintext_reference(self):
        # The agent must be able to reach the decoy; level 3 tells it how.
        blob = trapkey.build_blob(b"build-A", 3, PAYLOADS)
        self.assertIn(b"TK2-REF", blob)
        self.assertIn(b"seed  = seed_c XOR mask", blob)
        self.assertNotIn(b"TK2-REF", trapkey.build_blob(b"build-A", 2, PAYLOADS))

    def test_level1_stays_plaintext(self):
        blob = trapkey.build_blob(b"build-A", 1, PAYLOADS)
        self.assertTrue(blob.startswith(trapkey.MARKER_V1))
        self.assertIn(b"crc32_table_driven", blob)

    def test_truncated_blob_is_rejected(self):
        blob = trapkey.build_blob(b"build-A", 2, PAYLOADS)
        with self.assertRaises(ValueError):
            trapkey.decode_blob(blob[:16])


@unittest.skipUnless(os.path.exists(NOTEPAD), "no Windows binary")
class StripTests(unittest.TestCase):
    def test_removes_pdb_path_and_debug_directory(self):
        data = Path(NOTEPAD).read_bytes()
        if b".pdb" not in data.lower():
            self.skipTest("fixture has no PDB path (already stripped)")
        pe = PE(data)

        stats = pe.strip_debug()
        self.assertTrue(stats["present"])
        self.assertIn(b".pdb", data.lower())
        self.assertNotIn(b".pdb", bytes(pe.data).lower())
        self.assertEqual(pe.dir_entry(6), (0, 0))
        # Section table untouched.
        self.assertEqual(PE(bytes(pe.data)).nsec, pe.nsec)

    def test_strip_is_idempotent(self):
        pe = PE(Path(NOTEPAD).read_bytes())
        pe.strip_debug()
        self.assertFalse(pe.strip_debug()["present"])


@unittest.skipUnless(os.path.exists(NOTEPAD), "no Windows binary")
class ProtectCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="trapkey-protect-")
        self.src = Path(self.tmp) / "app.exe"
        shutil.copy(NOTEPAD, self.src)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_protect(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(ROOT / "cli" / "trapkey.py"), "protect", *args],
            capture_output=True,
            text=True,
            timeout=180,
        )

    def test_protect_strips_pdb_and_scan_flags_traps(self):
        out = Path(self.tmp) / "app.protected.exe"
        proc = self.run_protect(str(self.src), "--level", "3", "--out", str(out))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("debug info", proc.stdout)

        data = out.read_bytes()
        self.assertNotIn(b".pdb", data.lower())
        self.assertNotIn(b"crc32_table_driven", data)

        before = estimate(collect(str(self.src)))
        after = estimate(collect(str(out)))
        self.assertIn("TK2", collect(str(out)).markers)
        self.assertLess(after.p_success, before.p_success)
        self.assertGreater(after.best, before.best)

    def test_double_protect_is_refused(self):
        first = Path(self.tmp) / "once.exe"
        self.assertEqual(self.run_protect(str(self.src), "--out", str(first)).returncode, 0)
        second = self.run_protect(str(first), "--out", str(Path(self.tmp) / "twice.exe"))
        self.assertEqual(second.returncode, 3)
        self.assertIn("already protected", second.stderr)

    def test_no_strip_keeps_debug_directory(self):
        if b".pdb" not in Path(self.src).read_bytes().lower():
            self.skipTest("fixture has no PDB path")
        out = Path(self.tmp) / "kept.exe"
        proc = self.run_protect(str(self.src), "--no-strip", "--out", str(out))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(b".pdb", out.read_bytes().lower())


@unittest.skipUnless(HAVE_CRYPTO, "no cryptography")
class SignedBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="trapkey-sig-"))
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pubkey = self.tmp / "vendor.pem"
        self.pubkey.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        self.sig = self.tmp / "payloads.sig"
        self.sig.write_bytes(key.sign(PAYLOADS, padding.PKCS1v15(), hashes.SHA256()))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_valid_signature_is_accepted(self):
        trapkey.verify_payload_bundle(PAYLOADS, self.sig, self.pubkey)

    def test_tampered_bundle_is_refused(self):
        with self.assertRaises(ValueError):
            trapkey.verify_payload_bundle(PAYLOADS + b" ", self.sig, self.pubkey)

    def test_missing_pubkey_is_refused(self):
        saved = os.environ.pop("TRAPKEY_PAYLOAD_PUBKEY", None)
        try:
            with self.assertRaises(ValueError):
                trapkey.verify_payload_bundle(PAYLOADS, self.sig, None)
        finally:
            if saved is not None:
                os.environ["TRAPKEY_PAYLOAD_PUBKEY"] = saved


if __name__ == "__main__":
    unittest.main(verbosity=2)
