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

import revscan  # noqa: E402
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
    return b"".join(c["bytes"] for c in decoded["chunks"] if c["id"] not in revscan.DECOY_IDS)


class PayloadEncodingTests(unittest.TestCase):
    def test_v2_round_trip(self):
        blob = revscan.build_blob(b"build-A", 2, PAYLOADS)
        decoded = revscan.decode_blob(blob)
        text = real_chunks(decoded)
        self.assertIn(b"crc32_table_driven", text)
        self.assertIn(b"payload v2 layout", text)
        self.assertFalse(decoded["decoys"])

    def test_plaintext_is_not_in_the_blob(self):
        blob = revscan.build_blob(b"build-A", 2, PAYLOADS)
        self.assertNotIn(b"crc32_table_driven", blob)
        self.assertNotIn(b"BEGIN RECOVERED SOURCE", blob)
        self.assertNotIn(b"serial validation", blob)

    def test_seed_is_per_build(self):
        a = revscan.build_blob(b"build-A", 2, PAYLOADS)
        b = revscan.build_blob(b"build-B", 2, PAYLOADS)
        self.assertNotEqual(a, b)
        self.assertNotEqual(revscan.decode_blob(a)["seed"], revscan.decode_blob(b)["seed"])
        # Same build + same payloads -> identical bytes (reproducible builds).
        self.assertEqual(a, revscan.build_blob(b"build-A", 2, PAYLOADS))

    def test_level3_adds_decoys(self):
        decoded = revscan.decode_blob(revscan.build_blob(b"build-A", 3, PAYLOADS))
        self.assertTrue(decoded["decoys"])
        ids = {c["id"] for c in decoded["chunks"]}
        self.assertTrue(set(revscan.DECOY_IDS) <= ids)

    def test_level3_carries_a_plaintext_reference(self):
        # The agent must be able to reach the decoy; level 3 tells it how.
        blob = revscan.build_blob(b"build-A", 3, PAYLOADS)
        self.assertIn(b"TK2-REF", blob)
        self.assertIn(b"seed  = seed_c XOR mask", blob)
        self.assertNotIn(b"TK2-REF", revscan.build_blob(b"build-A", 2, PAYLOADS))

    def test_level1_stays_plaintext(self):
        blob = revscan.build_blob(b"build-A", 1, PAYLOADS)
        self.assertTrue(blob.startswith(revscan.MARKER_V1))
        self.assertIn(b"crc32_table_driven", blob)

    def test_truncated_blob_is_rejected(self):
        blob = revscan.build_blob(b"build-A", 2, PAYLOADS)
        with self.assertRaises(ValueError):
            revscan.decode_blob(blob[:16])


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
        self.tmp = tempfile.mkdtemp(prefix="revscan-protect-")
        self.src = Path(self.tmp) / "app.exe"
        shutil.copy(NOTEPAD, self.src)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_protect(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(ROOT / "cli" / "revscan.py"), "protect", *args],
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
        self.tmp = Path(tempfile.mkdtemp(prefix="revscan-sig-"))
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
        revscan.verify_payload_bundle(PAYLOADS, self.sig, self.pubkey)

    def test_tampered_bundle_is_refused(self):
        with self.assertRaises(ValueError):
            revscan.verify_payload_bundle(PAYLOADS + b" ", self.sig, self.pubkey)

    def test_missing_pubkey_is_refused(self):
        saved = os.environ.pop("TRAPKEY_PAYLOAD_PUBKEY", None)
        try:
            with self.assertRaises(ValueError):
                revscan.verify_payload_bundle(PAYLOADS, self.sig, None)
        finally:
            if saved is not None:
                os.environ["TRAPKEY_PAYLOAD_PUBKEY"] = saved


@unittest.skipUnless(os.path.exists(NOTEPAD), "no Windows binary")
class AuthenticodeWarningTests(unittest.TestCase):
    def test_warns_when_protecting_authenticode_signed_pe(self):
        import struct

        tmp = Path(tempfile.mkdtemp(prefix="revscan-auth-"))
        try:
            src = tmp / "signed.exe"
            out = tmp / "signed.protected.exe"
            raw = bytearray(Path(NOTEPAD).read_bytes())
            pe = PE(raw)
            # Ensure data directory entry 4 (SECURITY) is non-zero to simulate a signed binary.
            sec_off = pe.data_dir + 4 * 8
            if pe.num_dirs > 4 and sec_off + 8 <= len(raw):
                struct.pack_into("<II", raw, sec_off, len(raw), 64)
                raw.extend(b"\0" * 64)
            src.write_bytes(raw)

            self.assertTrue(PE(src.read_bytes()).has_authenticode())
            proc = subprocess.run(
                [sys.executable, str(ROOT / "cli" / "revscan.py"), "protect", str(src), "--out", str(out)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("Authenticode", proc.stderr)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
