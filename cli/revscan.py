#!/usr/bin/env python3
"""RevScan CLI.

    revscan protect  <app.exe> --level 2 [--out <file>] [--no-strip]
    revscan protect  <app.exe> --sig payloads.sig --pubkey vendor.pem
    revscan verify   <license-token> --pem <public.pem>
    revscan verify   <license-token> --n <b64url> --e <hex>
    revscan info     <app.exe>
    revscan compare  <original.exe> <protected.exe> [--json] [--ai [--repeat N]]

`protect` never rebuilds and never needs source. It strips debug/PDB data and
appends a data section that carries AI-deception payloads. Use `scan.py` for the
crack-time report. `compare` rescans both files with the static cost model and
prints the delta — the "did protection actually help" loop.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from pe import PE, PEError  # noqa: E402

ROOT = HERE.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner import collect, estimate, human_duration  # noqa: E402
from scanner.compare import AIMeasureError  # noqa: E402
from scanner.compare import compare as compare_files  # noqa: E402
from scanner.compare import from_reports  # noqa: E402
from scanner.compare import render as render_compare  # noqa: E402
from scanner.compare import render_json as render_compare_json  # noqa: E402
from scanner.peinfo import PEError as ScanPEError  # noqa: E402

MAX_CHUNK = 1800  # Ghidra truncates decompiled string vars at 2048 chars
MARKER_V1 = b"\0TK1\0"
MARKER_V2 = b"\0TK2\0"
V2_VERSION = 2
V2_MAGIC = b"TK2"
DECOY_IDS = (0xFFFE, 0xFFFF)
DECOY_SIZE = 512

LEVEL_LABELS = {
    1: "plaintext traps (debug only)",
    2: "encrypted traps, per-build seed",
    3: "encrypted traps + decoy chunks + reference",
}

# Plaintext trailer for level 3. The decoy is worthless if the agent cannot
# reach it; this costs one round, then feeds the fake source.
REFERENCE = (
    b"\n\0TK2-REF\0"
    b"RevScan payload reference (build tooling)\n"
    b"  index entry = {u32 offset, u16 length, u16 chunk id}\n"
    b"  mask  = sha256(\"TK2\" + header + index)[0:16]\n"
    b"  seed  = seed_c XOR mask\n"
    b"  key   = sha256(\"revscan-v2-chunk\\0\" + seed + le16(id))\n"
    b"  plain = cipher XOR sha256(key + le32(counter)) blocks\n"
    b"  chunk ids 0xFFFE and 0xFFFF are decoys.\n"
)


# --------------------------------------------------------------------- utils

def chunk_text(text: str, limit: int = MAX_CHUNK) -> list[bytes]:
    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        if len(current) + len(line) > limit and current:
            chunks.append(current)
            current = ""
        while len(line) > limit:
            chunks.append(line[:limit])
            line = line[limit:]
        current += line
    if current:
        chunks.append(current)
    return [c.encode("utf-8", "ignore") for c in chunks]


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def load_parts(payloads_bytes: bytes) -> list[bytes]:
    payloads = json.loads(payloads_bytes.decode("utf-8"))
    parts: list[bytes] = []
    for name, payload in payloads.items():
        text = f"== {name} ==\n" + payload["prepend"] + payload["target"] + payload["append"]
        parts.extend(chunk_text(text))
    return parts


def build_seed(build: bytes, parts: list[bytes]) -> bytes:
    """Per-build seed: the same payload in two builds must not share bytes.

    This is obfuscation, not secrecy: the seed is recoverable from the blob
    (see decode_blob) because the agent has to be able to read the decoy to be
    deceived by it. The point is that a regex/signature for one build does not
    match the next.
    """
    digest = hashlib.sha256(b"revscan-v2-build\0" + hashlib.sha256(build).digest())
    for part in parts:
        digest.update(hashlib.sha256(part).digest())
    return digest.digest()[:16]


def keystream(key: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + struct.pack("<I", counter)).digest()
        counter += 1
    return bytes(out[:length])


def chunk_key(seed: bytes, cid: int) -> bytes:
    return hashlib.sha256(b"revscan-v2-chunk\0" + seed + struct.pack("<H", cid)).digest()


def crypt(data: bytes, seed: bytes, cid: int) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream(chunk_key(seed, cid), len(data))))


def decoy_chunk(seed: bytes, cid: int) -> bytes:
    material = hashlib.sha256(seed + b"decoy" + struct.pack("<H", cid)).digest()
    return (material * (DECOY_SIZE // len(material) + 1))[:DECOY_SIZE]


def encode_v2(build: bytes, parts: list[bytes], decoys: bool = True, hint: bool = False) -> bytes:
    """Chunked payload: no chunk is plaintext and chunks are not contiguous text.

    Layout:
        marker(5) | version(1) | count(u16) | seed_c(16) | index(count*8) | data
        index entry = offset(u32, from data start) | length(u16) | chunk id(u16)
        mask = sha256("TK2" + header + index)[:16]; seed = seed_c XOR mask
        key(id) = sha256("revscan-v2-chunk\\0" + seed + le16(id))

    With `hint`, a plaintext reference trailer explains the format. The payload
    has to be readable for the deception to land; the hint costs the agent one
    round, then it reads the decoy source.
    """
    seed = build_seed(build, parts)
    chunks: list[tuple[int, bytes]] = list(enumerate(parts))
    if decoys:
        chunks.extend((cid, decoy_chunk(seed, cid)) for cid in DECOY_IDS)

    header = MARKER_V2 + bytes([V2_VERSION]) + struct.pack("<H", len(chunks))
    index_entries: list[bytes] = []
    encrypted: list[bytes] = []
    cursor = 0
    for cid, plain in chunks:
        cipher = crypt(plain, seed, cid)
        index_entries.append(struct.pack("<IHH", cursor, len(plain), cid))
        encrypted.append(cipher)
        cursor += len(cipher)

    index = b"".join(index_entries)
    mask = hashlib.sha256(V2_MAGIC + header + index).digest()[:16]
    seed_c = xor(seed, mask)
    blob = header + seed_c + index + b"".join(encrypted)
    return blob + (REFERENCE if hint else b"")


def decode_blob(blob: bytes) -> dict:
    """Recover chunks from a v2 payload. Used by `info`, tests and feed tooling."""
    if not blob.startswith(MARKER_V2):
        raise ValueError("not a TK2 payload")
    if len(blob) < 24:
        raise ValueError("truncated payload header")
    version = blob[5]
    if version != V2_VERSION:
        raise ValueError(f"unsupported payload version {version}")
    count = struct.unpack_from("<H", blob, 6)[0]
    header = blob[:8]
    seed_c = blob[8:24]
    index = blob[24:24 + 8 * count]
    if len(index) < 8 * count:
        raise ValueError("truncated payload index")

    mask = hashlib.sha256(V2_MAGIC + header + index).digest()[:16]
    seed = xor(seed_c, mask)
    data = blob[24 + 8 * count:]
    chunks = []
    for i in range(count):
        offset, size, cid = struct.unpack_from("<IHH", index, i * 8)
        cipher = data[offset:offset + size]
        if len(cipher) != size:
            raise ValueError("truncated payload chunk")
        chunks.append({"id": cid, "bytes": crypt(cipher, seed, cid)})
    return {"seed": seed, "chunks": chunks, "decoys": any(c["id"] in DECOY_IDS for c in chunks)}


def build_blob(data: bytes, level: int, payloads_bytes: bytes, decoys: bool = True) -> bytes:
    parts = load_parts(payloads_bytes)
    if level == 1:
        return MARKER_V1 + b"\0".join(parts)
    if level == 2:
        return encode_v2(data, parts, decoys=False)
    if level == 3:
        return encode_v2(data, parts, decoys=decoys, hint=True)
    raise ValueError("level must be 1, 2 or 3")


def verify_payload_bundle(payloads_bytes: bytes, sig_path: Path, pubkey_path: Path | None) -> None:
    """Optional: refuse a payload feed that the vendor did not sign."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError as err:
        raise ValueError("pip install cryptography (needed for --sig)") from err

    if pubkey_path is None:
        env = os.environ.get("TRAPKEY_PAYLOAD_PUBKEY")
        pubkey_path = Path(env) if env else None
    if pubkey_path is None or not pubkey_path.is_file():
        raise ValueError("signed bundle needs --pubkey <file.pem> or TRAPKEY_PAYLOAD_PUBKEY")
    public_key = serialization.load_pem_public_key(pubkey_path.read_bytes())
    try:
        public_key.verify(
            sig_path.read_bytes(), payloads_bytes, padding.PKCS1v15(), hashes.SHA256()
        )
    except InvalidSignature as err:
        raise ValueError("payload bundle signature is invalid") from err


def human(report: dict) -> str:
    lines = [
        f"file       : {report['file']}  ({report['size']:,} bytes)",
        f"resistance : {report['resistance']}/100  ({report['verdict']})",
        f"AI crack   : ~{report['ai_crack_time_sec_estimate']}s  (heuristic)",
        "",
    ]
    if report["violations"]:
        lines.append("what an AI agent gets for free:")
        for v in sorted(report["violations"], key=lambda x: -x["weight"]):
            lines.append(f"  -{v['weight']:>2}  {v['id']:<16} {v['detail']}")
            lines.append(f"         fix: {v['fix']}")
    if report["bonuses"]:
        lines.append("")
        lines.append("protection already in place:")
        for b in report["bonuses"]:
            lines.append(f"  +{b['weight']:>2}  {b['id']:<16} {b['detail']}")
    if not report["violations"]:
        lines.append("nothing obvious to fix.")
    return "\n".join(lines)


# ------------------------------------------------------------------ commands

def cmd_protect(args: argparse.Namespace) -> int:
    src = Path(args.file)
    if not src.is_file():
        print(f"error: {src} not found", file=sys.stderr)
        return 2

    data = src.read_bytes()
    before = estimate(collect(str(src)))

    try:
        pe = PE(data)
    except PEError as err:
        print(f"error: {src}: {err}", file=sys.stderr)
        return 2

    payloads_path = Path(args.payloads) if args.payloads else HERE / "payloads.json"
    if not payloads_path.is_file():
        print(f"error: payloads file not found: {payloads_path}", file=sys.stderr)
        return 2

    payloads_bytes = payloads_path.read_bytes()
    if args.sig:
        try:
            verify_payload_bundle(
                payloads_bytes,
                Path(args.sig),
                Path(args.pubkey) if args.pubkey else None,
            )
        except (ValueError, OSError) as err:
            print(f"error: {err}", file=sys.stderr)
            return 2

    blob = build_blob(data, args.level, payloads_bytes)
    had_authenticode = pe.has_authenticode()

    # Strip before injecting: the debug directory offsets refer to the original
    # layout, and injection never moves existing sections.
    stripped = {"present": False, "records": 0, "bytes": 0}
    if args.strip:
        stripped = pe.strip_debug()

    try:
        method, offset = pe.inject(blob)
    except PEError as err:
        print(f"error: {err}", file=sys.stderr)
        return 3

    out = Path(args.out) if args.out else src.with_suffix(".protected" + src.suffix)
    out.write_bytes(pe.data)

    # Never ship something we cannot re-parse, and never ship a payload that
    # cannot be recovered by the agent (that would silently disable the trap).
    written = out.read_bytes()
    check = PE(written)
    if not check.has_payload_marker():
        print("error: payload marker missing after write; aborting", file=sys.stderr)
        out.unlink(missing_ok=True)
        return 4
    if args.level >= 2:
        at = written.find(MARKER_V2)
        try:
            decoded = decode_blob(written[at:])
        except ValueError as err:
            print(f"error: payload unreadable after write ({err}); aborting", file=sys.stderr)
            out.unlink(missing_ok=True)
            return 4
        real = [c["bytes"] for c in decoded["chunks"] if c["id"] not in DECOY_IDS]
        if not any(b"crc32_table_driven" in chunk for chunk in real):
            print("error: payload content missing after write; aborting", file=sys.stderr)
            out.unlink(missing_ok=True)
            return 4

    after = estimate(collect(str(out)))

    print(f"protected  : {out}")
    print(f"method     : {method} (+{len(pe.data) - len(data):,} bytes, at 0x{offset:x})")
    print(f"sections   : {', '.join(check.summary()['sections'])}")
    print(f"level      : {args.level} ({LEVEL_LABELS[args.level]})")
    if stripped["present"]:
        print(f"debug info : stripped {stripped['records']} CodeView record(s), {stripped['bytes']:,} bytes")
    else:
        print("debug info : no debug/PDB directory found")
    print("")
    print(f"AI crack   : ~{human_duration(before.best)} -> ~{human_duration(after.best)}")
    print(f"P(success) : {before.p_success} -> {after.p_success}")
    if had_authenticode:
        print(
            "warning    : binary had an Authenticode signature; modifying the PE "
            "invalidates it — re-sign with signtool before shipping",
            file=sys.stderr,
        )
    print("")
    print("note: the payload is data-only; program behaviour is unchanged.")
    print("      verify with your normal test suite before shipping.")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    for path in (args.original, args.protected):
        if not Path(path).exists():
            print(f"error: {path} not found", file=sys.stderr)
            return 2
        if not Path(path).is_file():
            print(f"error: {path} is not a file", file=sys.stderr)
            return 2

    try:
        result = compare_files(args.original, args.protected, measure=args.ai, repeat=args.repeat)
    except AIMeasureError as err:
        print(f"error[{err.code}]: {err}", file=sys.stderr)
        return 3
    except (ScanPEError, OSError, struct.error) as err:
        # struct.error covers a truncated header: still "bad input", not a crash.
        print(f"error: {err}", file=sys.stderr)
        return 2

    if result["same_file"]:
        # stderr, not stdout: `--json` must stay a single parseable object.
        print(
            "warning: original and protected are the same file (same sha256); "
            "the delta is zero by construction",
            file=sys.stderr,
        )

    print(render_compare_json(result) if args.json else render_compare(result))
    return 0


def cmd_compare_reports(args: argparse.Namespace) -> int:
    """Diff two `scan.py --json` reports without touching a binary.

    This is what the web uses: the user runs scan/protect locally, so no
    customer binary is uploaded and the local-protect invariant stays intact.
    """
    try:
        before = json.loads(Path(args.before).read_text(encoding="utf-8"))
        after = json.loads(Path(args.after).read_text(encoding="utf-8"))
        result = from_reports(before, after)
    except (OSError, ValueError, TypeError, AttributeError, OverflowError, json.JSONDecodeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    if result["same_file"]:
        print(
            "warning: both reports have the same sha256; the delta is zero by construction",
            file=sys.stderr,
        )
    print(render_compare_json(result) if args.json else render_compare(result))
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    src = Path(args.file)
    if not src.is_file():
        print(f"error: {src} not found", file=sys.stderr)
        return 2
    pe = PE(src.read_bytes())
    print(json.dumps(pe.summary(), indent=2))
    for section in pe.sections:
        print(
            f"  {section['name']:<10} vaddr=0x{section['vaddr']:08x} "
            f"vsize=0x{section['vsize']:08x} raw=0x{section['rawptr']:08x}+0x{section['rawsize']:x}"
        )
    at = bytes(pe.data).find(MARKER_V2)
    if at >= 0:
        try:
            decoded = decode_blob(bytes(pe.data)[at:])
            real = [c for c in decoded["chunks"] if c["id"] not in DECOY_IDS]
            print(
                json.dumps(
                    {
                        "payload": {
                            "version": 2,
                            "offset": at,
                            "chunks": len(real),
                            "decoys": decoded["decoys"],
                            "seed_prefix": decoded["seed"][:4].hex(),
                        }
                    },
                    indent=2,
                )
            )
        except ValueError as err:
            print(json.dumps({"payload": {"version": 2, "error": str(err)}}, indent=2))
    elif MARKER_V1 in pe.data:
        print(json.dumps({"payload": {"version": 1}}, indent=2))
    return 0


def _pubkey_from_args(args: argparse.Namespace):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    if args.pem:
        return serialization.load_pem_public_key(Path(args.pem).read_bytes())
    if args.n:
        modulus = int.from_bytes(base64.urlsafe_b64decode(args.n + "=" * (-len(args.n) % 4)), "big")
        exponent = int(args.e or "10001", 16)
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()
    raise SystemExit("verify needs --pem or --n/--e")


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:
        print("error: pip install cryptography", file=sys.stderr)
        return 2

    token = args.license.strip()
    if token.count(".") != 1:
        print("error: token must be <claims>.<signature>", file=sys.stderr)
        return 2
    body_b64, sig_b64 = token.split(".")

    def b64u(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    public_key = _pubkey_from_args(args)
    try:
        public_key.verify(b64u(sig_b64), body_b64.encode(), padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        print("INVALID  signature does not match this public key", file=sys.stderr)
        return 1

    claims = json.loads(b64u(body_b64))
    print(json.dumps({"valid": True, "claims": claims}, indent=2, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="revscan", description="License + anti-AI-crack kit")
    sub = parser.add_subparsers(dest="command", required=True)

    p_protect = sub.add_parser("protect", help="inject AI-deception payloads into a PE file")
    p_protect.add_argument("file")
    p_protect.add_argument("--out")
    p_protect.add_argument("--level", type=int, choices=[1, 2, 3], default=2)
    p_protect.add_argument("--payloads")
    p_protect.add_argument("--strip", dest="strip", action="store_true", default=True,
                           help="strip debug directory / PDB path (default: on)")
    p_protect.add_argument("--no-strip", dest="strip", action="store_false")
    p_protect.add_argument("--sig", help="detached RSA signature for the payload bundle")
    p_protect.add_argument("--pubkey", help="PEM public key that must have signed --sig")
    p_protect.set_defaults(func=cmd_protect)

    p_info = sub.add_parser("info", help="dump PE section table")
    p_info.add_argument("file")
    p_info.set_defaults(func=cmd_info)

    p_compare = sub.add_parser(
        "compare", help="scan an original and a protected copy, then report the diff"
    )
    p_compare.add_argument("original")
    p_compare.add_argument("protected")
    p_compare.add_argument("--json", action="store_true", help="machine-readable output")
    p_compare.add_argument(
        "--ai", action="store_true", help="also run one live model round on each file"
    )
    p_compare.add_argument(
        "--repeat", type=int, default=1,
        help="with --ai, run N rounds per file and use the median (3 recommended)",
    )
    p_compare.set_defaults(func=cmd_compare)

    p_reports = sub.add_parser(
        "compare-reports", help="diff two scan.py --json reports (no binary needed)"
    )
    p_reports.add_argument("before")
    p_reports.add_argument("after")
    p_reports.add_argument("--json", action="store_true", help="machine-readable output")
    p_reports.set_defaults(func=cmd_compare_reports)

    p_verify = sub.add_parser("verify", help="verify a license token offline")
    p_verify.add_argument("license")
    p_verify.add_argument("--pem")
    p_verify.add_argument("--n")
    p_verify.add_argument("--e")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
