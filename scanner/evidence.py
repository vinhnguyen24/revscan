"""Evidence collection: everything an AI reverse-engineering agent would read.

The scanner never guesses here. Each item below is extracted from the file:
strings, section layout, imports, exports, .NET method/type names, protection
markers. The *interpretation* happens in `estimate.py`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .dotnet import DotNetInfo
from .peinfo import PEError, PEInfo

ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

LICENSE_WORDS = re.compile(
    r"(?i)\b(licen[cs]e|licensing|serial|activation|activate|deactivate|trial|"
    r"expire[sd]?|expiry|keygen|crack|unlock|seat|subscription|hwid|machine[ _-]?id)\b"
)
KEY_SHAPED = re.compile(r"\b[A-Z]{2,6}(?:-[A-Z0-9]{4,8}){2,5}\b")
PDB_PATH = re.compile(r"[A-Za-z]:\\[^\s\"']{3,}\.pdb")
SOURCE_PATH = re.compile(r"[A-Za-z]:\\[^\s\"']{3,}\.(?:c|cpp|h|hpp|cs|rs|go)\b")
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
URL_RE = re.compile(r"https?://[^\s\"'<>]{6,}")
INJECTION = [
    (r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|surrounding)\s+instructions", "instruction-override"),
    (r"(system|analysis)\s+(note|notice|prompt|message|instruction)", "fake-system-message"),
    (r"do\s+not\s+(mention|describe|report|analyze)", "output-suppression"),
    (r"===\s*(begin|end)\s+(recovered|authoritative)", "fake-delimiter"),
    (r"final\s+report\s*:", "forced-conclusion"),
    (r"conclude\s+that|state\s+that\s+the\s+(binary|executable|program)", "forced-conclusion"),
]
CRYPTO_IMPORTS = (
    "bcryptverify", "bcryptsign", "cryptprotectdata", "cryptunprotectdata",
    "cryptencrypt", "cryptdecrypt", "bcryptencrypt", "bcryptdecrypt",
    "cryptacquirecontext", "ncryptopenstorageprovider", "sspi",
)
DEBUG_IMPORTS = ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess")


@dataclass
class Evidence:
    path: str
    size: int
    sha256: str
    kind: str = "unknown"
    pe: PEInfo | None = None
    dotnet: DotNetInfo | None = None
    strings: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    markers: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    # ------------------------------------------------------------------ views

    def add(self, kind: str, weight: int, detail: str, fix: str, severity: str = "leak") -> None:
        self.findings.append(
            {"id": kind, "weight": weight, "detail": detail, "fix": fix, "severity": severity}
        )

    def has(self, finding_id: str) -> bool:
        return any(f["id"] == finding_id for f in self.findings)

    @property
    def license_strings(self) -> list[str]:
        return [s for s in self.strings if LICENSE_WORDS.search(s)][:400]

    @property
    def named_license_functions(self) -> list[dict]:
        out = []
        if self.dotnet and self.dotnet.ok:
            out = [{"name": m["name"], "il_bytes": m["il_bytes"]} for m in self.dotnet.license_methods()]
        if not out and self.pe:
            out = [{"name": e, "il_bytes": 0} for e in self.pe.exports() if LICENSE_WORDS.search(e)]
        return out

    @property
    def named_license_types(self) -> list[str]:
        if not self.dotnet or not self.dotnet.ok:
            return []
        return self.dotnet.license_types()[:50]

    @property
    def crypto_imports(self) -> list[str]:
        found = []
        if self.pe:
            for entry in self.pe.imports():
                for fn in entry["functions"]:
                    low = fn.lower()
                    if any(c in low for c in CRYPTO_IMPORTS):
                        found.append(fn)
        return sorted(set(found))

    @property
    def debugger_imports(self) -> list[str]:
        found = []
        if self.pe:
            for entry in self.pe.imports():
                for fn in entry["functions"]:
                    low = fn.lower()
                    if any(c in low for c in DEBUG_IMPORTS):
                        found.append(fn)
        return sorted(set(found))

    @property
    def packed(self) -> bool:
        if not self.pe:
            return False
        # Section names must be compared case-insensitively: the old set held
        # "UPX0" but the section names were lowercased, so the branch never fired.
        suspicious = {"upx0", "upx1", "upx2", ".aspack", ".pec", ".mpress1", ".mpress2",
                      ".themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2"}
        if suspicious & {s.lower() for s in self.pe.section_names}:
            return True
        for s in self.pe.sections:
            if s["executable"] and s["entropy"] >= 7.2 and s["rawsize"] > 4096:
                return True
        return False

    @property
    def obfuscated_names(self) -> bool:
        if not self.dotnet or not self.dotnet.ok or not self.dotnet.methods:
            return False
        names = [m["name"] for m in self.dotnet.methods[:4000] if not m["name"].startswith("method@")]
        if len(names) < 50:
            return False
        weird = sum(1 for n in names if len(n) <= 2 or any(ord(c) > 127 for c in n))
        return weird / len(names) > 0.35

    @property
    def has_traps(self) -> bool:
        return any(m in ("TK1", "TK2") for m in self.markers)


def collect(path: str) -> Evidence:
    p = Path(path)
    data = p.read_bytes()
    ev = Evidence(
        path=str(p),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )

    try:
        ev.pe = PEInfo(data, str(p))
    except PEError:
        ev.pe = None

    if ev.pe and ev.pe.is_dotnet:
        ev.dotnet = DotNetInfo(ev.pe)
        ev.kind = "dotnet" if ev.dotnet.ok else "native"
    else:
        ev.kind = "native"

    ev.strings = _extract_strings(data)

    joined = "\n".join(ev.strings[:30_000])
    if "app.asar" in joined or "node_modules\\" in joined or "Electron" in joined:
        ev.kind = "electron"

    _protection_markers(ev, data)
    _findings(ev, joined)

    ev.stats = {
        "strings_total": len(ev.strings),
        "strings_chars": sum(len(s) for s in ev.strings),
        "license_strings": len(ev.license_strings),
        "crypto_imports": ev.crypto_imports,
        "debugger_imports": ev.debugger_imports,
        "packed": ev.packed,
        "dotnet_methods": ev.dotnet.method_count if ev.dotnet and ev.dotnet.ok else 0,
        "dotnet_types": ev.dotnet.type_count if ev.dotnet and ev.dotnet.ok else 0,
        "dotnet_il_bytes": ev.dotnet.total_il_bytes if ev.dotnet and ev.dotnet.ok else 0,
        "native_functions": ev.pe.function_count() if ev.pe else None,
        "obfuscated_names": ev.obfuscated_names,
    }
    return ev


def _extract_strings(data: bytes, limit: int = 60_000) -> list[str]:
    """ASCII + UTF-16LE, each with its own share of the budget.

    Scanning ASCII to the limit first meant any large DLL (>=60k ASCII strings)
    never had a single UTF-16 string read — and Windows licence messages are
    usually UTF-16. Reserve a third of the budget for them.
    """
    utf16_budget = max(5_000, limit // 3)
    ascii_budget = limit - utf16_budget

    out: list[str] = []
    for m in ASCII_RE.finditer(data):
        out.append(m.group().decode("ascii", "ignore"))
        if len(out) >= ascii_budget:
            break
    for m in UTF16_RE.finditer(data):
        out.append(m.group().decode("utf-16-le", "ignore"))
        if len(out) >= limit:
            break
    return out


def _protection_markers(ev: Evidence, data: bytes) -> None:
    if b"\0TK1\0" in data:
        ev.markers.append("TK1")
    if b"\0TK2\0" in data:
        ev.markers.append("TK2")

    hits = set()
    for text in ev.strings:
        for pattern, tag in INJECTION:
            if re.search(pattern, text, re.I):
                hits.add(tag)
    if hits:
        ev.markers.append("traps:" + ",".join(sorted(hits)))
        ev.add(
            "deception-active",
            -15,
            f"AI deception payloads active ({len(hits)} techniques). "
            "An agent reading these strings is instructed to report a decoy program.",
            "keep payloads fresh: models learn and become immune (payload feed)",
            severity="protection",
        )


def _findings(ev: Evidence, joined: str) -> None:
    words = {w.lower() for w in LICENSE_WORDS.findall(joined)}
    if words:
        ev.add(
            "license-literals",
            min(30, 4 * len(words)),
            f"{len(words)} licensing word(s) readable: {', '.join(sorted(words)[:8])}",
            "encrypt these literals and decrypt at the point of use",
        )

    keyish = set(KEY_SHAPED.findall(joined))
    if keyish:
        ev.add(
            "key-format",
            20,
            f"key-shaped strings reveal your licence format ({len(keyish)} found)",
            "never embed a real key; synthesise or split the format",
        )

    named = ev.named_license_functions
    if named:
        sample = ", ".join(x["name"] for x in named[:5])
        ev.add(
            "named-functions",
            25,
            f"{len(named)} function(s) are *named* after licensing: {sample}",
            "rename to neutral names, or obfuscate identifiers",
        )

    types = ev.named_license_types
    if types:
        ev.add(
            "named-types",
            10,
            f"{len(types)} type(s) named after licensing: {', '.join(types[:5])}",
            "obfuscate type names",
        )

    if ev.has("named-functions") or ev.has("license-literals"):
        # The entry point is reachable by grep: the agent does not need to read much.
        pass

    if PDB_PATH.search(joined):
        ev.add(
            "pdb-path",
            15,
            "PDB path leaks build directory and symbol names",
            "strip debug info (/DEBUG:NONE, remove /PDBALTPATH)",
        )

    if SOURCE_PATH.search(joined):
        ev.add(
            "source-paths",
            10,
            "source file paths are embedded (assert/log strings)",
            "strip __FILE__ or build with /d2togglefilepath",
        )

    if B64_BLOB.search(joined):
        ev.add(
            "encoded-blob",
            8,
            "long base64 blob (often the licence payload itself)",
            "compress+encrypt, or move it out of .rdata",
        )

    if ev.kind == "electron":
        ev.add(
            "electron-asar",
            25,
            "Electron app: app.asar decompiles to near-original JavaScript",
            "keep the check in native code, never in the asar",
        )

    if ev.dotnet and ev.dotnet.ok and not ev.obfuscated_names:
        ev.add(
            "dotnet-readable",
            15,
            f"{ev.dotnet.method_count} .NET methods with readable names "
            f"({ev.dotnet.total_il_bytes:,} bytes of IL)",
            "obfuscate identifiers; keep licence logic out of IL",
        )

    if ev.obfuscated_names:
        ev.add(
            "obfuscated-names",
            -12,
            "method names are obfuscated (agent cannot grep for 'License')",
            "good: keep it, and refresh the obfuscator",
            severity="protection",
        )

    if ev.packed:
        ev.add(
            "packed",
            -20,
            "packed/encrypted code section: the agent must unpack before reading",
            "good: packing is the highest-value protection you can buy",
            severity="protection",
        )

    if ev.crypto_imports:
        ev.add(
            "crypto-imports",
            6,
            f"crypto API imports point to the verification code: {', '.join(ev.crypto_imports[:4])}",
            "resolve crypto APIs at runtime, or hide the import table",
        )

    if ev.debugger_imports:
        ev.add(
            "anti-debug",
            -8,
            f"anti-debug API present: {', '.join(ev.debugger_imports[:3])}",
            "keep it; consider stronger anti-attach",
            severity="protection",
        )
