"""Identifier heuristics.

Substring matching on names is a trap: `m_userSerializationData` and
`Verify_v15` are not licence code. Split identifiers into words first, then
match whole words. This is what keeps the scan credible.
"""

from __future__ import annotations

import re

_SPLIT = re.compile(r"[._<>:$`/\-\[\]() ]+")
_CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z][a-z]+|[A-Z]+|\d+")

# One of these is enough: they only appear in licensing code.
STRONG = {
    "license", "licence", "licensing", "keygen", "serialkey", "hwid", "trial",
    "subscription",
}

# Ambiguous on their own (Win32 has ActivationContext, CSPs have Unlock...).
# These need a supporting weak word to count.
AMBIGUOUS = {"activation", "activate", "deactivate", "unlock"}

# Two of these, or one next to an ambiguous word, is enough.
WEAK = {"verify", "serial", "expire", "expiry", "validate", "valid", "seat", "key", "checksum"}

# Words that describe an accessor / registry key / UI field. `ValidateKeyName`,
# `ValidateKeyRights`, `ValidateKeyMode` are Win32 registry helpers, not licence
# code — two weak words plus one of these is not enough.
CONTEXT = {
    "name", "names", "mode", "options", "view", "rights", "value", "values",
    "path", "type", "types", "flags", "index", "handle", "info", "data",
    "item", "items", "text", "label", "column", "row", "window", "control",
    "settings", "punctuation", "size", "length",
}


def words(name: str) -> list[str]:
    if not name:
        return []
    out: list[str] = []
    for chunk in _SPLIT.split(name):
        if not chunk:
            continue
        parts = _CAMEL.findall(chunk)
        if parts:
            out.extend(p.lower() for p in parts)
        else:
            out.append(chunk.lower())
    return out


def is_license_ident(name: str) -> bool:
    ws = words(name)
    if not ws:
        return False
    if any(w in STRONG for w in ws):
        return True
    # Distinct weak words: `GetBaseKeyFromKeyName` repeats "key" (registry API),
    # and counting the same word twice used to make it a licence function.
    weak = {w for w in ws if w in WEAK}
    if not weak or any(w in CONTEXT for w in ws):
        return False
    if any(w in AMBIGUOUS for w in ws):
        return True
    return len(weak) >= 2
