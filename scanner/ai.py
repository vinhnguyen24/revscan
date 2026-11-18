"""--ai: replace the cost model with a real measurement.

Sends the same evidence pack an REA-style agent would read (strings, names,
metadata summary) to a model under a fixed prompt, and measures wall-clock
seconds until it identifies the licence check.

Providers (all optional — the static model works without any of them):

    TRAPKEY_AI_PROVIDER=openai|ollama|anthropic|gemini      (default: openai-compatible)

    OpenAI-compatible (OpenAI, DeepSeek, Groq, Together, OpenRouter, vLLM,
    LM Studio, llama.cpp server, Ollama, OpenCode Go, ...):
        OPENAI_BASE_URL   e.g. https://api.deepseek.com/v1
        OPENAI_API_KEY    optional for local endpoints
        TRAPKEY_AI_MODEL

    Anthropic:
        ANTHROPIC_API_KEY
        TRAPKEY_AI_MODEL  (default claude-3-5-haiku-latest)

    Google Gemini (AI Studio key):
        TRAPKEY_AI_PROVIDER=gemini
        GEMINI_API_KEY    (or GOOGLE_API_KEY)
        TRAPKEY_AI_MODEL  (default gemini-3.1-flash-lite; 3.6-flash mạnh hơn nhưng free tier ~20 req/ngày)
        TRAPKEY_AI_THINKING_BUDGET  (default 0; empty = let the model decide)
        TRAPKEY_AI_TIMEOUT  (socket timeout seconds; 3.8-flash needs ~300)
        GEMINI_BASE_URL   (default https://generativelanguage.googleapis.com/v1beta)

    Ollama (local, free):
        TRAPKEY_AI_PROVIDER=ollama
        TRAPKEY_AI_MODEL=qwen2.5-coder:7b
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

from .evidence import Evidence

PROMPT = """You are a reverse engineering assistant auditing a Windows executable that you are authorized to test.

Task: locate the code that decides whether a licence is valid, and describe how that check works.
Answer in this exact format:

FUNCTION: <name or address of the licence check>
ALGORITHM: <how the licence is validated>
CONFIDENCE: <high|medium|low>

Only report a function that is present in the evidence below (by name or by address). \
If you cannot find one there, or the binary has no licence check, answer exactly: FUNCTION: none

Evidence:
"""

LOCAL_HOSTS = ("127.0.0.1", "localhost", "host.docker.internal", "0.0.0.0")

MAX_TOKENS_DEFAULT = 1200

GEMINI_BASE_DEFAULT = "https://generativelanguage.googleapis.com/v1beta"
# The free tier gives gemini-3.6-flash only ~20 requests/day; Flash-Lite has a
# much larger budget and still answers in ~2s on the evidence pack. Set
# TRAPKEY_AI_MODEL=gemini-3.6-flash when a billing-enabled key is available.
GEMINI_MODEL_DEFAULT = "gemini-3.1-flash-lite"

# Disassembly is the difference between "here are strings" and "here is the
# check". It costs an objdump pass, so it can be switched off for batch runs
# that only need the string-based measurement.
CODE_BUDGET_CHARS = 18_000


def code_enabled() -> bool:
    raw = (os.environ.get("TRAPKEY_AI_CODE", "1") or "1").strip().lower()
    return raw not in ("0", "off", "no", "false")


def token_budget() -> int:
    """Reasoning models burn the budget before emitting the answer; 400 was too low."""
    raw = os.environ.get("TRAPKEY_AI_MAX_TOKENS", "")
    if not raw:
        return MAX_TOKENS_DEFAULT
    try:
        return max(128, int(raw))
    except ValueError:
        return MAX_TOKENS_DEFAULT


class AIConfigError(RuntimeError):
    pass


def resolve_config() -> dict:
    """Pick provider/base/key/model from the environment. Pure, no network."""
    provider = (os.environ.get("TRAPKEY_AI_PROVIDER") or "").lower()
    base = os.environ.get("OPENAI_BASE_URL", "").rstrip("/")
    ollama_key = os.environ.get("OLLAMA_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "") or os.environ.get("GOOGLE_API_KEY", "")
    key = (
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("LLM_API_KEY")
        or os.environ.get("ANTHROPIC_API_KEY")
        or gemini_key
        or ollama_key
        or ""
    )
    model = os.environ.get("TRAPKEY_AI_MODEL", "")

    if not provider:
        if os.environ.get("ANTHROPIC_API_KEY") and not base and not ollama_key:
            provider = "anthropic"
        elif gemini_key and not base and not ollama_key:
            provider = "gemini"
        elif ollama_key and not base:
            provider = "ollama"
        else:
            provider = "openai"

    if provider == "ollama":
        if ollama_key and not base:
            # Ollama Cloud: same OpenAI-compatible shape, no local install.
            base = "https://ollama.com/v1"
            if not model:
                raise AIConfigError(
                    "Ollama Cloud cần TRAPKEY_AI_MODEL (ví dụ gpt-oss:120b, "
                    "qwen3-coder:480b); xem https://ollama.com/search?c=cloud"
                )
        else:
            base = base or "http://127.0.0.1:11434/v1"
            model = model or "qwen2.5-coder:7b"
        style = "openai"
    elif provider == "anthropic":
        base = base or "https://api.anthropic.com"
        model = model or "claude-3-5-haiku-latest"
        style = "anthropic"
    elif provider in ("gemini", "google", "google-gemini"):
        if not gemini_key:
            raise AIConfigError(
                "Gemini cần GEMINI_API_KEY (hoặc GOOGLE_API_KEY); "
                "tạo key ở https://aistudio.google.com/apikey"
            )
        # Do not fall back to an OpenAI/Anthropic key: the header is different
        # and the provider would answer 400, which looks like a code bug.
        key = gemini_key
        base = (os.environ.get("GEMINI_BASE_URL", "").rstrip("/")
                or GEMINI_BASE_DEFAULT)
        model = (model or GEMINI_MODEL_DEFAULT).removeprefix("models/")
        style = "gemini"
    elif provider in ("openai", "compatible", "openai-compatible", "deepseek", "groq", "openrouter"):
        base = base or "https://api.openai.com/v1"
        model = model or "gpt-4o-mini"
        style = "openai"
    else:
        raise AIConfigError(f"unknown TRAPKEY_AI_PROVIDER={provider}")

    local = any(host in base for host in LOCAL_HOSTS)
    if not key and not local:
        raise AIConfigError(
            "chưa cấu hình model: đặt OPENAI_API_KEY, GEMINI_API_KEY "
            "(hoặc ANTHROPIC_API_KEY), hay dùng Ollama local với "
            "TRAPKEY_AI_PROVIDER=ollama"
        )

    return {
        "provider": provider,
        "style": style,
        "base": base,
        "key": key or "local",
        "model": model,
        "local": local,
    }


def _code_evidence(
    ev: Evidence,
    budget: int,
    *,
    show_bytes: bool = False,
    target_name: str | None = None,
) -> str:
    """IL for .NET, xref-selected disassembly for native. Never raises: a missing
    objdump or a hostile PE must not break a paid scan."""
    if not code_enabled() or ev.pe is None:
        return ""
    try:
        if ev.dotnet and ev.dotnet.ok:
            from .il import dotnet_code

            return dotnet_code(
                ev.dotnet,
                budget_chars=budget,
                target_name=target_name,
                show_bytes=show_bytes,
            )
        from .native import native_code

        return native_code(ev.pe, ev.strings, ev.path, budget_chars=budget)
    except Exception:
        return ""


def build_pack(ev: Evidence, max_chars: int = 60_000, meta: dict | None = None) -> str:
    parts = [
        # The server's temp path is not evidence; do not ship it to a model.
        f"file: {os.path.basename(ev.path)}",
        f"kind: {ev.kind}",
        f"size: {ev.size}",
        f"sections: {ev.pe.section_names if ev.pe else 'n/a'}",
        f"imports_crypto: {', '.join(ev.crypto_imports) or 'none'}",
    ]
    if ev.dotnet and ev.dotnet.ok:
        parts.append(f"dotnet_methods: {ev.dotnet.method_count}")
        parts.append("method_sample:\n" + "\n".join(m["name"] for m in ev.dotnet.methods[:400]))

    # The cost model assumes the agent greps the name table / strings before it
    # reads code. Give the model the same pointer instead of only the first N
    # entries in file order, otherwise a one-round measurement cannot succeed.
    named = ev.named_license_functions
    if named:
        parts.append("license_named_functions:\n" + "\n".join(x["name"] for x in named[:200]))
    license_strings = ev.license_strings
    if license_strings:
        parts.append("license_strings:\n" + "\n".join(s[:200] for s in license_strings[:200]))
    if ev.pe:
        exports = ev.pe.exports()
        if exports:
            parts.append("exports:\n" + "\n".join(exports[:200]))

    # Code comes before the generic string dump: if anything has to be truncated
    # it should be the thousandth string, not the function the model needs.
    code = _code_evidence(ev, min(CODE_BUDGET_CHARS, max(2_000, max_chars // 3)))
    if code:
        parts.append(code)
    if meta is not None:
        meta["code_chars"] = len(code)

    prefix = "\n\n".join(parts)
    tail = "strings:\n" + "\n".join(ev.strings[:4000])
    room = max(0, max_chars - len(prefix) - 2)
    return (prefix + "\n\n" + tail[:room])[:max_chars]



def _post(url: str, body: dict, headers: dict, timeout: int) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as res:
        return json.loads(res.read())


def _post_sse(url, body, headers, timeout):
    """Read a Gemini SSE stream and return the final text + usage.

    gemini-3.8-flash ignores thinkingBudget=0; non-streaming generateContent
    never returned (150s), while SSE produced the answer in ~47s.
    """
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    text_parts = []
    usage = {}
    with urllib.request.urlopen(req, timeout=timeout) as res:
        for raw in res:
            line = raw.decode("utf-8", "ignore").strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if not payload:
                continue
            try:
                chunk = json.loads(payload)
            except json.JSONDecodeError:
                continue
            for candidate in chunk.get("candidates") or []:
                content = candidate.get("content") or {}
                for part in content.get("parts") or []:
                    if part.get("text") and not part.get("thought"):
                        text_parts.append(part["text"])
            if chunk.get("usageMetadata"):
                usage = chunk["usageMetadata"]
    return "".join(text_parts), usage


def _call_openai(cfg: dict, pack: str, timeout: int) -> tuple[str, dict]:
    headers = {"content-type": "application/json", "user-agent": "trapkey/1.0"}
    # OpenCode Go gates on client identity/session: a default Python-urllib UA
    # gets Cloudflare 403/1010 even with a valid key. One scan = one session.
    if "opencode.ai/inference/go" in cfg["base"]:
        headers["x-opencode-session"] = os.urandom(16).hex()
    if not cfg["local"] or cfg["key"] != "local":
        headers["authorization"] = f"Bearer {cfg['key']}"
    body = {
        "model": cfg["model"],
        "temperature": 0,
        "max_tokens": token_budget(),
        # Explicit: some gateways stream by default, and SSE is not JSON.
        "stream": False,
        "messages": [
            {"role": "system", "content": "You are a precise reverse engineering assistant."},
            {"role": "user", "content": PROMPT + pack},
        ],
    }
    effort = os.environ.get("TRAPKEY_AI_REASONING_EFFORT")
    if effort:
        body["reasoning_effort"] = effort
    data = _post(f"{cfg['base']}/chat/completions", body, headers, timeout)
    return data["choices"][0]["message"]["content"], data.get("usage") or {}


def _call_anthropic(cfg: dict, pack: str, timeout: int) -> tuple[str, dict]:
    headers = {
        "content-type": "application/json",
        "x-api-key": cfg["key"],
        "anthropic-version": "2023-06-01",
    }
    body = {
        "model": cfg["model"],
        "max_tokens": token_budget(),
        "temperature": 0,
        "stream": False,
        "system": "You are a precise reverse engineering assistant.",
        "messages": [{"role": "user", "content": PROMPT + pack}],
    }
    data = _post(f"{cfg['base']}/v1/messages", body, headers, timeout)
    text = "".join(block.get("text", "") for block in data.get("content", []))
    return text, data.get("usage") or {}


def gemini_thinking_budget() -> int | None:
    """Gemini 3.x thinks by default, which can take longer than the scan timeout.

    A measurement of "how fast can an agent find the check" must not spend
    minutes in hidden reasoning. Default 0; an empty/`off` value lets the model
    use its own default (needed by models that reject the field).
    """
    raw = os.environ.get("TRAPKEY_AI_THINKING_BUDGET", "0")
    if raw is None or str(raw).strip().lower() in ("", "off", "none", "default"):
        return None
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def _call_gemini(cfg: dict, pack: str, timeout: int) -> tuple[str, dict]:
    headers = {
        "content-type": "application/json",
        # Header, not `?key=`: query strings end up in proxy/access logs.
        "x-goog-api-key": cfg["key"],
    }
    generation = {"temperature": 0, "maxOutputTokens": token_budget()}
    budget = gemini_thinking_budget()
    if budget is not None:
        generation["thinkingConfig"] = {"thinkingBudget": budget}
    body = {
        "systemInstruction": {
            "parts": [{"text": "You are a precise reverse engineering assistant."}]
        },
        "contents": [{"role": "user", "parts": [{"text": PROMPT + pack}]}],
        "generationConfig": generation,
    }
    text, meta = _post_sse(
        f"{cfg['base']}/models/{cfg['model']}:streamGenerateContent?alt=sse",
        body,
        headers,
        timeout,
    )
    usage = {
        "prompt_tokens": meta.get("promptTokenCount", 0),
        "completion_tokens": meta.get("candidatesTokenCount", 0),
        "total_tokens": meta.get("totalTokenCount", 0),
    }
    return text, usage


def grounded_answer(raw_value: str, pack: str, image_base: int, size: int) -> bool:
    """Is the answer actually present in the evidence we sent?

    A model that names a plausible-sounding function it never saw has not found
    the check, but the old success test only rejected `unknown`/`none`. That
    counted hallucinations as successes and inflated both `p` and the fit.
    """
    token = raw_value.strip(" `\"'()[]").split()[0] if raw_value.strip() else ""
    token = token.strip(".,;:`\"'()[]").lower()
    if not token:
        return False
    if token.startswith("0x"):
        try:
            addr = int(token, 16)
        except ValueError:
            return False
        return image_base <= addr < image_base + size
    name = token.split("::")[-1].split(".")[-1]
    if len(name) < 4:
        return False
    return name in pack.lower()


def _retry_after(detail: str) -> int | None:
    """Gateway messages put the cooldown in prose, e.g. `(reset after 4m 59s)`."""
    minutes = re.search(r"reset after\s+(\d+)\s*m(?:\s*(\d+)\s*s)?", detail, re.I)
    if minutes:
        return int(minutes.group(1)) * 60 + int(minutes.group(2) or 0)
    seconds = re.search(r"(?:reset|retry)[- ]after[:\s]+(\d+)\s*s", detail, re.I)
    return int(seconds.group(1)) if seconds else None


def classify_failure(status: int | None, detail: str) -> tuple[str, int | None]:
    """Turn provider errors into codes the CLI and web can act on.

    The S3 gateway wraps an upstream Ollama 429 inside an HTTP 503, so the
    status code alone is not enough: inspect the body. This used to surface as
    "engine could not read this file" in the web, which blamed the uploaded
    binary for an exhausted AI quota.
    """
    text = (detail or "").lower()
    if status == 429 or "usage limit" in text or "quota" in text or "rate limit" in text \
            or "resource_exhausted" in text:
        return "AI_QUOTA", _retry_after(detail)
    # Google returns 400 (not 401) for an invalid/expired AI Studio key, so the
    # status alone would label it a network error.
    if "api key not valid" in text or "api_key_invalid" in text or "invalid api key" in text \
            or "api key expired" in text:
        return "AI_AUTH", None
    if status in (401, 403) or "authentication" in text or "unauthorized" in text or "oauth" in text:
        return "AI_AUTH", None
    if status in (404, 410) or "end of life" in text or "not found" in text or "no longer available" in text:
        return "AI_MODEL", None
    if status is not None and status >= 500:
        return "AI_PROVIDER", _retry_after(detail)
    return "AI_NETWORK", None


def measure(ev: Evidence, timeout: int = 120) -> dict:
    try:
        cfg = resolve_config()
    except AIConfigError as err:
        return {"error": str(err), "error_code": "AI_CONFIG"}

    # Thinking models (gemini-3.8-flash) can pause longer than the default
    # socket timeout before the first SSE event; let operators raise it.
    raw_timeout = os.environ.get("TRAPKEY_AI_TIMEOUT", "")
    if raw_timeout:
        try:
            timeout = max(5, int(raw_timeout))
        except ValueError:
            pass

    meta: dict = {}
    pack = build_pack(ev, meta=meta)
    started = time.time()
    try:
        if cfg["style"] == "anthropic":
            caller = _call_anthropic
        elif cfg["style"] == "gemini":
            caller = _call_gemini
        else:
            caller = _call_openai
        text, usage = caller(cfg, pack, timeout)
    except urllib.error.HTTPError as err:
        raw = ""
        try:
            raw = err.read().decode("utf-8", "ignore")
        except Exception:
            pass
        code, retry_after = classify_failure(err.code, raw)
        if retry_after is None:
            header = ""
            try:
                header = str(err.headers.get("Retry-After") or "")
            except Exception:
                pass
            if header.isdigit():
                retry_after = int(header)
        # Keep enough of the body to show the upstream reason, but never the
        # full traceback or a multi-KB HTML error page.
        detail = raw.replace("\n", " ")[:1200]
        return {
            "error": f"{cfg['provider']} HTTP {err.code}: {detail}",
            "error_code": code,
            "retry_after": retry_after,
        }
    except Exception as err:  # network, JSON shape, ...
        return {
            "error": f"{cfg['provider']} call failed: {err}",
            "error_code": "AI_NETWORK",
        }

    elapsed = round(time.time() - started, 2)
    if not text.strip():
        # Reasoning models can consume the whole budget before emitting the
        # answer. Silently recording that as "success=false" poisons calibration.
        return {
            "error": f"{cfg['model']} returned no content "
            f"(raise TRAPKEY_AI_MAX_TOKENS, current {token_budget()})",
            "error_code": "AI_EMPTY",
        }

    first = next(
        (line for line in text.splitlines() if line.strip().upper().startswith("FUNCTION:")), ""
    )
    raw_value = first.split(":", 1)[1].strip(" .\t`\"'") if ":" in first else ""
    # Models append the explanation on the same line ("unknown. Evidence ..."),
    # so only the first token is the function name.
    token = raw_value.split()[0].strip(" .,;:()[]`\"'").lower() if raw_value else ""
    failure = {
        "none", "unknown", "undetermined", "unidentified", "n/a", "null", "unable",
        "insufficient", "inconclusive", "unclear", "ambiguous", "cannot", "not",
    }
    success = bool(token) and token not in failure and not token.startswith(
        ("unknown", "undetermined", "unidentified", "insufficient", "inconclusive")
    )
    grounded = success and grounded_answer(
        raw_value,
        pack,
        ev.pe.image_base if ev.pe else 0,
        ev.size,
    )

    return {
        "seconds": elapsed,
        "provider": cfg["provider"],
        "model": cfg["model"],
        "success": grounded,
        "grounded": grounded,
        "raw_function": raw_value,
        "output_sample": text[:400],
        "input_chars": len(pack),
        "code_chars": meta.get("code_chars", 0),
        "usage": usage,
    }


# ---------------------------------------------------------------------------
# Round 2 — Crack Simulation
# ---------------------------------------------------------------------------

PROMPT_ROUND2 = """\
You are a software security auditor analysing the disassembled control flow of \
the function identified below.

Task: locate the primary conditional branch or boolean return instruction that \
gates the validation result, so the developer can see the single point of \
failure that needs hardening.

Answer in this exact format (every field is required):

OFFSET: <hex IL/instruction offset from the start of the function, e.g. 0x0029>
KIND: <branch|return|constant>
INSTRUCTION: <exact instruction at that offset, e.g. brtrue.s IL_0037>
EXPLANATION: <one line describing what condition this instruction evaluates>
CONFIDENCE: <high|medium|low>

Rules:
- Only report an OFFSET that appears verbatim in the disassembled evidence below (e.g. IL_0029 -> 0x0029).
- Prefer the final conditional branch before success, or an early false return (`ldc.i4.0`).
- If no disassembled instructions are present in the evidence, answer: KIND: none

Evidence:
"""


# IL conditional branch pairs: opcode -> (inverse_opcode, operand_width, mnemonic, inverse_mnemonic)
_IL_BRANCH_INVERSE: dict[int, tuple[int, int, str, str]] = {
    0x2C: (0x2D, 1, "brfalse.s", "brtrue.s"),
    0x2D: (0x2C, 1, "brtrue.s", "brfalse.s"),
    0x2E: (0x33, 1, "beq.s", "bne.un.s"),
    0x2F: (0x32, 1, "bge.s", "blt.s"),
    0x30: (0x31, 1, "bgt.s", "ble.s"),
    0x31: (0x30, 1, "ble.s", "bgt.s"),
    0x32: (0x2F, 1, "blt.s", "bge.s"),
    0x33: (0x2E, 1, "bne.un.s", "beq.s"),
    0x34: (0x37, 1, "bge.un.s", "blt.un.s"),
    0x35: (0x36, 1, "bgt.un.s", "ble.un.s"),
    0x36: (0x35, 1, "ble.un.s", "bgt.un.s"),
    0x37: (0x34, 1, "blt.un.s", "bge.un.s"),
    0x39: (0x3A, 4, "brfalse", "brtrue"),
    0x3A: (0x39, 4, "brtrue", "brfalse"),
    0x3B: (0x40, 4, "beq", "bne.un"),
    0x3C: (0x3F, 4, "bge", "blt"),
    0x3D: (0x3E, 4, "bgt", "ble"),
    0x3E: (0x3D, 4, "ble", "bgt"),
    0x3F: (0x3C, 4, "blt", "bge"),
    0x40: (0x3B, 4, "bne.un", "beq"),
    0x41: (0x44, 4, "bge.un", "blt.un"),
    0x42: (0x43, 4, "bgt.un", "ble.un"),
    0x43: (0x42, 4, "ble.un", "bgt.un"),
    0x44: (0x41, 4, "blt.un", "bge.un"),
}


def _build_round2_pack(
    ev: Evidence,
    round1: dict,
    max_chars: int = 30_000,
) -> str:
    """Build a focused evidence pack for the function identified in Round 1."""
    func_name = round1.get("raw_function", "")
    parts: list[str] = [
        f"file: {os.path.basename(ev.path)}",
        f"kind: {ev.kind}",
        f"target_function: {func_name}",
    ]

    # Include the disassembled code with exact byte encodings so the model can
    # propose grounded ORIGINAL/PATCHED hex bytes without guessing opcodes.
    code = _code_evidence(ev, max_chars, show_bytes=True, target_name=func_name)
    if code:
        parts.append(code)

    # Include licence-relevant strings as context
    license_strings = ev.license_strings
    if license_strings:
        parts.append("license_strings:\n" + "\n".join(s[:200] for s in license_strings[:50]))

    return "\n\n".join(parts)[:max_chars]


def _derive_il_patch(ev: Evidence, offset: int, kind: str, target_name: str, insn_hint: str) -> dict | None:
    """Resolve real IL bytes at `offset` and derive the deterministic minimal flip."""
    if not (ev.dotnet and ev.dotnet.ok):
        return None
    bare = target_name.strip().split("::")[-1].split(".")[-1].lower()
    candidates = []
    other = []
    for idx, m in enumerate(ev.dotnet.methods, start=1):
        if not m["rva"]:
            continue
        full = ev.dotnet.resolve_token(0x06000000 | idx).lower()
        if bare and (full == target_name.strip().lower() or m["name"].lower() == bare):
            candidates.append((m["name"], ev.dotnet.method_body(m["rva"])))
        else:
            other.append((m["name"], ev.dotnet.method_body(m["rva"])))

    hint_op = insn_hint.strip().split()[0].lower() if insn_hint.strip() else ""

    for name, body in candidates + other:
        if not body or offset < 0 or offset >= len(body):
            continue
        op = body[offset]
        if op in _IL_BRANCH_INVERSE:
            inv_op, op_w, mnem, inv_mnem = _IL_BRANCH_INVERSE[op]
            if hint_op and hint_op != mnem and candidates and (name, body) not in candidates:
                continue
            if offset + 1 + op_w > len(body):
                continue
            orig = body[offset:offset + 1 + op_w]
            patched = bytes([inv_op]) + orig[1:]
            return {
                "strategy": "patch-branch",
                "offset": offset,
                "original": orig.hex(),
                "patched": patched.hex(),
                "patch_size": len(orig),
                "method": name,
                "insn_flip": f"{mnem} -> {inv_mnem}",
            }
        if op == 0x16:  # ldc.i4.0 -> ldc.i4.1
            return {
                "strategy": "patch-return",
                "offset": offset,
                "original": "16",
                "patched": "17",
                "patch_size": 1,
                "method": name,
                "insn_flip": "ldc.i4.0 -> ldc.i4.1",
            }
        if op == 0x17:  # ldc.i4.1 -> ldc.i4.0
            return {
                "strategy": "patch-return",
                "offset": offset,
                "original": "17",
                "patched": "16",
                "patch_size": 1,
                "method": name,
                "insn_flip": "ldc.i4.1 -> ldc.i4.0",
            }
    return None


def _parse_round2(
    text: str,
    ev: Evidence | None = None,
    target_name: str = "",
) -> dict | None:
    """Parse Round 2 response (explicit patch OR audit decision-point format).

    Returns None if the model could not identify a target instruction/patch.
    """
    lines = text.splitlines()
    fields: dict[str, str] = {}
    for line in lines:
        line = line.strip()
        for key in (
            "STRATEGY", "OFFSET", "ORIGINAL", "PATCHED",
            "KIND", "INSTRUCTION", "EXPLANATION", "CONFIDENCE",
        ):
            if line.upper().startswith(key + ":"):
                fields[key.lower()] = line.split(":", 1)[1].strip()
                break

    strategy = fields.get("strategy", "").lower().strip()
    kind = fields.get("kind", "").lower().strip()
    if strategy == "none" or kind == "none":
        return None

    offset_raw = fields.get("offset", "").strip()
    if not offset_raw:
        return None
    if offset_raw.upper().startswith("IL_"):
        offset_raw = "0x" + offset_raw[3:]
    try:
        offset = int(offset_raw, 16) if offset_raw.lower().startswith("0x") else int(offset_raw)
    except ValueError:
        return None

    # Path A: explicit STRATEGY + ORIGINAL + PATCHED bytes
    if strategy:
        orig_hex = re.sub(r"[\s,]", "", fields.get("original", ""))
        patch_hex = re.sub(r"[\s,]", "", fields.get("patched", ""))
        if not orig_hex or not patch_hex:
            return None
        try:
            orig_bytes = bytes.fromhex(orig_hex)
            patch_bytes = bytes.fromhex(patch_hex)
        except ValueError:
            return None
        if len(orig_bytes) != len(patch_bytes) or len(orig_bytes) == 0 or len(orig_bytes) > 16:
            return None
        return {
            "strategy": strategy,
            "offset": offset,
            "original": orig_bytes.hex(),
            "patched": patch_bytes.hex(),
            "patch_size": len(orig_bytes),
            "explanation": fields.get("explanation", ""),
            "confidence": fields.get("confidence", "low").lower(),
        }

    # Path B: audit decision-point format (KIND + OFFSET + INSTRUCTION) ->
    # deterministically derive exact bytes from the binary.
    if kind and ev is not None:
        derived = _derive_il_patch(ev, offset, kind, target_name, fields.get("instruction", ""))
        if not derived:
            return None
        derived["explanation"] = fields.get("explanation", "") or derived.get("insn_flip", "")
        derived["confidence"] = fields.get("confidence", "medium").lower()
        return derived

    return None


def verify_patch(ev: Evidence, patch: dict) -> dict:
    """Verify a proposed patch against the actual binary/IL.

    Returns a dict with 'valid' (bool), 'reason' (str), and optionally
    'difficulty' (str).
    """
    offset = patch["offset"]
    orig = bytes.fromhex(patch["original"])
    patched = bytes.fromhex(patch["patched"])

    # For .NET: verify against the IL body of the target method
    if ev.dotnet and ev.dotnet.ok:
        # Find a method whose body contains those bytes at that offset.
        # The model gives offset relative to the method body start (IL_0000).
        for m in ev.dotnet.methods:
            if not m["rva"]:
                continue
            body = ev.dotnet.method_body(m["rva"])
            if not body:
                continue
            if offset < 0 or offset + len(orig) > len(body):
                continue
            actual = body[offset:offset + len(orig)]
            if actual == orig:
                # Bytes match — this is the right method and the patch is grounded
                difficulty = _assess_difficulty(orig, patched, patch.get("strategy", ""))
                return {
                    "valid": True,
                    "reason": f"bytes at IL offset 0x{offset:04x} match: {orig.hex()} → {patched.hex()}",
                    "method": m["name"],
                    "difficulty": difficulty,
                }
        # Offset given but no method body has those bytes there
        return {
            "valid": False,
            "reason": f"no method body contains {orig.hex()} at offset 0x{offset:04x}",
            "difficulty": "unknown",
        }

    # For native: verify against file bytes
    if ev.pe:
        data = ev.pe.data
        if 0 <= offset < len(data) and offset + len(orig) <= len(data):
            actual = data[offset:offset + len(orig)]
            if actual == orig:
                difficulty = _assess_difficulty(orig, patched, patch.get("strategy", ""))
                return {
                    "valid": True,
                    "reason": f"bytes at file offset 0x{offset:x} match: {orig.hex()} → {patched.hex()}",
                    "difficulty": difficulty,
                }
            return {
                "valid": False,
                "reason": f"bytes at 0x{offset:x} are {actual.hex()}, not {orig.hex()}",
                "difficulty": "unknown",
            }
        # Maybe the offset is an RVA — try converting
        file_off = ev.pe.rva_to_offset(offset)
        if file_off is not None and 0 <= file_off < len(data) and file_off + len(orig) <= len(data):
            actual = data[file_off:file_off + len(orig)]
            if actual == orig:
                difficulty = _assess_difficulty(orig, patched, patch.get("strategy", ""))
                return {
                    "valid": True,
                    "reason": f"bytes at RVA 0x{offset:x} (file 0x{file_off:x}) match",
                    "method": None,
                    "difficulty": difficulty,
                }

    return {
        "valid": False,
        "reason": "could not locate the specified bytes in the binary",
        "difficulty": "unknown",
    }


def _assess_difficulty(orig: bytes, patched: bytes, strategy: str) -> str:
    """Rate how easy the patch is: TRIVIAL / EASY / MODERATE."""
    n = len(orig)
    if n <= 2:
        # 1-2 byte patch: branch flip, constant change
        return "TRIVIAL"
    if n <= 4:
        return "EASY"
    return "MODERATE"


def crack_simulate(ev: Evidence, round1: dict, timeout: int = 120) -> dict:
    """Round 2: given a successful Round 1, ask the model for a specific patch.

    Returns a dict with crack_simulation data or an error.
    """
    if not round1.get("success"):
        return {"error": "Round 1 did not find a function; skipping crack simulation"}

    try:
        cfg = resolve_config()
    except AIConfigError as err:
        return {"error": str(err), "error_code": "AI_CONFIG"}

    raw_timeout = os.environ.get("TRAPKEY_AI_TIMEOUT", "")
    if raw_timeout:
        try:
            timeout = max(5, int(raw_timeout))
        except ValueError:
            pass

    pack = _build_round2_pack(ev, round1)
    started = time.time()
    try:
        if cfg["style"] == "anthropic":
            caller = _call_anthropic
        elif cfg["style"] == "gemini":
            caller = _call_gemini
        else:
            caller = _call_openai
        text, usage = _call_round2(cfg, pack, timeout, caller)
    except urllib.error.HTTPError as err:
        raw = ""
        try:
            raw = err.read().decode("utf-8", "ignore")
        except Exception:
            pass
        code, retry_after = classify_failure(err.code, raw)
        return {
            "error": f"{cfg['provider']} HTTP {err.code}: {raw[:600]}",
            "error_code": code,
            "retry_after": retry_after,
        }
    except Exception as err:
        return {"error": f"Round 2 call failed: {err}", "error_code": "AI_NETWORK"}

    elapsed = round(time.time() - started, 2)

    if not text.strip():
        return {
            "error": f"{cfg['model']} returned no content for Round 2",
            "error_code": "AI_EMPTY",
        }

    patch = _parse_round2(text, ev=ev, target_name=round1.get("raw_function", ""))
    if not patch:
        return {
            "seconds": elapsed,
            "model": cfg["model"],
            "success": False,
            "output_sample": text[:400],
            "usage": usage,
            "reason": "model could not propose a patch",
        }

    # Verify the patch against the actual binary
    verification = verify_patch(ev, patch)
    patch["verified"] = verification["valid"]
    patch["verify_reason"] = verification["reason"]
    patch["method"] = verification.get("method")
    if verification["valid"]:
        patch["difficulty"] = verification["difficulty"]

    return {
        "seconds": elapsed,
        "model": cfg["model"],
        "success": verification["valid"],
        "patch": patch,
        "output_sample": text[:400],
        "usage": usage,
    }


def _call_round2(
    cfg: dict, pack: str, timeout: int,
    caller,
) -> tuple[str, dict]:
    """Dispatch Round 2 to the right provider, with its own prompt."""
    prompt = PROMPT_ROUND2 + pack
    # Round 2 computes jump offsets/bytes, so reasoning models can spend ~1k
    # thinking tokens before emitting the structured patch.
    budget_tokens = max(token_budget(), 2000)
    if cfg["style"] == "openai":
        headers = {"content-type": "application/json", "user-agent": "trapkey/1.0"}
        if "opencode.ai/inference/go" in cfg["base"]:
            headers["x-opencode-session"] = os.urandom(16).hex()
        if not cfg["local"] or cfg["key"] != "local":
            headers["authorization"] = f"Bearer {cfg['key']}"
        body = {
            "model": cfg["model"],
            "temperature": 0,
            "max_tokens": budget_tokens,
            "stream": False,
            "messages": [
                {"role": "system", "content": "You are a precise reverse engineering assistant."},
                {"role": "user", "content": prompt},
            ],
        }
        effort = os.environ.get("TRAPKEY_AI_REASONING_EFFORT")
        if effort:
            body["reasoning_effort"] = effort
        data = _post(f"{cfg['base']}/chat/completions", body, headers, timeout)
        return data["choices"][0]["message"]["content"], data.get("usage") or {}
    elif cfg["style"] == "anthropic":
        headers = {
            "content-type": "application/json",
            "x-api-key": cfg["key"],
            "anthropic-version": "2023-06-01",
        }
        body = {
            "model": cfg["model"],
            "max_tokens": budget_tokens,
            "temperature": 0,
            "stream": False,
            "system": "You are a precise reverse engineering assistant.",
            "messages": [{"role": "user", "content": prompt}],
        }
        data = _post(f"{cfg['base']}/v1/messages", body, headers, timeout)
        text = "".join(block.get("text", "") for block in data.get("content", []))
        return text, data.get("usage") or {}
    else:  # gemini
        headers = {
            "content-type": "application/json",
            "x-goog-api-key": cfg["key"],
        }
        generation = {"temperature": 0, "maxOutputTokens": budget_tokens}
        budget = gemini_thinking_budget()
        if budget is not None:
            generation["thinkingConfig"] = {"thinkingBudget": budget}
        body = {
            "systemInstruction": {
                "parts": [{"text": "You are a precise reverse engineering assistant."}]
            },
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": generation,
        }
        text, meta = _post_sse(
            f"{cfg['base']}/models/{cfg['model']}:streamGenerateContent?alt=sse",
            body, headers, timeout,
        )
        usage = {
            "prompt_tokens": meta.get("promptTokenCount", 0),
            "completion_tokens": meta.get("candidatesTokenCount", 0),
            "total_tokens": meta.get("totalTokenCount", 0),
        }
        return text, usage
