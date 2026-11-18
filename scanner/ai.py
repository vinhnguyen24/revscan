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


def _code_evidence(ev: Evidence, budget: int) -> str:
    """IL for .NET, xref-selected disassembly for native. Never raises: a missing
    objdump or a hostile PE must not break a paid scan."""
    if not code_enabled() or ev.pe is None:
        return ""
    try:
        if ev.dotnet and ev.dotnet.ok:
            from .il import dotnet_code

            return dotnet_code(ev.dotnet, budget_chars=budget)
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
        "output_sample": text[:400],
        "input_chars": len(pack),
        "code_chars": meta.get("code_chars", 0),
        "usage": usage,
    }
