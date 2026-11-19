# Contributing to TrapKey

Thanks for your interest! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/vinhnguyen24/trap-key.git
cd trap-key
cp .env.example .env  # optional: configure AI provider

# Run the scanner
python scan.py path/to/some.exe

# Run the web UI
npm start

# Run all tests
npm test
```

**Requirements:**
- Python 3.10+
- Node.js 22+ (for web UI and tests)
- `objdump` (optional — for native disassembly in `--ai` evidence packs)

## Running Tests

```bash
npm test                       # all 256 tests
python tests/test_scan.py      # scanner only
node tests/test_web.js         # web e2e only
```

PE/.NET tests auto-skip without real binaries. To run them, set:
```bash
TRAPKEY_TEST_EXE=/path/to/native.exe
TRAPKEY_TEST_DOTNET=/path/to/dotnet.dll
TRAPKEY_TEST_BINARIES=/path/to/corpus/
```

## Code Style

- **Python**: type hints (`from __future__ import annotations`), no dependencies beyond stdlib + `cryptography` (verify/test only). Comments explain **why**, not **what**.
- **JavaScript**: CommonJS, no framework, template literals for HTML. Escape user input via `views.esc()`. Zero npm dependencies.
- **Tests**: `unittest` for Python, self-running scripts for Node. No mocking the engine — use real PE files where possible.

## Architecture Invariants

These are non-negotiable. Don't break them:

1. **Zero npm dependencies** in the web server. Server-rendered HTML, no build step.
2. **Engine runs as a subprocess** with timeout + SIGKILL. A bad PE must never crash the web server.
3. **Uploaded files are deleted immediately** after scan (even on error). Only SHA-256 + report are stored.
4. **Credits are deducted before scan**, refunded on engine error. Cache by SHA-256 for 24h.
5. **Never claim "uncrackable".** All output states it's a cost model; `--ai` is a live measurement.
6. **Never send user binaries to external servers.** `protect` runs locally.

## Pull Requests

1. Fork and create a branch from `main`
2. Make your changes
3. Run `npm test` and ensure all tests pass
4. Open a PR with a clear description of what and why

## Areas Where Help Is Needed

- **Calibration corpus**: More real-world Windows binaries (especially native C/C++ shareware) to improve the cost model. See [`benchmarks/README.md`](benchmarks/README.md).
- **SDK C++ build**: `sdk/cpp/` hasn't been compiled on MSVC yet.
- **More AI providers**: Test and document additional OpenAI-compatible endpoints.
- **Platform support**: macOS Mach-O, Linux ELF (currently Windows PE only).

## Reporting Security Issues

If you find a security vulnerability, please email vinh.nguyent@protonmail.com instead of opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
