#!/usr/bin/env python3
"""TrapKey scan — how long until an AI reverse-engineering agent cracks this app?

    python3 scan.py App.exe
    python3 scan.py App.exe --json
    python3 scan.py dist/*.exe --min-seconds 60      # CI gate
    python3 scan.py App.exe --ai                     # measure against a live model

Exit codes: 0 ok · 1 below --min-seconds · 2 bad input · 3 AI provider unavailable.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from scanner import collect, estimate, human_duration, render, render_json, to_dict
from scanner.peinfo import PEError


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--min-seconds", type=float, default=None,
                    help="fail if the fastest model cracks it under this many seconds")
    ap.add_argument("--ai", action="store_true", help="measure with a live model (needs OPENAI_API_KEY)")
    args = ap.parse_args(argv)

    failed = False
    for path in args.files:
        p = Path(path)
        if not p.is_file():
            print(f"error: {path} not found", file=sys.stderr)
            return 2
        try:
            ev = collect(str(p))
        except PEError as err:
            print(f"error: {path}: {err}", file=sys.stderr)
            return 2

        if args.ai:
            from scanner.ai import measure

            result = measure(ev)
            if result.get("error"):
                code = result.get("error_code") or "AI_ERROR"
                retry_after = result.get("retry_after")
                if args.json:
                    # Structured even on failure: the web parses stdout before
                    # looking at the exit code, so an exhausted quota must not
                    # be reported as "engine could not read this file".
                    print(
                        json.dumps(
                            {
                                "ok": False,
                                "error": {
                                    "code": code,
                                    "message": result["error"],
                                    "retry_after": retry_after,
                                },
                            },
                            ensure_ascii=False,
                        )
                    )
                else:
                    suffix = f" (thử lại sau {retry_after}s)" if retry_after else ""
                    print(f"error[{code}]: {result['error']}{suffix}", file=sys.stderr)
                return 3
            est = estimate(ev)
            est.measured = {
                "seconds": result["seconds"],
                "model": result["model"],
                "provider": result.get("provider"),
                "success": result["success"],
                "grounded": result.get("grounded"),
                "output_sample": result.get("output_sample", "")[:200],
                "usage": result.get("usage"),
                "code_chars": result.get("code_chars", 0),
            }
            est.confidence = "model+measured"
            est.breakdown.append(
                f"measured: {result['model']} answered in {result['seconds']:.1f}s "
                f"(one round, tool time not included), success={result['success']}"
            )

        else:
            est = estimate(ev)

        print(render_json(ev, est) if args.json else render(ev, est))

        if args.min_seconds is not None and est.best < args.min_seconds:
            print(
                f"\nCI FAIL: fastest estimated crack {human_duration(est.best)} "
                f"< --min-seconds {human_duration(args.min_seconds)}",
                file=sys.stderr,
            )
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
