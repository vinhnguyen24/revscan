"""TrapKey scan engine.

    from scanner import scan
    result = scan("App.exe")
    print(result["crack_seconds_best"], result["resistance"])
"""

from .evidence import Evidence, collect
from .estimate import Estimate, estimate, human_duration
from .report import render, render_json, resistance, risk_score, to_dict

__all__ = [
    "Evidence",
    "collect",
    "Estimate",
    "estimate",
    "human_duration",
    "render",
    "render_json",
    "resistance",
    "risk_score",
    "to_dict",
    "scan",
]


def scan(path: str) -> dict:
    evidence = collect(path)
    est = estimate(evidence)
    return to_dict(evidence, est)
