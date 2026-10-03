"""Turn findings into a 0-100 risk score and a verdict.

Each finding contributes its severity weight (see models.Severity):
info 0, low 5, medium 15, high 30, critical 50. The total is capped at 100.
"""

from __future__ import annotations

from .models import Finding

CLEAN, SUSPICIOUS, PHISHING = "Clean", "Suspicious", "Likely phishing"
# (minimum score, verdict), highest first
THRESHOLDS = [(50, PHISHING), (20, SUSPICIOUS), (0, CLEAN)]
EXIT_CODES = {CLEAN: 0, SUSPICIOUS: 1, PHISHING: 2}


def score(findings: list[Finding]) -> tuple[int, str]:
    total = min(100, sum(int(f.severity) for f in findings))
    verdict = next(v for minimum, v in THRESHOLDS if total >= minimum)
    return total, verdict
