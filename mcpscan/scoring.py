"""Aggregate findings into a single risk score.

The score is a bounded 0-100 value weighted by severity and confidence. It is deterministic so
it can be tracked over time and asserted in CI.
"""

from __future__ import annotations

from mcpscan.config import Severity
from mcpscan.models import Finding

_SEVERITY_WEIGHT = {
    Severity.INFO: 0.0,
    Severity.LOW: 2.0,
    Severity.MEDIUM: 5.0,
    Severity.HIGH: 12.0,
    Severity.CRITICAL: 25.0,
}


def risk_score(findings: list[Finding]) -> int:
    """Compute a 0-100 risk score from findings.

    Uses diminishing returns (sqrt-like saturation) so a large number of low findings cannot
    dominate a single critical one.
    """

    if not findings:
        return 0
    raw = sum(_SEVERITY_WEIGHT[f.severity] * max(f.confidence, 0.1) for f in findings)
    # Saturate towards 100.
    score = 100.0 * (1.0 - 1.0 / (1.0 + raw / 40.0))
    return round(min(score, 100.0))
