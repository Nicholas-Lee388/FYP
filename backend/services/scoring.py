from __future__ import annotations

from dataclasses import dataclass


SEVERITY_BANDS = [
    ("Critical", 9.0, 10.0),
    ("High", 7.0, 8.9),
    ("Medium", 4.0, 6.9),
    ("Low", 1.0, 3.9),
    ("Info", 0.0, 0.9),
]

SEVERITY_WEIGHT = {
    "Critical": 10.0,
    "High": 8.0,
    "Medium": 5.5,
    "Low": 2.5,
    "Info": 0.0,
}

CONFIDENCE_MULTIPLIER = {
    "High": 1.0,
    "Medium": 0.8,
    "Low": 0.55,
}


@dataclass(frozen=True)
class RiskFactors:
    impact: float
    exposure: float
    exploitability: float
    confidence: str = "Medium"


def clamp(value: float, low: float = 0.0, high: float = 10.0) -> float:
    return max(low, min(high, value))


def score_from_factors(factors: RiskFactors) -> float:
    base = (factors.impact * 0.4) + (factors.exposure * 0.3) + (factors.exploitability * 0.3)
    return round(clamp(base * CONFIDENCE_MULTIPLIER.get(factors.confidence, 0.8)), 2)


def severity_from_score(score: float) -> str:
    for name, low, high in SEVERITY_BANDS:
        if low <= score <= high:
            return name
    return "Info"


def overall_risk(findings: list[dict]) -> tuple[float, str]:
    if not findings:
        return 0.0, "Info"

    weighted = 0.0
    for finding in findings:
        severity = finding.get("severity", "Info")
        score = float(finding.get("score", 0.0))
        weighted += score * (SEVERITY_WEIGHT.get(severity, 0.0) / 10.0)

    average_component = weighted / max(len(findings), 1)
    high_count = sum(1 for item in findings if item.get("severity") in {"High", "Critical"})
    medium_count = sum(1 for item in findings if item.get("severity") == "Medium")
    volume_boost = min(2.0, high_count * 0.8 + medium_count * 0.25)
    score = round(clamp(average_component + volume_boost), 2)
    return score, severity_from_score(score)

