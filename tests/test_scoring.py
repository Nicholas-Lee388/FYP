from backend.services.scoring import RiskFactors, overall_risk, score_from_factors, severity_from_score


def test_score_from_factors_uses_confidence_multiplier():
    high_confidence = score_from_factors(RiskFactors(impact=8, exposure=8, exploitability=8, confidence="High"))
    low_confidence = score_from_factors(RiskFactors(impact=8, exposure=8, exploitability=8, confidence="Low"))
    assert high_confidence > low_confidence


def test_severity_bands():
    assert severity_from_score(9.1) == "Critical"
    assert severity_from_score(7.2) == "High"
    assert severity_from_score(5.1) == "Medium"
    assert severity_from_score(2.0) == "Low"
    assert severity_from_score(0.0) == "Info"


def test_overall_risk_for_empty_findings():
    score, level = overall_risk([])
    assert score == 0.0
    assert level == "Info"

