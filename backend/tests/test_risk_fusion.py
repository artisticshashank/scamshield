import json

import pytest

from core.ml_classifier import MLResult, URLClassifier, URLRecord
from core.risk_fusion import (
    DEFAULT_THRESHOLDS,
    DEFAULT_WEIGHTS,
    FusionWeights,
    ScoreBreakdown,
    SignalResult,
    SignalStatus,
    VerdictThresholds,
    build_scan_result,
    classify_risk,
    failed_signal,
    fuse_signals,
    not_implemented_signal,
    normalize_rule_score,
)
from core.rule_engine import RuleEvidence


def evidence(score: int, rule_id: str = "RULE") -> RuleEvidence:
    return RuleEvidence(
        rule_id=rule_id,
        category="test",
        severity="medium",
        triggered=True,
        score=score,
        explanation="test evidence",
        feature="test",
        value=True,
    )


def ml_result(probability: float) -> MLResult:
    return MLResult("model", "1", probability, int(probability >= 0.5), 0.5, 10, {})


def test_rule_score_is_bounded_and_preserves_evidence() -> None:
    assert normalize_rule_score([evidence(1000)]) <= 100
    assert normalize_rule_score([]) == 0


def test_rules_only_fusion_renormalizes_available_weight() -> None:
    result = fuse_signals(rule_evidence=[evidence(20)])

    assert result.score_breakdown.rule_score > 0
    assert result.score_breakdown.ml_score is None
    assert result.score_breakdown.available_signal_weights == {"rules": DEFAULT_WEIGHTS.rules}
    assert result.risk_score == result.score_breakdown.rule_score


def test_ml_only_fusion_uses_probability_times_100() -> None:
    result = fuse_signals(ml_result=ml_result(0.72))

    assert result.risk_score == pytest.approx(72.0)
    assert result.score_breakdown.ml_score == pytest.approx(72.0)


def test_rules_and_ml_are_availability_normalized() -> None:
    rules = [evidence(40)]
    result = fuse_signals(rule_evidence=rules, ml_result=ml_result(0.8))
    expected_rule = normalize_rule_score(rules)
    expected = (expected_rule * 0.30 + 80 * 0.30) / 0.60

    assert result.risk_score == pytest.approx(expected)
    assert set(result.score_breakdown.weighted_contributions) == {"rules", "ml"}


def test_no_rule_evidence_does_not_suppress_ml_score() -> None:
    result = fuse_signals(rule_evidence=[], ml_result=ml_result(0.42))

    assert result.risk_score == pytest.approx(42.0)
    assert result.score_breakdown.rule_score is None
    assert result.score_breakdown.ml_score == pytest.approx(42.0)
    assert result.score_breakdown.weighted_contributions == {"ml": pytest.approx(42.0)}
    assert "rules" in result.score_breakdown.unavailable_signals


def test_rule_evidence_preserves_existing_blend_behavior() -> None:
    rules = [evidence(40)]
    result = fuse_signals(rule_evidence=rules, ml_result=ml_result(0.8))
    expected_rule = normalize_rule_score(rules)

    assert result.risk_score == pytest.approx((expected_rule + 80) / 2)
    assert result.score_breakdown.rule_score == pytest.approx(expected_rule)


def test_future_signals_are_not_implemented_and_do_not_lower_score() -> None:
    result = fuse_signals(ml_result=ml_result(0.8))

    assert result.score_breakdown.reputation_score is None
    assert result.score_breakdown.domain_intelligence_score is None
    assert {"reputation", "domain_intelligence"} <= set(
        result.score_breakdown.unavailable_signals
    )


def test_available_external_signal_fuses_when_rules_have_no_evidence() -> None:
    reputation = SignalResult(SignalStatus.AVAILABLE, score=60)

    result = fuse_signals(rule_evidence=[], ml_result=ml_result(0.8), reputation=reputation)

    expected = (80 * DEFAULT_WEIGHTS.ml + 60 * DEFAULT_WEIGHTS.reputation) / (
        DEFAULT_WEIGHTS.ml + DEFAULT_WEIGHTS.reputation
    )
    assert result.risk_score == pytest.approx(expected)
    assert result.score_breakdown.rule_score is None
    assert result.score_breakdown.reputation_score == 60


def test_failed_signal_is_explicit_and_excluded() -> None:
    result = fuse_signals(
        ml_result=ml_result(0.5),
        reputation=failed_signal("provider timeout"),
    )

    assert result.risk_score == pytest.approx(50)
    assert "reputation" in result.score_breakdown.unavailable_signals


def test_no_available_signals_is_safe_with_explicit_empty_breakdown() -> None:
    result = fuse_signals()

    assert result.risk_score == 0
    assert result.verdict == "safe"
    assert result.score_breakdown.weighted_contributions == {}


@pytest.mark.parametrize(
    ("score", "verdict"),
    [(0, "safe"), (29, "safe"), (30, "suspicious"), (69, "suspicious"), (70, "dangerous"), (100, "dangerous")],
)
def test_verdict_boundaries(score: float, verdict: str) -> None:
    assert classify_risk(score)[0] == verdict


def test_recommendations_are_deterministic() -> None:
    assert classify_risk(10)[1] == "Proceed with normal caution."
    assert classify_risk(40)[1] == "Verify the sender and destination before continuing."
    assert classify_risk(80)[1] == "Do not open this link or provide credentials."


def test_custom_weights_and_thresholds_are_centralized() -> None:
    result = fuse_signals(
        ml_result=ml_result(0.5),
        weights=FusionWeights(rules=0, ml=1, reputation=0, domain_intelligence=0),
        thresholds=VerdictThresholds(suspicious=40, dangerous=60),
    )

    assert result.risk_score == 50
    assert result.verdict == "suspicious"


def test_scan_result_is_complete_and_json_serializable() -> None:
    records = [
        URLRecord("https://example.com/about", 0),
        URLRecord("http://bad.invalid/login", 1),
        URLRecord("https://safe.example.org/home", 0),
        URLRecord("http://evil.invalid/verify", 1),
    ]
    model = URLClassifier.fit(records)

    result = build_scan_result("http://bad.invalid/login", classifier=model, scan_id="fixed-id")
    serialized = result.to_dict()

    json.dumps(serialized)
    assert result.scan_id == "fixed-id"
    assert result.normalized_urls
    assert result.triggered_rules == serialized["evidence"]
    assert result.reputation_result.status == SignalStatus.NOT_IMPLEMENTED
    assert result.domain_intelligence_result.status == SignalStatus.NOT_IMPLEMENTED
    assert result.redirect_result.status == SignalStatus.NOT_IMPLEMENTED
    assert result.shap_result.status == SignalStatus.UNAVAILABLE
    assert serialized["rule_result"]["status"] == "available"


def test_scan_result_without_ml_keeps_rules_only_behavior() -> None:
    result = build_scan_result("https://example.com/about")

    assert result.ml_result.status == SignalStatus.UNAVAILABLE
    assert result.risk_score == 0
    assert result.score_breakdown.rule_score is None
    assert result.verdict == "safe"


def test_scan_result_includes_available_shap_without_scoring_it() -> None:
    result = build_scan_result(
        "https://example.com/about",
        shap_result={"explainer_type": "shap.LinearExplainer", "top_features": []},
    )

    assert result.shap_result.status == SignalStatus.AVAILABLE
    assert result.shap_result.score is None
    assert "shap" not in result.score_breakdown.weighted_contributions


def test_signal_serialization_and_status_helpers() -> None:
    assert not_implemented_signal().to_dict()["status"] == "not_implemented"
    assert failed_signal("timeout").to_dict()["error"] == "timeout"


def test_invalid_thresholds_and_weights_are_rejected() -> None:
    with pytest.raises(ValueError):
        VerdictThresholds(suspicious=70, dangerous=30)
    with pytest.raises(ValueError):
        FusionWeights(
            rules=0,
            ml=0,
            reputation=0,
            domain_intelligence=0,
            redirect=0,
        )
