"""Evidence-aware risk fusion and the unified scan-result contract.

An empty rule-evidence list means that the rule engine has no positive
evidence; it is not a benign or negative rule score. In that case the rules
signal is omitted from fusion so it cannot suppress an otherwise available
signal. When rule evidence exists, the configured weighted blend is preserved.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
import math
from typing import Any, Mapping
from uuid import uuid4

from .feature_extraction import extract_features
from .ml_classifier import MLResult, URLClassifier
from .normalization import NormalizedURL, normalize_url
from .rule_engine import RuleEvidence, evaluate_rules


class SignalStatus(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    NOT_IMPLEMENTED = "not_implemented"
    FAILED = "failed"


@dataclass(frozen=True)
class SignalResult:
    """A signal plus explicit execution state."""

    status: SignalStatus
    value: object | None = None
    score: float | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "value": _serialize(self.value),
            "score": self.score,
            "error": self.error,
        }


@dataclass(frozen=True)
class FusionWeights:
    """Starting product weights; these are not calibrated weights."""

    rules: float = 0.30
    ml: float = 0.30
    reputation: float = 0.25
    domain_intelligence: float = 0.15
    redirect: float = 0.10

    def __post_init__(self) -> None:
        if any(weight < 0 for weight in asdict(self).values()):
            raise ValueError("Fusion weights cannot be negative")
        if sum(asdict(self).values()) <= 0:
            raise ValueError("At least one fusion weight must be positive")


@dataclass(frozen=True)
class VerdictThresholds:
    suspicious: float = 30.0
    dangerous: float = 70.0

    def __post_init__(self) -> None:
        if not 0 <= self.suspicious < self.dangerous <= 100:
            raise ValueError("Thresholds must satisfy 0 <= suspicious < dangerous <= 100")


@dataclass(frozen=True)
class ScoreBreakdown:
    final_score: float
    rule_score: float | None
    ml_score: float | None
    reputation_score: float | None
    domain_intelligence_score: float | None
    redirect_score: float | None
    weighted_contributions: dict[str, float]
    available_signal_weights: dict[str, float]
    unavailable_signals: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class FusionResult:
    risk_score: float
    verdict: str
    recommendation: str
    score_breakdown: ScoreBreakdown

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    """Stable backend contract for future UI, API, and forensic consumers."""

    scan_id: str
    input_type: str
    original_input: str
    normalized_urls: list[dict[str, object]]
    verdict: str
    risk_score: float
    recommendation: str
    rule_result: SignalResult
    ml_result: SignalResult
    shap_result: SignalResult
    reputation_result: SignalResult
    domain_intelligence_result: SignalResult
    redirect_result: SignalResult
    triggered_rules: list[dict[str, object]]
    evidence: list[dict[str, object]]
    score_breakdown: ScoreBreakdown
    engine_metadata: dict[str, object]
    timestamp: str
    version: str = "0.1.0"

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        for name in (
            "rule_result",
            "ml_result",
            "shap_result",
            "reputation_result",
            "domain_intelligence_result",
            "redirect_result",
        ):
            result[name] = getattr(self, name).to_dict()
        result["score_breakdown"] = self.score_breakdown.to_dict()
        return _serialize(result)


DEFAULT_WEIGHTS = FusionWeights()
DEFAULT_THRESHOLDS = VerdictThresholds()


def normalize_rule_score(evidence: list[RuleEvidence]) -> float:
    """Convert bounded rule contributions to a 0-100 score."""

    total = max(0.0, sum(float(item.contribution) for item in evidence))
    return _clamp(100.0 * (1.0 - math.exp(-total / 40.0)))


def ml_score(result: MLResult) -> float:
    """Convert the unchanged ML probability to the fusion scale."""

    return _clamp(float(result.phishing_probability) * 100.0)


def fuse_signals(
    *,
    rule_evidence: list[RuleEvidence] | None = None,
    ml_result: MLResult | None = None,
    reputation: SignalResult | None = None,
    domain_intelligence: SignalResult | None = None,
    redirect: SignalResult | None = None,
    weights: FusionWeights = DEFAULT_WEIGHTS,
    thresholds: VerdictThresholds = DEFAULT_THRESHOLDS,
) -> FusionResult:
    """Fuse available signals without treating absent rule evidence as negative.

    An explicit empty ``rule_evidence`` list represents an available rule
    evaluation with no triggered evidence. The rules channel is therefore
    omitted from the numeric fusion rather than contributing a zero score.
    Non-empty rule evidence continues to use the existing availability-aware
    weighted blend.
    """

    rules_have_evidence = bool(rule_evidence)
    signals: dict[str, tuple[float | None, float, SignalStatus]] = {
        "rules": (
            normalize_rule_score(rule_evidence) if rules_have_evidence else None,
            weights.rules,
            SignalStatus.AVAILABLE if rules_have_evidence else SignalStatus.UNAVAILABLE,
        ),
        "ml": (ml_score(ml_result) if ml_result is not None else None, weights.ml,
               SignalStatus.AVAILABLE if ml_result is not None else SignalStatus.UNAVAILABLE),
        "reputation": _scored_signal(reputation, weights.reputation),
        "domain_intelligence": _scored_signal(domain_intelligence, weights.domain_intelligence),
        "redirect": _scored_signal(redirect, weights.redirect),
    }
    available = {
        name: (score, weight)
        for name, (score, weight, status) in signals.items()
        if status == SignalStatus.AVAILABLE and score is not None
    }
    denominator = sum(weight for _, weight in available.values())
    if denominator == 0:
        final_score = 0.0
    else:
        final_score = _clamp(
            sum(score * weight for score, weight in available.values()) / denominator
        )
    contributions = {
        name: _clamp(score * weight / denominator) if denominator else 0.0
        for name, (score, weight) in available.items()
    }
    unavailable = [name for name, (_, _, status) in signals.items() if status != SignalStatus.AVAILABLE]
    verdict, recommendation = classify_risk(final_score, thresholds)
    return FusionResult(
        risk_score=final_score,
        verdict=verdict,
        recommendation=recommendation,
        score_breakdown=ScoreBreakdown(
            final_score=final_score,
            rule_score=signals["rules"][0],
            ml_score=signals["ml"][0],
            reputation_score=signals["reputation"][0],
            domain_intelligence_score=signals["domain_intelligence"][0],
            redirect_score=signals["redirect"][0],
            weighted_contributions=contributions,
            available_signal_weights={
                name: weight for name, (_, weight) in available.items()
            },
            unavailable_signals=unavailable,
        ),
    )


def classify_risk(
    score: float, thresholds: VerdictThresholds = DEFAULT_THRESHOLDS
) -> tuple[str, str]:
    score = _clamp(score)
    if score >= thresholds.dangerous:
        return "dangerous", "Do not open this link or provide credentials."
    if score >= thresholds.suspicious:
        return "suspicious", "Verify the sender and destination before continuing."
    return "safe", "Proceed with normal caution."


def build_scan_result(
    original_input: str,
    *,
    classifier: URLClassifier | None = None,
    shap_result: object | None = None,
    reputation: SignalResult | None = None,
    domain_intelligence: SignalResult | None = None,
    redirect: SignalResult | None = None,
    input_type: str = "url",
    scan_id: str | None = None,
    weights: FusionWeights = DEFAULT_WEIGHTS,
    thresholds: VerdictThresholds = DEFAULT_THRESHOLDS,
) -> ScanResult:
    """Run the currently available local pipeline without future integrations."""

    normalized = normalize_url(original_input)
    features = extract_features(normalized)
    rules = evaluate_rules(normalized, features)
    ml = classifier.predict_one(normalized) if classifier is not None else None
    fusion = fuse_signals(
        rule_evidence=rules,
        ml_result=ml,
        reputation=reputation or not_implemented_signal(),
        domain_intelligence=domain_intelligence or not_implemented_signal(),
        redirect=redirect or not_implemented_signal(),
        weights=weights,
        thresholds=thresholds,
    )
    return ScanResult(
        scan_id=scan_id or str(uuid4()),
        input_type=input_type,
        original_input=original_input,
        normalized_urls=[normalized.to_dict()],
        verdict=fusion.verdict,
        risk_score=fusion.risk_score,
        recommendation=fusion.recommendation,
        rule_result=SignalResult(SignalStatus.AVAILABLE, [item.to_dict() for item in rules],
                                 fusion.score_breakdown.rule_score),
        ml_result=(
            SignalResult(SignalStatus.AVAILABLE, ml.to_dict(), fusion.score_breakdown.ml_score)
            if ml is not None
            else SignalResult(SignalStatus.UNAVAILABLE)
        ),
        shap_result=(
            SignalResult(SignalStatus.AVAILABLE, _serialize(shap_result))
            if shap_result is not None
            else SignalResult(SignalStatus.UNAVAILABLE)
        ),
        reputation_result=reputation or not_implemented_signal(),
        domain_intelligence_result=domain_intelligence or not_implemented_signal(),
        redirect_result=redirect or not_implemented_signal(),
        triggered_rules=[item.to_dict() for item in rules],
        evidence=[item.to_dict() for item in rules],
        score_breakdown=fusion.score_breakdown,
        engine_metadata={
            "normalization": "available",
            "feature_extraction": "available",
            "rule_engine": "available",
            "ml_classifier": "available" if classifier is not None else "not_run",
            "shap": "explanatory_only",
            "fusion_weights_are_calibrated": False,
        },
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


def not_implemented_signal() -> SignalResult:
    return SignalResult(SignalStatus.NOT_IMPLEMENTED)


def failed_signal(error: str) -> SignalResult:
    if not error:
        raise ValueError("A failure signal requires an error message")
    return SignalResult(SignalStatus.FAILED, error=error)


def _scored_signal(signal: SignalResult | None, weight: float) -> tuple[float | None, float, SignalStatus]:
    if signal is None:
        return None, weight, SignalStatus.UNAVAILABLE
    return (
        _clamp(signal.score) if signal.status == SignalStatus.AVAILABLE and signal.score is not None else None,
        weight,
        signal.status,
    )


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, float(value)))


def _serialize(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _serialize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serialize(item) for item in value]
    return value
