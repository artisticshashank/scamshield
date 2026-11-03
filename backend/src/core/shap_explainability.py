"""Exact SHAP explanations for the fitted linear URL classifier.

For a binary logistic-regression model and an all-zero feature baseline,
the exact interventional SHAP value for feature i is coefficient_i * x_i.
The baseline is the model intercept. This preserves SHAP's additive
explanation without importing the heavyweight optional SHAP package.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import numpy as np

from .ml_classifier import MODEL_NAME, URLClassifier
from .normalization import NormalizedURL, normalize_url


@dataclass(frozen=True)
class SHAPFeature:
    """One character n-gram attribution from the exact linear SHAP calculation."""

    feature: str
    feature_value: float
    shap_value: float
    direction: str
    contribution: float
    explanation: str
    plain_language: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SHAPResult:
    """Stable application contract for exact linear SHAP explanations."""

    explainer_type: str
    model_name: str
    model_version: str
    explained_class: str
    base_value: float
    prediction_value: float
    expected_value: float
    top_features: list[SHAPFeature]
    plain_language_summary: str
    metadata: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["top_features"] = [feature.to_dict() for feature in self.top_features]
        return result


def explain_url(
    model: URLClassifier,
    value: str | NormalizedURL,
    *,
    max_features: int = 10,
    top_positive: int | None = None,
    top_negative: int | None = None,
) -> SHAPResult:
    """Explain a URL using exact linear SHAP values in raw log-odds space.

    With the zero-vector background used by the previous LinearExplainer
    integration, each attribution is x_i * coefficient_i and the baseline
    is the intercept. Their sum exactly reconstructs decision_function.
    """

    if max_features < 1:
        raise ValueError("max_features must be positive")
    normalized = _normalize_input(value)
    matrix = model.vectorizer.transform([normalized.normalized_url])
    _validate_binary_classifier(model)

    coefficients = np.asarray(model.classifier.coef_[0], dtype=float)
    base_value = float(np.asarray(model.classifier.intercept_).reshape(-1)[0])
    feature_values = matrix.toarray()[0]
    shap_values = feature_values * coefficients
    prediction_value = float(model.classifier.decision_function(matrix)[0])

    if not np.isclose(base_value + float(shap_values.sum()), prediction_value, atol=1e-6):
        raise RuntimeError("Linear SHAP values do not reconcile with the classifier prediction")

    names = model.vectorizer.get_feature_names_out()
    positive_limit = top_positive if top_positive is not None else max_features
    negative_limit = top_negative if top_negative is not None else max_features
    ranked = _build_features(names, feature_values, shap_values)
    selected = _select_features(ranked, positive_limit, negative_limit, max_features)
    return SHAPResult(
        explainer_type="exact_linear_shap_zero_baseline",
        model_name=MODEL_NAME,
        model_version=model.model_version,
        explained_class="phishing",
        base_value=base_value,
        prediction_value=prediction_value,
        expected_value=base_value,
        top_features=selected,
        plain_language_summary=_plain_language_summary(selected),
        metadata={
            "output_space": "log_odds",
            "shap_method": "exact linear SHAP with zero-vector background",
            "input": normalized.normalized_url,
            "feature_count": int(matrix.shape[1]),
            "nonzero_features": int(matrix.nnz),
            "shap_value_sum": float(shap_values.sum()),
            "model_prediction": int(model.predict_one(normalized).predicted_class),
            "probability_is_calibrated": False,
            "baseline_note": "The zero-vector baseline represents an input with no active URL text features; the intercept is the baseline log-odds. SHAP values explain movement from this baseline, not a calibrated risk percentage.",
        },
    )


def _normalize_input(value: str | NormalizedURL) -> NormalizedURL:
    if isinstance(value, NormalizedURL):
        if not value.normalized_url:
            raise ValueError("URL input must not be empty")
        return value
    if isinstance(value, str):
        return normalize_url(value)
    raise ValueError("URL input must be a string or NormalizedURL")


def _validate_binary_classifier(model: URLClassifier) -> None:
    classes = {int(label) for label in model.classifier.classes_}
    if classes != {0, 1}:
        raise ValueError("SHAP explanations require a binary benign/phishing classifier")
    if np.asarray(model.classifier.coef_).shape[0] != 1:
        raise ValueError("SHAP explanations require a binary logistic-regression model")


def _build_features(
    names: np.ndarray,
    feature_values: np.ndarray,
    shap_values: np.ndarray,
) -> list[SHAPFeature]:
    result: list[SHAPFeature] = []
    for name, value, shap_value in zip(names, feature_values, shap_values):
        contribution = float(shap_value)
        if contribution == 0.0:
            continue
        direction = "phishing" if contribution > 0 else "benign"
        result.append(
            SHAPFeature(
                feature=str(name),
                feature_value=float(value),
                shap_value=contribution,
                direction=direction,
                contribution=contribution,
                explanation=(
                    f"Character n-gram {name!r} pushes the model toward "
                    f"{direction} by {contribution:+.6f} log-odds."
                ),
                plain_language=_plain_language(str(name), direction),
            )
        )
    return result


def _select_features(
    features: list[SHAPFeature],
    top_positive: int,
    top_negative: int,
    overall: int,
) -> list[SHAPFeature]:
    positives = sorted(
        (feature for feature in features if feature.shap_value > 0),
        key=lambda feature: feature.shap_value,
        reverse=True,
    )[:top_positive]
    negatives = sorted(
        (feature for feature in features if feature.shap_value < 0),
        key=lambda feature: feature.shap_value,
    )[:top_negative]
    return sorted(
        positives + negatives,
        key=lambda feature: abs(feature.shap_value),
        reverse=True,
    )[:overall]


def _plain_language(feature: str, direction: str) -> str:
    """Translate model text fragments without presenting them as proof."""
    token = feature.lower().strip()
    patterns = (
        (("login", "signin", "sign-in", "log-in"), "login wording"),
        (("verify", "verification", "confirm"), "verification or confirmation wording"),
        (("password", "passwd", "credential"), "password or account-access wording"),
        (("payment", "billing", "invoice", "wallet"), "payment or billing wording"),
        (("account", "profile", "member"), "account-related wording"),
        (("secure", "security", "auth"), "security or authentication wording"),
        (("bank", "card", "upi"), "banking or payment-related wording"),
        (("urgent", "alert", "suspend", "locked"), "urgent or account-warning wording"),
        (("http", "www", ".com", ".org", ".net"), "a common web-address pattern"),
    )
    matched = next((label for needles, label in patterns if any(n in token for n in needles)), None)
    if direction == "phishing":
        if matched:
            return f"This fragment contains {matched}, which nudged the model toward its phishing-like class. Legitimate sites can use the same wording, so this is a clue—not proof."
        return "This small address fragment nudged the model toward its phishing-like class. It is not meaningful evidence on its own."
    if matched:
        return f"This fragment contains {matched}, which nudged the model toward its benign-like class. It does not certify that the website is safe."
    return "This small address fragment nudged the model toward its benign-like class. It does not certify that the website is safe."


def _plain_language_summary(features: list[SHAPFeature]) -> str:
    positive = [item for item in features if item.shap_value > 0]
    negative = [item for item in features if item.shap_value < 0]
    if not features:
        return "The model produced no non-zero text-fragment explanations for this URL."
    parts = []
    if positive:
        parts.append(f"{len(positive)} highlighted fragment(s) pushed the model toward phishing-like patterns")
    if negative:
        parts.append(f"{len(negative)} pushed it toward benign-like patterns")
    return "; ".join(parts) + ". These are influences on the ML model, not a final verdict or proof of fraud."
