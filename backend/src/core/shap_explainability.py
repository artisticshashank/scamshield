"""SHAP explanations for the fitted URL TF-IDF/logistic-regression model."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
from scipy import sparse

from .ml_classifier import MODEL_NAME, URLClassifier
from .normalization import NormalizedURL, normalize_url


@dataclass(frozen=True)
class SHAPFeature:
    """One character n-gram attribution from the actual SHAP explanation."""

    feature: str
    feature_value: float
    shap_value: float
    direction: str
    contribution: float
    explanation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SHAPResult:
    """Stable application contract over SHAP's version-dependent shapes."""

    explainer_type: str
    model_name: str
    model_version: str
    explained_class: str
    base_value: float
    prediction_value: float
    expected_value: float
    top_features: list[SHAPFeature]
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
    """Explain one prediction using the exact fitted model and vectorizer.

    SHAP values are in the classifier's raw decision-function (log-odds)
    space. The additive identity is therefore:
    ``base_value + sum(shap_values) == prediction_value``.
    """

    if max_features < 1:
        raise ValueError("max_features must be positive")
    normalized = _normalize_input(value)
    matrix = model.vectorizer.transform([normalized.normalized_url])
    _validate_binary_classifier(model)
    shap = _load_shap()
    background = sparse.csr_matrix((1, matrix.shape[1]), dtype=np.float64)
    explainer = shap.LinearExplainer(model.classifier, background)
    explanation = explainer(matrix)
    shap_values = _normalize_shap_values(explanation.values, matrix.shape[1])
    base_value = _normalize_scalar(explanation.base_values)
    prediction_value = float(model.classifier.decision_function(matrix)[0])
    if not np.isclose(base_value + float(shap_values.sum()), prediction_value, atol=1e-6):
        raise RuntimeError("SHAP values do not reconcile with the classifier prediction")

    names = model.vectorizer.get_feature_names_out()
    feature_values = matrix.toarray()[0]
    positive_limit = top_positive if top_positive is not None else max_features
    negative_limit = top_negative if top_negative is not None else max_features
    ranked = _build_features(names, feature_values, shap_values)
    selected = _select_features(ranked, positive_limit, negative_limit, max_features)
    return SHAPResult(
        explainer_type="shap.LinearExplainer",
        model_name=MODEL_NAME,
        model_version=model.model_version,
        explained_class="phishing",
        base_value=base_value,
        prediction_value=prediction_value,
        expected_value=base_value,
        top_features=selected,
        metadata={
            "output_space": "log_odds",
            "shap_version": str(getattr(shap, "__version__", "unknown")),
            "input": normalized.normalized_url,
            "feature_count": int(matrix.shape[1]),
            "nonzero_features": int(matrix.nnz),
            "shap_value_sum": float(shap_values.sum()),
            "model_prediction": int(model.predict_one(normalized).predicted_class),
            "probability_is_calibrated": False,
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


def _load_shap() -> Any:
    try:
        import shap
    except (ImportError, OSError) as exc:
        raise RuntimeError(
            "SHAP is installed but unavailable in this environment; "
            "its compiled dependency could not be loaded"
        ) from exc
    return shap


def _normalize_shap_values(values: Any, feature_count: int) -> np.ndarray:
    array = np.asarray(values, dtype=float)
    if array.ndim == 3:
        array = array[0, :, 1]
    elif array.ndim == 2:
        array = array[0]
    elif array.ndim != 1:
        raise RuntimeError(f"Unsupported SHAP value shape: {array.shape}")
    if array.shape[0] != feature_count:
        raise RuntimeError("SHAP feature count does not match the fitted vectorizer")
    return array


def _normalize_scalar(value: Any) -> float:
    array = np.asarray(value, dtype=float).reshape(-1)
    if array.size == 0:
        raise RuntimeError("SHAP returned no expected value")
    return float(array[0])


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
