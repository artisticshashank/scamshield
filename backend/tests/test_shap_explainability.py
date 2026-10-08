from pathlib import Path

import pytest

from core.ml_classifier import URLClassifier, URLRecord
from core.shap_explainability import explain_url


try:
    import shap
except (ImportError, OSError):
    pytest.skip("SHAP import is blocked by the environment", allow_module_level=True)

RECORDS = [
    URLRecord("https://example.com/about", 0),
    URLRecord("https://safe.example.org/home", 0),
    URLRecord("https://docs.example.net/guide", 0),
    URLRecord("http://secure-login.invalid/account", 1),
    URLRecord("http://verify-payment.invalid/card", 1),
    URLRecord("http://urgent-alert.invalid/login", 1),
]


def test_explanation_uses_actual_binary_model_prediction() -> None:
    model = URLClassifier.fit(RECORDS)
    result = explain_url(model, "http://secure-login.invalid/verify")

    assert result.explainer_type == "shap.LinearExplainer"
    assert result.explained_class == "phishing"
    assert result.top_features
    assert result.metadata["model_prediction"] == model.predict_one(
        "http://secure-login.invalid/verify"
    ).predicted_class
    assert result.base_value + result.metadata["shap_value_sum"] == pytest.approx(
        result.prediction_value
    )


def test_explanation_is_deterministic() -> None:
    model = URLClassifier.fit(RECORDS)
    first = explain_url(model, "https://example.com/about").to_dict()
    second = explain_url(model, "https://example.com/about").to_dict()

    assert first == second


def test_selected_attributions_preserve_real_shap_signs() -> None:
    model = URLClassifier.fit(RECORDS)
    result = explain_url(model, "http://secure-login.invalid/verify", max_features=50)

    feature_names = set(model.vectorizer.get_feature_names_out())
    directions = {feature.direction for feature in result.top_features}
    assert directions <= {"phishing", "benign"}
    assert all(feature.feature in feature_names for feature in result.top_features)
    assert all(feature.contribution == feature.shap_value for feature in result.top_features)
    assert all(
        (feature.shap_value > 0 and feature.direction == "phishing")
        or (feature.shap_value < 0 and feature.direction == "benign")
        for feature in result.top_features
    )
    assert all(
        feature.shap_value == feature.contribution
        and feature.shap_value != 0.0
        for feature in result.top_features
    )


def test_top_feature_limits_are_respected() -> None:
    model = URLClassifier.fit(RECORDS)
    result = explain_url(model, "http://verify-payment.invalid/card", max_features=3)

    assert len(result.top_features) <= 3


def test_result_is_json_serializable() -> None:
    import json

    result = explain_url(URLClassifier.fit(RECORDS), "https://example.com").to_dict()

    json.dumps(result)
    assert {"explainer_type", "base_value", "prediction_value", "expected_value"} <= result.keys()


@pytest.mark.parametrize("value", ["", "not a url", None])
def test_malformed_or_empty_input_is_rejected(value: object) -> None:
    with pytest.raises((ValueError, TypeError)):
        explain_url(URLClassifier.fit(RECORDS), value)  # type: ignore[arg-type]


def test_saved_model_can_be_explained(tmp_path: Path) -> None:
    model = URLClassifier.fit(RECORDS)
    path = tmp_path / "model.pkl"
    model.save(path)

    result = explain_url(URLClassifier.load(path), RECORDS[3].url)

    assert result.model_name == "url-char-ngram-logistic-regression"
