from pathlib import Path

import pytest

from core.ml_classifier import (
    NGRAM_RANGE,
    URLClassifier,
    URLRecord,
    build_vectorizer,
    evaluate_model,
    load_csv_dataset,
    parse_label,
    split_dataset,
    train_from_records,
)
from core.normalization import normalize_url


RECORDS = [
    URLRecord("https://example.com/about", 0),
    URLRecord("https://www.example.org/contact", 0),
    URLRecord("https://docs.example.net/guide", 0),
    URLRecord("http://secure-login.invalid/account", 1),
    URLRecord("http://verify-payment.invalid/card", 1),
    URLRecord("http://urgent-alert.invalid/login", 1),
    URLRecord("https://portal.example.edu/home", 0),
    URLRecord("http://credential-check.invalid/verify", 1),
]


def test_vectorizer_is_character_ngrams_and_deterministic() -> None:
    first = build_vectorizer()
    second = build_vectorizer()

    assert first.analyzer == second.analyzer == "char"
    assert first.ngram_range == second.ngram_range == NGRAM_RANGE == (3, 5)
    assert first.get_params() == second.get_params()


def test_tiny_synthetic_dataset_fits_and_infers_probability() -> None:
    model = URLClassifier.fit(RECORDS[:6])

    result = model.predict_one(normalize_url("http://secure-login.invalid/verify"))

    assert 0.0 <= result.phishing_probability <= 1.0
    assert result.model_name == "url-char-ngram-logistic-regression"
    assert result.predicted_class in {0, 1}
    assert result.feature_count > 0
    assert result.inference_metadata["probability_is_calibrated"] is False


def test_repeated_inference_is_deterministic_and_supports_multiple_urls() -> None:
    model = URLClassifier.fit(RECORDS[:6])
    values = ["https://example.com/home", "http://bad.invalid/login"]

    first = [result.to_dict() for result in model.predict_many(values)]
    second = [result.to_dict() for result in model.predict_many(values)]

    assert first == second
    assert len(first) == 2


def test_model_save_and_load_preserves_inference(tmp_path: Path) -> None:
    model = URLClassifier.fit(RECORDS[:6])
    artifact = tmp_path / "url-model.pkl"
    model.save(artifact)

    loaded = URLClassifier.load(artifact)

    assert loaded.predict_one(RECORDS[3].url).to_dict() == model.predict_one(RECORDS[3].url).to_dict()
    assert loaded.vectorizer is not None
    assert loaded.classifier is not None


def test_pipeline_uses_normalized_url_before_model_inference() -> None:
    model = URLClassifier.fit(RECORDS[:6])
    raw = " HTTPS://EXAMPLE.COM/home "

    result = model.predict_one(raw)
    normalized = normalize_url(raw)

    assert result.feature_count == model.vectorizer.transform([normalized.normalized_url]).shape[1]


@pytest.mark.parametrize("value", ["", "not a url", None])
def test_malformed_or_empty_inference_input_is_rejected(value: object) -> None:
    model = URLClassifier.fit(RECORDS[:6])

    with pytest.raises((ValueError, TypeError)):
        model.predict_one(value)  # type: ignore[arg-type]


def test_training_rejects_empty_or_single_class_data() -> None:
    with pytest.raises(ValueError):
        URLClassifier.fit([])
    with pytest.raises(ValueError):
        URLClassifier.fit(RECORDS[:3])


def test_dataset_labels_and_csv_interface(tmp_path: Path) -> None:
    dataset = tmp_path / "urls.csv"
    dataset.write_text(
        "url,label,timestamp\n"
        "https://example.com,benign,2025-01-01T00:00:00Z\n"
        "http://bad.invalid,phishing,2025-01-02T00:00:00Z\n",
        encoding="utf-8",
    )

    records = load_csv_dataset(dataset)

    assert records[0].label == parse_label("benign") == 0
    assert records[1].label == parse_label("phishing") == 1
    assert records[1].timestamp == "2025-01-02T00:00:00Z"


def test_dataset_loader_rejects_missing_columns_and_bad_labels(tmp_path: Path) -> None:
    missing = tmp_path / "missing.csv"
    missing.write_text("url\nhttps://example.com\n", encoding="utf-8")
    with pytest.raises(ValueError):
        load_csv_dataset(missing)
    with pytest.raises(ValueError):
        parse_label("unknown")


def test_time_based_split_is_used_when_timestamps_exist() -> None:
    records = [
        URLRecord(f"https://example{i}.com", i % 2, f"2025-01-{i + 1:02d}T00:00:00Z")
        for i in range(8)
    ]

    split = split_dataset(records)

    assert split.strategy == "time-based chronological split"
    assert split.train[-1].timestamp < split.validation[0].timestamp
    assert split.validation[-1].timestamp < split.test[0].timestamp


def test_stratified_split_documents_missing_timestamp_limitation() -> None:
    split = split_dataset(RECORDS)

    assert "timestamps unavailable" in split.strategy
    assert sum(map(len, (split.train, split.validation, split.test))) == len(RECORDS)


def test_evaluation_report_contains_required_metrics() -> None:
    model, split, report = train_from_records(RECORDS)
    serialized = report.to_dict()

    assert report.sample_count == len(split.test)
    assert 0.0 <= report.precision <= 1.0
    assert 0.0 <= report.recall <= 1.0
    assert 0.0 <= report.f1 <= 1.0
    assert 0.0 <= report.false_positive_rate <= 1.0
    assert report.roc_auc is None or 0.0 <= report.roc_auc <= 1.0
    assert len(report.confusion_matrix) == 2
    assert set(serialized) == set(report.__dataclass_fields__)


def test_evaluate_rejects_empty_records() -> None:
    model = URLClassifier.fit(RECORDS[:6])

    with pytest.raises(ValueError):
        evaluate_model(model, [], "test")
