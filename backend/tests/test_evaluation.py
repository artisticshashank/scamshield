import csv
import json

import pytest

from core.evaluation import (
    BenchmarkConfig,
    BenchmarkEvaluator,
    BenchmarkMode,
    EvaluationDataset,
    EvaluationError,
    EvaluationRecord,
    calculate_metrics,
    normalize_label,
    split_dataset,
    summarize_latency,
    threshold_analysis,
)


RECORDS = [
    EvaluationRecord("https://good-a.example/home", 0, "2026-01-01T00:00:00Z"),
    EvaluationRecord("https://good-b.example/login", 0, "2026-01-02T00:00:00Z"),
    EvaluationRecord("http://bad-a.example/verify", 1, "2026-01-03T00:00:00Z"),
    EvaluationRecord("http://bad-b.example/pay", 1, "2026-01-04T00:00:00Z"),
    EvaluationRecord("https://good-c.example/account", 0, "2026-01-05T00:00:00Z"),
    EvaluationRecord("http://bad-c.example/login", 1, "2026-01-06T00:00:00Z"),
]


def test_labels_are_strictly_normalized() -> None:
    assert normalize_label("benign") == 0
    assert normalize_label("PHISHING") == 1
    with pytest.raises(EvaluationError):
        normalize_label("unknown")


def test_csv_loading_and_summary(tmp_path) -> None:
    path = tmp_path / "dataset.csv"
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["url", "label", "timestamp", "source"])
        writer.writeheader()
        writer.writerow({"url": RECORDS[0].url, "label": "benign", "timestamp": RECORDS[0].timestamp, "source": "test"})
        writer.writerow({"url": RECORDS[2].url, "label": "1", "timestamp": RECORDS[2].timestamp, "source": "test"})
    dataset = EvaluationDataset.from_csv(path)
    summary = dataset.summary()
    assert summary.total_samples == 2
    assert summary.benign_count == 1
    assert summary.malicious_count == 1
    assert summary.timestamp_coverage == 1


def test_missing_malformed_and_conflicting_records_are_rejected() -> None:
    with pytest.raises(EvaluationError):
        EvaluationDataset.from_records([EvaluationRecord("", 0)])
    with pytest.raises(EvaluationError):
        EvaluationDataset.from_records([EvaluationRecord("not a url", 0)])
    with pytest.raises(EvaluationError):
        EvaluationDataset.from_records([EvaluationRecord("https://example.com", 2)])


def test_duplicate_and_conflict_leakage_diagnostics() -> None:
    dataset = EvaluationDataset.from_records([
        EvaluationRecord("https://example.com/a", 0, campaign_id="c1"),
        EvaluationRecord("https://EXAMPLE.com/a", 1, campaign_id="c1"),
        EvaluationRecord("https://example.com/b", 0, campaign_id="c2"),
    ])
    summary = dataset.summary()
    leakage = dataset.leakage()
    assert summary.conflicting_duplicate_count == 1
    assert leakage.normalized_duplicate_urls == 1
    assert leakage.conflicting_labels == 1
    assert leakage.timestamp_available is False


def test_split_strategies_are_deterministic_and_temporal() -> None:
    dataset = EvaluationDataset.from_records(RECORDS)
    first = split_dataset(dataset, strategy="chronological")
    second = split_dataset(dataset, strategy="chronological")
    assert first.to_dict() == second.to_dict()
    assert first.train[-1].timestamp < first.validation[0].timestamp
    assert first.validation[-1].timestamp < first.test[0].timestamp

    grouped = split_dataset(dataset, strategy="domain_grouped")
    assert set(record.resolved_domain() for record in grouped.train).isdisjoint(
        record.resolved_domain() for record in grouped.test
    )


def test_stratified_split_and_auto_strategy() -> None:
    dataset = EvaluationDataset.from_records([EvaluationRecord(record.url, record.label) for record in RECORDS])
    split = split_dataset(dataset, strategy="stratified", seed=7)
    assert split.strategy == "stratified"
    assert split.train and split.validation and split.test
    assert split_dataset(dataset).strategy == "stratified"


def test_split_failures_are_explicit() -> None:
    single = EvaluationDataset.from_records([EvaluationRecord("https://one.example", 0)])
    with pytest.raises(EvaluationError):
        split_dataset(single, strategy="stratified")
    missing_time = EvaluationDataset.from_records(
        [EvaluationRecord("https://one.example", 0), EvaluationRecord("https://two.example", 1)]
    )
    with pytest.raises(EvaluationError):
        split_dataset(missing_time, strategy="chronological")


def test_metrics_thresholds_and_single_class_roc_auc() -> None:
    metrics = calculate_metrics([0, 0, 1, 1], [10, 80, 20, 90], threshold=50)
    assert metrics.confusion_matrix == [[1, 1], [1, 1]]
    assert metrics.false_positive_rate == 0.5
    assert metrics.false_negative_rate == 0.5
    assert metrics.roc_auc == 0.75
    assert len(threshold_analysis([0, 1], [20, 80], [0, 50, 100])) == 3
    assert calculate_metrics([0, 0], [20, 30]).roc_auc is None


def test_latency_summary_and_json_config() -> None:
    summary = summarize_latency([1, 2, 3, 4, 5])
    assert summary.median_ms == 3
    assert summary.p95_ms >= 4
    assert json.dumps(BenchmarkConfig().to_dict())


def test_benchmark_modes_same_test_partition_and_ablation() -> None:
    dataset = EvaluationDataset.from_records(RECORDS)
    evaluator = BenchmarkEvaluator(dataset)
    test = RECORDS[-2:]
    predictors = {
        BenchmarkMode.RULE_ONLY: lambda url: 90 if "bad" in url else 10,
        BenchmarkMode.ML_ONLY: lambda url: 80 if "bad" in url else 20,
    }
    compared = evaluator.compare_modes(predictors, test)
    assert set(compared) == {"rule_only", "ml_only"}
    assert all(result.split["test_count"] == 2 for result in compared.values())
    ablation = evaluator.ablation({"without_rules": predictors[BenchmarkMode.ML_ONLY]}, test)
    assert ablation["without_rules"].mode == "without_rules"


def test_benchmark_result_is_json_and_has_no_fabricated_values() -> None:
    dataset = EvaluationDataset.from_records(RECORDS)
    result = BenchmarkEvaluator(dataset).evaluate(
        lambda url: 90 if "bad" in url else 10,
        RECORDS,
        mode=BenchmarkMode.FULL_SCAMSHIELD,
    )
    json.dumps(result.to_dict())
    assert result.metrics["accuracy"] == 1.0
    assert "supplied dataset" in result.human_report()


def test_predictor_failures_are_visible() -> None:
    dataset = EvaluationDataset.from_records(RECORDS)
    with pytest.raises(EvaluationError, match="Predictor failed"):
        BenchmarkEvaluator(dataset).evaluate(
            lambda _: (_ for _ in ()).throw(RuntimeError("broken")),
            RECORDS[:1],
            mode=BenchmarkMode.RULE_ONLY,
        )
