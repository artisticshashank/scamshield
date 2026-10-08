import csv
import hashlib
import json

import pytest

from core.evaluation import EvaluationError, EvaluationRecord
from core.ml_classifier import URLClassifier
from core.training import TrainingConfig, audit_csv, train_from_csv


ROWS = [
    ("https://good-a.example/home", "0", "2026-01-01T00:00:00Z"),
    ("https://good-b.example/login", "0", "2026-01-02T00:00:00Z"),
    ("https://good-c.example/account", "0", "2026-01-03T00:00:00Z"),
    ("http://bad-a.example/verify", "1", "2026-01-04T00:00:00Z"),
    ("http://bad-b.example/pay", "1", "2026-01-05T00:00:00Z"),
    ("http://bad-c.example/login", "1", "2026-01-06T00:00:00Z"),
    ("https://good-d.example/home", "0", "2026-01-07T00:00:00Z"),
    ("http://bad-d.example/verify", "1", "2026-01-08T00:00:00Z"),
    ("https://good-e.example/home", "0", "2026-01-09T00:00:00Z"),
    ("http://bad-e.example/verify", "1", "2026-01-10T00:00:00Z"),
]


def write_dataset(path, rows=ROWS) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["url", "label", "timestamp", "source", "campaign_id"])
        for index, (url, label, timestamp) in enumerate(rows):
            writer.writerow([url, label, timestamp, "synthetic", f"campaign-{index}"])


def test_audit_fingerprint_and_rejection_reporting(tmp_path) -> None:
    path = tmp_path / "data.csv"
    write_dataset(path, ROWS + [
        ("not a url", "0", ""),
        ("https://good-a.example/home", "1", ""),
    ])
    dataset, audit = audit_csv(path)
    assert dataset.records
    assert audit.total_rows == 12
    assert audit.rejected_rows == 3
    assert audit.conflicting_label_urls == 1
    assert audit.dataset_fingerprint == hashlib.sha256(path.read_bytes()).hexdigest()
    assert audit.source_distribution == {"synthetic": 9}


def test_conflict_policy_keep_is_explicit(tmp_path) -> None:
    path = tmp_path / "data.csv"
    write_dataset(path, ROWS + [("https://good-a.example/home", "1", "")])
    dataset, audit = audit_csv(path, conflict_policy="keep")
    assert len(dataset.records) == 11
    assert audit.conflicting_label_urls == 1


def test_training_artifact_metadata_save_load_and_metrics(tmp_path) -> None:
    dataset_path = tmp_path / "data.csv"
    artifact_path = tmp_path / "model.pkl"
    write_dataset(dataset_path)
    run = train_from_csv(
        dataset_path,
        artifact_path,
        config=TrainingConfig(split_strategy="chronological"),
    )

    assert artifact_path.is_file()
    assert run.audit.accepted_rows == len(ROWS)
    assert run.training_metadata["analyzer"] == "char"
    assert run.training_metadata["ngram_range"] == [3, 5]
    assert run.validation_metrics is not None
    assert run.test_metrics is not None
    assert run.model_card["dataset"]["dataset_fingerprint"]
    loaded = URLClassifier.load(artifact_path)
    assert loaded.metadata["dataset_fingerprint"] == run.audit.dataset_fingerprint
    assert loaded.predict_one(ROWS[-1][0]).to_dict() == URLClassifier.load(
        artifact_path
    ).predict_one(ROWS[-1][0]).to_dict()
    json.dumps(run.to_dict())


def test_training_reproducibility(tmp_path) -> None:
    dataset_path = tmp_path / "data.csv"
    first_path = tmp_path / "first.pkl"
    second_path = tmp_path / "second.pkl"
    write_dataset(dataset_path)
    first = train_from_csv(dataset_path, first_path)
    second = train_from_csv(dataset_path, second_path)
    assert first.audit.dataset_fingerprint == second.audit.dataset_fingerprint
    assert first.split == second.split
    assert first.training_metadata["feature_count"] == second.training_metadata["feature_count"]
    assert first.validation_metrics.to_dict() == second.validation_metrics.to_dict()
    assert first.test_metrics.to_dict() == second.test_metrics.to_dict()


def test_empty_single_class_and_invalid_policy_are_rejected(tmp_path) -> None:
    empty = tmp_path / "empty.csv"
    empty.write_text("url,label\n", encoding="utf-8")
    with pytest.raises(EvaluationError):
        audit_csv(empty)

    single = tmp_path / "single.csv"
    write_dataset(single, [(url, "0", timestamp) for url, _, timestamp in ROWS])
    with pytest.raises(EvaluationError):
        train_from_csv(single, tmp_path / "single.pkl")

    with pytest.raises(EvaluationError):
        audit_csv(single, conflict_policy="unknown")
