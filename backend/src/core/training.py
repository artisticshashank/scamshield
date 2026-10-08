"""Audited dataset ingestion, baseline training, and held-out evaluation."""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Sequence

from .evaluation import (
    EVALUATION_VERSION,
    EvaluationDataset,
    EvaluationError,
    EvaluationRecord,
    Metrics,
    calculate_metrics,
    normalize_label,
    split_dataset,
)
from .ml_classifier import (
    MODEL_NAME,
    MODEL_VERSION,
    NGRAM_RANGE,
    RANDOM_STATE,
    URLClassifier,
    URLRecord,
)


@dataclass(frozen=True)
class RejectedRecord:
    row_number: int
    reason: str
    url: str | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DatasetAudit:
    source_path: str
    dataset_fingerprint: str
    total_rows: int
    accepted_rows: int
    rejected_rows: int
    benign_count: int
    malicious_count: int
    exact_duplicate_urls: int
    normalized_duplicate_urls: int
    conflicting_label_urls: int
    identical_domains_across_labels: int
    unique_domains: int
    unique_hosts: int
    timestamp_coverage: float
    malformed_records: int
    source_distribution: dict[str, int]
    campaign_distribution: dict[str, int]
    rejected_records: list[RejectedRecord]

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["rejected_records"] = [item.to_dict() for item in self.rejected_records]
        return result


@dataclass(frozen=True)
class TrainingConfig:
    conflict_policy: str = "reject"
    seed: int = RANDOM_STATE
    split_strategy: str = "auto"
    train_ratio: float = 0.6
    validation_ratio: float = 0.2
    threshold: float = 50.0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TrainingRun:
    audit: DatasetAudit
    split: dict[str, object]
    training_metadata: dict[str, object]
    validation_metrics: Metrics | None
    test_metrics: Metrics | None
    model_card: dict[str, object]
    artifact_path: str

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["audit"] = self.audit.to_dict()
        result["validation_metrics"] = (
            self.validation_metrics.to_dict() if self.validation_metrics else None
        )
        result["test_metrics"] = self.test_metrics.to_dict() if self.test_metrics else None
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def audit_csv(
    path: str | Path,
    *,
    conflict_policy: str = "reject",
) -> tuple[EvaluationDataset, DatasetAudit]:
    """Read every CSV row and report, rather than silently discard, rejects."""

    if conflict_policy not in {"reject", "keep"}:
        raise EvaluationError("conflict_policy must be 'reject' or 'keep'")
    source = Path(path)
    if not source.is_file():
        raise EvaluationError("Dataset file does not exist")
    raw = source.read_bytes()
    fingerprint = hashlib.sha256(raw).hexdigest()
    accepted: list[EvaluationRecord] = []
    rejected: list[RejectedRecord] = []
    total_rows = 0
    try:
        with source.open(newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            if not reader.fieldnames or not {"url", "label"} <= set(reader.fieldnames):
                raise EvaluationError("CSV must contain url and label columns")
            for row_number, row in enumerate(reader, start=2):
                total_rows += 1
                url = (row.get("url") or "").strip()
                try:
                    label = normalize_label(row.get("label"))
                    if not url:
                        raise EvaluationError("missing URL")
                    record = EvaluationRecord(
                        url=url,
                        label=label,
                        timestamp=_optional(row.get("timestamp")),
                        source=_optional(row.get("source")),
                        campaign_id=_optional(row.get("campaign_id")),
                        domain=_optional(row.get("domain")),
                        family=_optional(row.get("family") or row.get("category")),
                    )
                    record.normalized_url()
                    accepted.append(record)
                except (EvaluationError, ValueError) as exc:
                    rejected.append(RejectedRecord(row_number, str(exc), url or None))
    except csv.Error as exc:
        raise EvaluationError(f"Malformed CSV: {exc}") from exc

    conflicting = _conflicting_urls(accepted)
    if conflict_policy == "reject" and conflicting:
        kept: list[EvaluationRecord] = []
        for record in accepted:
            if record.normalized_url() in conflicting:
                rejected.append(
                    RejectedRecord(
                        0,
                        "conflicting labels for normalized URL",
                        record.url,
                    )
                )
            else:
                kept.append(record)
        accepted = kept
    if not accepted:
        raise EvaluationError("No usable records remain after dataset audit")
    dataset = EvaluationDataset.from_records(accepted)
    normalized = [record.normalized_url() for record in accepted]
    domains = [record.resolved_domain() for record in accepted]
    labels_by_domain: dict[str, set[int]] = {}
    for record, domain in zip(accepted, domains):
        labels_by_domain.setdefault(domain, set()).add(record.label)
    audit = DatasetAudit(
        source_path=str(source),
        dataset_fingerprint=fingerprint,
        total_rows=total_rows,
        accepted_rows=len(accepted),
        rejected_rows=len(rejected),
        benign_count=sum(record.label == 0 for record in accepted),
        malicious_count=sum(record.label == 1 for record in accepted),
        exact_duplicate_urls=len(accepted) - len({record.url for record in accepted}),
        normalized_duplicate_urls=len(normalized) - len(set(normalized)),
        conflicting_label_urls=len(conflicting),
        identical_domains_across_labels=sum(
            len(labels) > 1 for labels in labels_by_domain.values()
        ),
        unique_domains=len(set(domains)),
        unique_hosts=len(set(domains)),
        timestamp_coverage=sum(record.timestamp is not None for record in accepted) / len(accepted),
        malformed_records=sum("URL" in item.reason or "label" in item.reason for item in rejected),
        source_distribution=_distribution(record.source for record in accepted),
        campaign_distribution=_distribution(record.campaign_id for record in accepted),
        rejected_records=rejected,
    )
    return EvaluationDataset(tuple(accepted), str(source)), audit


def train_from_csv(
    path: str | Path,
    artifact_path: str | Path,
    *,
    config: TrainingConfig = TrainingConfig(),
) -> TrainingRun:
    dataset, audit = audit_csv(path, conflict_policy=config.conflict_policy)
    selected_strategy = config.split_strategy
    if selected_strategy == "auto" and not all(record.timestamp for record in dataset.records):
        selected_strategy = "domain_grouped"
        try:
            split = split_dataset(
                dataset,
                strategy=selected_strategy,
                train_ratio=config.train_ratio,
                validation_ratio=config.validation_ratio,
                seed=config.seed,
            )
        except EvaluationError:
            selected_strategy = "stratified"
            split = split_dataset(
                dataset,
                strategy=selected_strategy,
                train_ratio=config.train_ratio,
                validation_ratio=config.validation_ratio,
                seed=config.seed,
            )
    else:
        split = split_dataset(
            dataset,
            strategy=selected_strategy,
            train_ratio=config.train_ratio,
            validation_ratio=config.validation_ratio,
            seed=config.seed,
        )
    if len({record.label for record in split.train}) != 2:
        raise EvaluationError("Training partition must contain both classes")
    model = URLClassifier.fit(
        [URLRecord(record.url, record.label, record.timestamp) for record in split.train]
    )
    training_metadata = {
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "analyzer": "char",
        "ngram_range": list(NGRAM_RANGE),
        "lowercase": True,
        "strip_accents": "unicode",
        "sublinear_tf": True,
        "min_df": 1,
        "logistic_regression": {
            "solver": "liblinear",
            "max_iter": 1000,
            "random_state": RANDOM_STATE,
        },
        "random_seed": config.seed,
        "training_sample_count": len(split.train),
        "feature_count": len(model.vectorizer.get_feature_names_out()),
        "dataset_fingerprint": audit.dataset_fingerprint,
        "evaluation_version": EVALUATION_VERSION,
        "training_timestamp": datetime.now(timezone.utc).isoformat(),
    }
    model.metadata = training_metadata
    destination = Path(artifact_path)
    model.save(destination)
    validation = _evaluate_model(model, split.validation, config.threshold)
    test = _evaluate_model(model, split.test, config.threshold)
    card = {
        "dataset": audit.to_dict(),
        "split": {
            **split.to_dict(),
            "train_class_balance": _balance(split.train),
            "validation_class_balance": _balance(split.validation),
            "test_class_balance": _balance(split.test),
            "leakage": dataset.leakage(split.train, split.test).to_dict(),
        },
        "training": training_metadata,
        "validation_metrics": validation.to_dict() if validation else None,
        "test_metrics": test.to_dict() if test else None,
        "limitations": [
            "Metrics describe only the supplied dataset.",
            "Production thresholds and fusion weights were not changed.",
            "SHAP is explanatory only and was not required for scoring.",
        ],
    }
    return TrainingRun(
        audit,
        card["split"],
        training_metadata,
        validation,
        test,
        card,
        str(destination),
    )


def _evaluate_model(
    model: URLClassifier,
    records: Sequence[EvaluationRecord],
    threshold: float,
) -> Metrics | None:
    if not records:
        return None
    labels = [record.label for record in records]
    scores = [model.predict_one(record.url).phishing_probability * 100 for record in records]
    return calculate_metrics(labels, scores, threshold)


def _conflicting_urls(records: Sequence[EvaluationRecord]) -> set[str]:
    labels: dict[str, set[int]] = {}
    for record in records:
        labels.setdefault(record.normalized_url(), set()).add(record.label)
    return {url for url, values in labels.items() if len(values) > 1}


def _distribution(values: object) -> dict[str, int]:
    result: dict[str, int] = {}
    for value in values:
        if value:
            result[str(value)] = result.get(str(value), 0) + 1
    return result


def _balance(records: Sequence[EvaluationRecord]) -> dict[str, float]:
    if not records:
        return {}
    return {
        "0": sum(record.label == 0 for record in records) / len(records),
        "1": sum(record.label == 1 for record in records) / len(records),
    }


def _optional(value: str | None) -> str | None:
    return value.strip() if value and value.strip() else None
