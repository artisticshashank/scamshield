"""Reproducible, data-driven evaluation and benchmarking utilities.

This module intentionally does not contain a dataset or produce benchmark
numbers on its own. Callers provide records and prediction functions.
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
import random
import statistics
import time
from typing import Callable, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from .normalization import URLNormalizationError, normalize_url


EVALUATION_VERSION = "1.0"


class EvaluationError(ValueError):
    """Raised when supplied evaluation data or configuration is invalid."""


class BenchmarkMode(str, Enum):
    RULE_ONLY = "rule_only"
    ML_ONLY = "ml_only"
    REPUTATION_ONLY = "reputation_only"
    RULE_PLUS_ML = "rule_plus_ml"
    RULE_PLUS_REPUTATION = "rule_plus_reputation"
    ML_PLUS_REPUTATION = "ml_plus_reputation"
    FULL_SCAMSHIELD = "full_scamshield"


@dataclass(frozen=True)
class BenchmarkConfig:
    """Reproducibility metadata for one benchmark run."""

    seed: int = 42
    split_strategy: str = "auto"
    train_ratio: float = 0.6
    validation_ratio: float = 0.2
    threshold: float = 50.0
    evaluation_version: str = EVALUATION_VERSION

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class EvaluationRecord:
    url: str
    label: int
    timestamp: str | None = None
    source: str | None = None
    campaign_id: str | None = None
    domain: str | None = None
    family: str | None = None

    def normalized_url(self) -> str:
        return normalize_url(self.url).normalized_url

    def resolved_domain(self) -> str:
        if self.domain:
            return self.domain.lower().rstrip(".")
        return urlsplit(self.normalized_url()).hostname or ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DatasetSummary:
    total_samples: int
    benign_count: int
    malicious_count: int
    duplicate_count: int
    invalid_count: int
    conflicting_duplicate_count: int
    class_balance: dict[str, float]
    unique_domains: int
    timestamp_coverage: float

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class LeakageDiagnostics:
    exact_duplicate_urls: int
    normalized_duplicate_urls: int
    conflicting_labels: int
    same_domain_overlap: int
    same_host_overlap: int
    campaign_overlap: int
    timestamp_available: bool
    temporal_evaluation_available: bool
    warnings: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class EvaluationDataset:
    records: tuple[EvaluationRecord, ...]
    source_path: str | None = None

    @classmethod
    def from_records(cls, records: Iterable[EvaluationRecord]) -> "EvaluationDataset":
        values = tuple(records)
        if not values:
            raise EvaluationError("Dataset must contain at least one record")
        _validate_records(values)
        return cls(values)

    @classmethod
    def from_csv(cls, path: str | Path) -> "EvaluationDataset":
        source = Path(path)
        if not source.is_file():
            raise EvaluationError(f"Dataset file does not exist: {source.name}")
        try:
            with source.open(newline="", encoding="utf-8-sig") as stream:
                reader = csv.DictReader(stream)
                if not reader.fieldnames or not {"url", "label"} <= set(reader.fieldnames):
                    raise EvaluationError("CSV must contain url and label columns")
                records = [
                    EvaluationRecord(
                        url=(row.get("url") or "").strip(),
                        label=normalize_label(row.get("label")),
                        timestamp=_optional(row.get("timestamp")),
                        source=_optional(row.get("source")),
                        campaign_id=_optional(row.get("campaign_id")),
                        domain=_optional(row.get("domain")),
                        family=_optional(row.get("family") or row.get("category")),
                    )
                    for row in reader
                ]
        except csv.Error as exc:
            raise EvaluationError(f"Malformed CSV: {exc}") from exc
        dataset = cls.from_records(records)
        return cls(dataset.records, str(source))

    def summary(self) -> DatasetSummary:
        normalized = [_safe_normalized(record.url) for record in self.records]
        valid = [value for value in normalized if value is not None]
        domains = {record.resolved_domain() for record in self.records if _safe_domain(record)}
        counts = {0: sum(record.label == 0 for record in self.records),
                  1: sum(record.label == 1 for record in self.records)}
        duplicate_count = len(self.records) - len(set(self.records[i].url for i in range(len(self.records))))
        normalized_duplicates = len(valid) - len(set(valid))
        conflicts = _conflicting_duplicates(self.records)
        timestamped = sum(record.timestamp is not None for record in self.records)
        return DatasetSummary(
            total_samples=len(self.records),
            benign_count=counts[0],
            malicious_count=counts[1],
            duplicate_count=duplicate_count + normalized_duplicates,
            invalid_count=sum(value is None for value in normalized),
            conflicting_duplicate_count=conflicts,
            class_balance={str(label): count / len(self.records) for label, count in counts.items()},
            unique_domains=len(domains),
            timestamp_coverage=timestamped / len(self.records),
        )

    def leakage(self, train: Sequence[EvaluationRecord] | None = None,
                test: Sequence[EvaluationRecord] | None = None) -> LeakageDiagnostics:
        records = self.records
        comparing_partitions = train is not None or test is not None
        train_records = tuple(train) if train is not None else records
        test_records = tuple(test) if test is not None else records
        train_exact = {record.url for record in train_records}
        test_exact = {record.url for record in test_records}
        train_normalized = {_safe_normalized(record.url) for record in train_records}
        test_normalized = {_safe_normalized(record.url) for record in test_records}
        train_domains = {_safe_domain(record) for record in train_records}
        test_domains = {_safe_domain(record) for record in test_records}
        train_campaigns = {record.campaign_id for record in train_records if record.campaign_id}
        test_campaigns = {record.campaign_id for record in test_records if record.campaign_id}
        warnings: list[str] = []
        if train_domains & test_domains:
            warnings.append("same-domain overlap exists between train and test")
        if train_campaigns & test_campaigns:
            warnings.append("campaign overlap exists between train and test")
        timestamp_available = all(record.timestamp for record in records)
        exact_duplicates = (
            len(train_exact & test_exact)
            if comparing_partitions
            else len(records) - len({record.url for record in records})
        )
        normalized_duplicates = (
            len({item for item in train_normalized & test_normalized if item})
            if comparing_partitions
            else len([key for key in _normalized_counts(records) if _normalized_counts(records)[key] > 1])
        )
        return LeakageDiagnostics(
            exact_duplicate_urls=exact_duplicates,
            normalized_duplicate_urls=normalized_duplicates,
            conflicting_labels=_conflicting_duplicates(records),
            same_domain_overlap=len({item for item in train_domains & test_domains if item}),
            same_host_overlap=len({item for item in train_domains & test_domains if item}),
            campaign_overlap=len(train_campaigns & test_campaigns),
            timestamp_available=bool(timestamp_available),
            temporal_evaluation_available=bool(timestamp_available and len(records) > 1),
            warnings=warnings,
        )


FreshTestDataset = EvaluationDataset


@dataclass(frozen=True)
class DatasetSplit:
    train: tuple[EvaluationRecord, ...]
    validation: tuple[EvaluationRecord, ...]
    test: tuple[EvaluationRecord, ...]
    strategy: str
    seed: int

    def to_dict(self) -> dict[str, object]:
        return {
            "strategy": self.strategy,
            "seed": self.seed,
            "train_count": len(self.train),
            "validation_count": len(self.validation),
            "test_count": len(self.test),
        }


def split_dataset(
    dataset: EvaluationDataset,
    *,
    strategy: str = "auto",
    train_ratio: float = 0.6,
    validation_ratio: float = 0.2,
    seed: int = 42,
) -> DatasetSplit:
    if not 0 < train_ratio < 1 or not 0 <= validation_ratio < 1 or train_ratio + validation_ratio >= 1:
        raise EvaluationError("Split ratios must leave a non-empty test partition")
    records = list(dataset.records)
    chosen = strategy
    if strategy == "auto":
        chosen = "chronological" if dataset.leakage().temporal_evaluation_available else "stratified"
    if chosen == "chronological":
        if not all(record.timestamp for record in records):
            raise EvaluationError("Chronological split requires timestamps for every record")
        records.sort(key=lambda record: _parse_timestamp(record.timestamp or ""))
    elif chosen == "stratified":
        rng = random.Random(seed)
        rng.shuffle(records)
        try:
            train, remainder = train_test_split(
                records, train_size=train_ratio, random_state=seed,
                stratify=[record.label for record in records],
            )
            relative_test = 1 - train_ratio
            val_fraction = validation_ratio / relative_test
            try:
                validation, test = train_test_split(
                    remainder, test_size=1 - val_fraction, random_state=seed,
                    stratify=[record.label for record in remainder],
                )
            except ValueError:
                validation, test = train_test_split(
                    remainder, test_size=1 - val_fraction, random_state=seed
                )
            return DatasetSplit(tuple(train), tuple(validation), tuple(test), chosen, seed)
        except ValueError as exc:
            raise EvaluationError(f"Stratified split failed: {exc}") from exc
    elif chosen == "domain_grouped":
        groups: dict[str, list[EvaluationRecord]] = {}
        for record in records:
            groups.setdefault(record.resolved_domain(), []).append(record)
        ordered = sorted(groups.items(), key=lambda item: item[0])
        train, validation, test = [], [], []
        targets = (train_ratio, train_ratio + validation_ratio)
        for domain, group in ordered:
            current = len(train + validation + test) / len(records)
            destination = train if current < targets[0] else validation if current < targets[1] else test
            destination.extend(group)
        if not train or not validation or not test:
            raise EvaluationError("Domain-grouped split cannot create all three partitions")
        return DatasetSplit(tuple(train), tuple(validation), tuple(test), chosen, seed)
    else:
        raise EvaluationError("Unknown split strategy")
    first = int(len(records) * train_ratio)
    second = first + int(len(records) * validation_ratio)
    if first < 1 or second <= first or second >= len(records):
        raise EvaluationError("Dataset is too small for requested split ratios")
    return DatasetSplit(tuple(records[:first]), tuple(records[first:second]), tuple(records[second:]), chosen, seed)


@dataclass(frozen=True)
class Metrics:
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float | None
    false_positive_rate: float
    false_negative_rate: float
    confusion_matrix: list[list[int]]
    threshold: float
    benign_false_positives: int
    malicious_false_negatives: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def calculate_metrics(labels: Sequence[int], scores: Sequence[float], threshold: float = 50.0) -> Metrics:
    if len(labels) != len(scores) or not labels:
        raise EvaluationError("Labels and scores must be non-empty and the same length")
    if not 0 <= threshold <= 100:
        raise EvaluationError("Threshold must be between 0 and 100")
    predictions = [int(score >= threshold) for score in scores]
    matrix = confusion_matrix(labels, predictions, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    return Metrics(
        accuracy=float(accuracy_score(labels, predictions)),
        precision=float(precision_score(labels, predictions, zero_division=0)),
        recall=float(recall_score(labels, predictions, zero_division=0)),
        f1=float(f1_score(labels, predictions, zero_division=0)),
        roc_auc=float(roc_auc_score(labels, scores)) if len(set(labels)) == 2 else None,
        false_positive_rate=fp / (fp + tn) if fp + tn else 0.0,
        false_negative_rate=fn / (fn + tp) if fn + tp else 0.0,
        confusion_matrix=matrix.astype(int).tolist(),
        threshold=threshold,
        benign_false_positives=int(fp),
        malicious_false_negatives=int(fn),
    )


def threshold_analysis(labels: Sequence[int], scores: Sequence[float],
                       thresholds: Iterable[float] = range(0, 101)) -> list[dict[str, object]]:
    return [calculate_metrics(labels, scores, float(threshold)).to_dict() for threshold in thresholds]


@dataclass(frozen=True)
class LatencySummary:
    count: int
    median_ms: float
    p95_ms: float
    p99_ms: float

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def summarize_latency(samples_ms: Sequence[float]) -> LatencySummary:
    if not samples_ms:
        raise EvaluationError("Latency samples cannot be empty")
    values = sorted(float(value) for value in samples_ms)
    return LatencySummary(len(values), statistics.median(values), _percentile(values, 0.95),
                          _percentile(values, 0.99))


@dataclass(frozen=True)
class BenchmarkResult:
    mode: str
    dataset: dict[str, object]
    split: dict[str, object]
    metrics: dict[str, object]
    latency: dict[str, object]
    leakage: dict[str, object]
    configuration: dict[str, object]
    errors: list[dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    def human_report(self) -> str:
        metrics = self.metrics
        return (
            f"# ScamShield Benchmark ({self.mode})\n\n"
            f"- Samples: {self.dataset['total_samples']}\n"
            f"- Split: {self.split['strategy']}\n"
            f"- Accuracy: {metrics.get('accuracy')}\n"
            f"- Precision: {metrics.get('precision')}\n"
            f"- Recall: {metrics.get('recall')}\n"
            f"- F1: {metrics.get('f1')}\n"
            f"- ROC-AUC: {metrics.get('roc_auc')}\n\n"
            "Values are produced only from the supplied dataset; no production-readiness claim is implied.\n"
        )


Predictor = Callable[[str], float]


class BenchmarkEvaluator:
    """Evaluate a supplied predictor over one fixed test partition."""

    def __init__(self, dataset: EvaluationDataset, *, seed: int = 42) -> None:
        self.dataset = dataset
        self.seed = seed

    def split(self, *, strategy: str = "auto", train_ratio: float = 0.6,
              validation_ratio: float = 0.2) -> DatasetSplit:
        return split_dataset(
            self.dataset,
            strategy=strategy,
            train_ratio=train_ratio,
            validation_ratio=validation_ratio,
            seed=self.seed,
        )

    def compare_modes(
        self,
        predictors: Mapping[BenchmarkMode | str, Predictor],
        test: Sequence[EvaluationRecord],
        *,
        threshold: float = 50.0,
    ) -> dict[str, BenchmarkResult]:
        """Evaluate all supplied modes on exactly the same test partition."""

        return {
            mode.value if isinstance(mode, BenchmarkMode) else str(mode): self.evaluate(
                predictor, test, mode=mode, threshold=threshold
            )
            for mode, predictor in predictors.items()
        }

    def ablation(
        self,
        predictors: Mapping[str, Predictor],
        test: Sequence[EvaluationRecord],
        *,
        threshold: float = 50.0,
    ) -> dict[str, BenchmarkResult]:
        """Evaluate explicitly supplied ablation predictors without assumptions."""

        return {
            name: self.evaluate(predictor, test, mode=name, threshold=threshold)
            for name, predictor in predictors.items()
        }

    def evaluate(self, predictor: Predictor, test: Sequence[EvaluationRecord],
                 *, mode: BenchmarkMode | str, threshold: float = 50.0) -> BenchmarkResult:
        scores: list[float] = []
        latency: list[float] = []
        errors: list[dict[str, object]] = []
        labels: list[int] = []
        for record in test:
            started = time.perf_counter()
            try:
                score = float(predictor(record.url))
                if not 0 <= score <= 100:
                    raise EvaluationError("Predictor score must be between 0 and 100")
                scores.append(score)
                labels.append(record.label)
            except Exception as exc:
                errors.append({"url": record.url, "error": str(exc), "type": exc.__class__.__name__})
            finally:
                latency.append((time.perf_counter() - started) * 1000)
        if errors:
            raise EvaluationError(f"Predictor failed for {len(errors)} samples")
        metrics = calculate_metrics(labels, scores, threshold)
        split = {"strategy": "provided_test_partition", "test_count": len(test), "seed": self.seed}
        return BenchmarkResult(
            mode=mode.value if isinstance(mode, BenchmarkMode) else str(mode),
            dataset=self.dataset.summary().to_dict(),
            split=split,
            metrics=metrics.to_dict(),
            latency={"local_engine": summarize_latency(latency).to_dict()},
            leakage=self.dataset.leakage(test=test).to_dict(),
            configuration={
                "evaluation_version": EVALUATION_VERSION,
                "seed": self.seed,
                "threshold": threshold,
                "dataset": self.dataset.source_path,
            },
            errors=[],
        )


def normalize_label(value: object) -> int:
    text = str(value).strip().lower() if value is not None else ""
    if text in {"0", "benign", "legitimate", "legit", "safe"}:
        return 0
    if text in {"1", "malicious", "phishing", "phish", "scam", "bad"}:
        return 1
    raise EvaluationError(f"Unsupported or ambiguous label: {value!r}")


def _validate_records(records: Sequence[EvaluationRecord]) -> None:
    for record in records:
        if not record.url.strip():
            raise EvaluationError("Dataset contains a missing URL")
        if record.label not in {0, 1}:
            raise EvaluationError("Labels must be 0 or 1")
        try:
            normalize_url(record.url)
        except URLNormalizationError as exc:
            raise EvaluationError(f"Malformed URL: {record.url!r}") from exc
        if record.timestamp:
            _parse_timestamp(record.timestamp)


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvaluationError(f"Invalid timestamp: {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _safe_normalized(value: str) -> str | None:
    try:
        return normalize_url(value).normalized_url
    except URLNormalizationError:
        return None


def _safe_domain(record: EvaluationRecord) -> str | None:
    try:
        return record.resolved_domain()
    except (EvaluationError, URLNormalizationError):
        return None


def _conflicting_duplicates(records: Sequence[EvaluationRecord]) -> int:
    labels: dict[str, set[int]] = {}
    for record in records:
        normalized = _safe_normalized(record.url)
        if normalized:
            labels.setdefault(normalized, set()).add(record.label)
    return sum(len(values) > 1 for values in labels.values())


def _normalized_counts(records: Sequence[EvaluationRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        normalized = _safe_normalized(record.url)
        if normalized:
            counts[normalized] = counts.get(normalized, 0) + 1
    return counts


def _optional(value: str | None) -> str | None:
    return value.strip() if value and value.strip() else None


def _percentile(values: Sequence[float], fraction: float) -> float:
    if len(values) == 1:
        return values[0]
    index = (len(values) - 1) * fraction
    lower = int(index)
    upper = min(lower + 1, len(values) - 1)
    return values[lower] + (values[upper] - values[lower]) * (index - lower)
