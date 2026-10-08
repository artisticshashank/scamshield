"""Character n-gram TF-IDF and logistic-regression URL classifier.

Expected dataset CSV format:

    url,label,timestamp
    https://example.com,benign,2025-01-01T00:00:00Z
    http://bad.example/login,phishing,2025-01-02T00:00:00Z

``timestamp`` is optional. Labels may be 0/1 or one of the documented
benign/phishing aliases. No dataset is bundled with this project.
"""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from datetime import datetime
import math
from pathlib import Path
import pickle
from typing import Iterable, Sequence

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from .normalization import NormalizedURL, normalize_url


MODEL_NAME = "url-char-ngram-logistic-regression"
MODEL_VERSION = "0.1.0"
NGRAM_RANGE = (3, 5)
RANDOM_STATE = 42

_POSITIVE_LABELS = frozenset({"1", "malicious", "phishing", "phish", "scam", "bad"})
_NEGATIVE_LABELS = frozenset({"0", "benign", "legitimate", "legit", "safe", "good"})


@dataclass(frozen=True)
class URLRecord:
    url: str
    label: int
    timestamp: str | None = None


@dataclass(frozen=True)
class SplitData:
    train: tuple[URLRecord, ...]
    validation: tuple[URLRecord, ...]
    test: tuple[URLRecord, ...]
    strategy: str


@dataclass(frozen=True)
class EvaluationReport:
    precision: float
    recall: float
    f1: float
    roc_auc: float | None
    false_positive_rate: float
    confusion_matrix: list[list[int]]
    split_strategy: str
    sample_count: int

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class MLResult:
    model_name: str
    model_version: str
    phishing_probability: float
    predicted_class: int
    confidence: float
    feature_count: int
    inference_metadata: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class URLClassifier:
    """A fitted, persisted-together vectorizer and logistic-regression model."""

    def __init__(
        self,
        vectorizer: TfidfVectorizer,
        classifier: LogisticRegression,
        *,
        model_version: str = MODEL_VERSION,
        metadata: dict[str, object] | None = None,
    ) -> None:
        self.vectorizer = vectorizer
        self.classifier = classifier
        self.model_version = model_version
        self.metadata = metadata or {}

    @classmethod
    def fit(cls, records: Sequence[URLRecord]) -> "URLClassifier":
        if not records:
            raise ValueError("At least one training record is required")
        labels = [record.label for record in records]
        if set(labels) != {0, 1}:
            raise ValueError("Training data must contain both benign and phishing labels")
        vectorizer = build_vectorizer()
        matrix = vectorizer.fit_transform(_normalized_texts(records))
        classifier = LogisticRegression(
            max_iter=1000,
            random_state=RANDOM_STATE,
            solver="liblinear",
        )
        classifier.fit(matrix, labels)
        return cls(vectorizer, classifier)

    def predict_one(self, value: str | NormalizedURL) -> MLResult:
        if isinstance(value, NormalizedURL):
            normalized = value
        elif isinstance(value, str):
            normalized = normalize_url(value)
        else:
            raise ValueError("URL input must be a string or NormalizedURL")
        if not normalized.normalized_url:
            raise ValueError("URL input must not be empty")
        matrix = self.vectorizer.transform([normalized.normalized_url])
        probabilities = self.classifier.predict_proba(matrix)[0]
        positive_index = _positive_class_index(self.classifier.classes_)
        probability = float(probabilities[positive_index])
        predicted = int(self.classifier.predict(matrix)[0])
        return MLResult(
            model_name=MODEL_NAME,
            model_version=self.model_version,
            phishing_probability=probability,
            predicted_class=predicted,
            confidence=float(max(probabilities)),
            feature_count=int(matrix.shape[1]),
            inference_metadata={
                "vectorizer": "tfidf",
                "analyzer": "char",
                "ngram_range": list(NGRAM_RANGE),
                "nonzero_features": int(matrix.nnz),
                "probability_is_calibrated": False,
            },
        )

    def predict_many(self, values: Iterable[str | NormalizedURL]) -> list[MLResult]:
        return [self.predict_one(value) for value in values]

    def save(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("wb") as stream:
            pickle.dump(self, stream, protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def load(cls, path: str | Path) -> "URLClassifier":
        with Path(path).open("rb") as stream:
            model = pickle.load(stream)
        if not isinstance(model, cls):
            raise ValueError("Model artifact is not a URLClassifier")
        return model


def build_vectorizer() -> TfidfVectorizer:
    """Build the deterministic character vectorizer used by every model."""

    return TfidfVectorizer(
        analyzer="char",
        ngram_range=NGRAM_RANGE,
        lowercase=True,
        strip_accents="unicode",
        sublinear_tf=True,
        min_df=1,
    )


def load_csv_dataset(path: str | Path) -> list[URLRecord]:
    """Load URL records from a CSV without silently dropping malformed rows."""

    records: list[URLRecord] = []
    with Path(path).open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or not {"url", "label"} <= set(reader.fieldnames):
            raise ValueError("Dataset CSV must contain url and label columns")
        for line_number, row in enumerate(reader, start=2):
            raw_url = (row.get("url") or "").strip()
            if not raw_url:
                raise ValueError(f"Dataset row {line_number} has an empty URL")
            records.append(
                URLRecord(
                    url=raw_url,
                    label=parse_label(row.get("label")),
                    timestamp=(row.get("timestamp") or "").strip() or None,
                )
            )
    if not records:
        raise ValueError("Dataset CSV contains no records")
    return records


def parse_label(value: str | None) -> int:
    if value is None:
        raise ValueError("Dataset label is required")
    label = value.strip().lower()
    if label in _POSITIVE_LABELS:
        return 1
    if label in _NEGATIVE_LABELS:
        return 0
    raise ValueError(f"Unsupported dataset label: {value!r}")


def split_dataset(
    records: Sequence[URLRecord],
    *,
    train_size: float = 0.7,
    validation_size: float = 0.15,
) -> SplitData:
    """Use chronological splitting when every record has a timestamp.

    Without complete timestamps, use deterministic stratification and expose the
    limitation in ``strategy`` rather than claiming temporal generalization.
    """

    if len(records) < 6:
        raise ValueError("At least 6 records are required for train/validation/test splits")
    if all(record.timestamp for record in records):
        ordered = sorted(records, key=lambda record: _parse_timestamp(record.timestamp or ""))
        train_end = max(1, int(len(ordered) * train_size))
        validation_end = max(train_end + 1, int(len(ordered) * (train_size + validation_size)))
        validation_end = min(validation_end, len(ordered) - 1)
        return SplitData(
            tuple(ordered[:train_end]),
            tuple(ordered[train_end:validation_end]),
            tuple(ordered[validation_end:]),
            "time-based chronological split",
        )

    train, remainder = train_test_split(
        list(records),
        test_size=1 - train_size,
        random_state=RANDOM_STATE,
        stratify=[record.label for record in records],
    )
    relative_validation = validation_size / (1 - train_size)
    remainder_labels = [record.label for record in remainder]
    can_stratify_remainder = (
        len(remainder) >= 4
        and min(remainder_labels.count(label) for label in {0, 1}) >= 2
    )
    validation, test = train_test_split(
        remainder,
        test_size=1 - relative_validation,
        random_state=RANDOM_STATE,
        stratify=remainder_labels if can_stratify_remainder else None,
    )
    strategy = (
        "stratified split; timestamps unavailable"
        if can_stratify_remainder
        else "stratified split with deterministic small-sample fallback; timestamps unavailable"
    )
    return SplitData(
        tuple(train),
        tuple(validation),
        tuple(test),
        strategy,
    )


def train_from_records(records: Sequence[URLRecord]) -> tuple[URLClassifier, SplitData, EvaluationReport]:
    split = split_dataset(records)
    model = URLClassifier.fit(split.train)
    report = evaluate_model(model, split.test, split.strategy)
    return model, split, report


def evaluate_model(
    model: URLClassifier,
    records: Sequence[URLRecord],
    split_strategy: str,
) -> EvaluationReport:
    if not records:
        raise ValueError("Evaluation requires at least one record")
    actual = [record.label for record in records]
    results = model.predict_many(record.url for record in records)
    predicted = [result.predicted_class for result in results]
    probabilities = [result.phishing_probability for result in results]
    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    false_positive_rate = _false_positive_rate(matrix)
    roc_auc = None if len(set(actual)) < 2 else float(roc_auc_score(actual, probabilities))
    return EvaluationReport(
        precision=float(precision_score(actual, predicted, zero_division=0)),
        recall=float(recall_score(actual, predicted, zero_division=0)),
        f1=float(f1_score(actual, predicted, zero_division=0)),
        roc_auc=roc_auc,
        false_positive_rate=false_positive_rate,
        confusion_matrix=matrix.tolist(),
        split_strategy=split_strategy,
        sample_count=len(records),
    )


def _normalized_texts(records: Sequence[URLRecord]) -> list[str]:
    return [normalize_url(record.url).normalized_url for record in records]


def _positive_class_index(classes: Sequence[int]) -> int:
    for index, label in enumerate(classes):
        if int(label) == 1:
            return index
    raise ValueError("Fitted classifier has no phishing class")


def _false_positive_rate(matrix: object) -> float:
    true_negative, false_positive, _, _ = matrix.ravel()
    denominator = int(true_negative + false_positive)
    return float(false_positive / denominator) if denominator else 0.0


def _parse_timestamp(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid dataset timestamp: {value!r}") from exc
