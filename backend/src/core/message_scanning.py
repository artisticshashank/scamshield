"""Message URL extraction and independent multi-URL scanning."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Callable

from .ml_classifier import URLClassifier
from .risk_fusion import ScanResult, build_scan_result


@dataclass(frozen=True)
class ExtractionLimits:
    max_message_length: int = 100_000
    max_urls: int = 100
    max_url_length: int = 4_096


DEFAULT_LIMITS = ExtractionLimits()
_URL_PATTERN = re.compile(r"https?://[^\s<>'\"`]+", re.IGNORECASE)
_TRAILING_PUNCTUATION = ".,!?;:"
_CLOSING_PAIRS = {")": "(", "]": "[", "}": "{"}


class MessageScanError(ValueError):
    """Raised when message scanning input exceeds configured safety limits."""


def select_highest_result(results: list[ScanResult]) -> ScanResult:
    """Select the highest-risk result, breaking equal scores by severity."""

    severity = {"SAFE": 0, "SUSPICIOUS": 1, "DANGEROUS": 2}
    return max(
        results,
        key=lambda result: (result.risk_score, severity.get(result.verdict.upper(), -1)),
    )


def extract_urls(
    message: str,
    *,
    limits: ExtractionLimits = DEFAULT_LIMITS,
) -> list[str]:
    """Extract HTTP(S) URLs without normalization or network access."""

    if not isinstance(message, str):
        raise MessageScanError("Message must be a string")
    if len(message) > limits.max_message_length:
        raise MessageScanError("Message exceeds the maximum allowed length")
    if limits.max_urls < 1 or limits.max_url_length < 1:
        raise MessageScanError("Extraction limits must be positive")

    extracted: list[str] = []
    seen: set[str] = set()
    for match in _URL_PATTERN.finditer(message):
        candidate = _trim_url(match.group(0))
        if not candidate or len(candidate) > limits.max_url_length:
            continue
        if candidate not in seen:
            seen.add(candidate)
            extracted.append(candidate)
        if len(extracted) > limits.max_urls:
            raise MessageScanError("Message contains more URLs than allowed")
    return extracted


@dataclass(frozen=True)
class MessageScanResult:
    """Stable message-level contract over independently scanned URLs."""

    input_type: str
    original_message: str
    extracted_urls: list[str]
    scan_results: list[ScanResult]
    overall_verdict: str
    overall_risk_score: float | None
    recommendation: str
    metadata: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["scan_results"] = [scan.to_dict() for scan in self.scan_results]
        return result


def scan_url(
    url: str,
    *,
    classifier: URLClassifier | None = None,
    **scan_options: object,
) -> ScanResult:
    """Scan one URL through the same shared pipeline used by messages."""

    return build_scan_result(
        url,
        classifier=classifier,
        input_type="url",
        **scan_options,
    )


def scan_message(
    message: str,
    *,
    classifier: URLClassifier | None = None,
    limits: ExtractionLimits = DEFAULT_LIMITS,
    scan_options: dict[str, object] | None = None,
) -> MessageScanResult:
    """Extract and scan each URL independently; never fetches any URL."""

    urls = extract_urls(message, limits=limits)
    options = scan_options or {}
    results = [
        build_scan_result(
            url,
            classifier=classifier,
            input_type="url",
            **options,
        )
        for url in urls
    ]
    if not results:
        return MessageScanResult(
            input_type="message",
            original_message=message,
            extracted_urls=[],
            scan_results=[],
            overall_verdict="no_url_detected",
            overall_risk_score=None,
            recommendation="No HTTP or HTTPS URL was detected in this message.",
            metadata={
                "aggregation_strategy": "maximum URL risk score",
                "url_count": 0,
                "limits": asdict(limits),
            },
        )

    highest = select_highest_result(results)
    return MessageScanResult(
        input_type="message",
        original_message=message,
        extracted_urls=urls,
        scan_results=results,
        overall_verdict=highest.verdict,
        overall_risk_score=highest.risk_score,
        recommendation=highest.recommendation,
        metadata={
            "aggregation_strategy": "maximum URL risk score",
            "aggregation_strategy_validated": False,
            "url_count": len(urls),
            "limits": asdict(limits),
        },
    )


def _trim_url(value: str) -> str:
    candidate = value
    while candidate and candidate[-1] in _TRAILING_PUNCTUATION:
        candidate = candidate[:-1]
    while candidate and candidate[-1] in _CLOSING_PAIRS:
        opener = _CLOSING_PAIRS[candidate[-1]]
        if candidate.count(candidate[-1]) > candidate.count(opener):
            candidate = candidate[:-1]
        else:
            break
    return candidate
