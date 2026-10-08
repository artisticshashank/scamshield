"""Unified orchestration for URL and message scans."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence
from uuid import uuid4

from .domain_intelligence import (
    DNSCollector,
    RegistrationCollector,
    TLSCollector,
    collect_domain_intelligence,
)
from .message_scanning import (
    ExtractionLimits,
    MessageScanError,
    MessageScanResult,
    extract_urls,
    select_highest_result,
)
from .ml_classifier import URLClassifier
from .reputation import ReputationAggregate, ReputationProvider, ReputationStatus
from .redirect_analysis import RedirectResolver, RedirectResult
from .risk_fusion import (
    ScanResult,
    SignalResult,
    SignalStatus,
    build_scan_result,
)
from .normalization import URLNormalizationError


@dataclass(frozen=True)
class ServiceLimits:
    max_input_length: int = 100_000
    overall_timeout_seconds: float = 15.0
    extraction: ExtractionLimits = ExtractionLimits()


class ScanInputError(ValueError):
    """Raised for invalid or unsupported scan input."""


class MLClassifierService:
    """Loads an existing classifier artifact; never trains during inference."""

    def __init__(self, artifact_path: str | Path | None = None) -> None:
        self.artifact_path = Path(artifact_path) if artifact_path else None
        self.classifier: URLClassifier | None = None
        self.status = SignalStatus.UNAVAILABLE
        self.error: str | None = None

    def load(self) -> None:
        if self.artifact_path is None:
            self.status = SignalStatus.UNAVAILABLE
            self.error = "ML model artifact is not configured"
            return
        if not self.artifact_path.is_file():
            self.status = SignalStatus.UNAVAILABLE
            self.error = "ML model artifact is unavailable"
            return
        try:
            self.classifier = URLClassifier.load(self.artifact_path)
            self.status = SignalStatus.AVAILABLE
            self.error = None
        except (OSError, ValueError, TypeError) as exc:
            self.status = SignalStatus.FAILED
            self.error = f"ML model load failed: {exc.__class__.__name__}"


class ScanService:
    """Coordinates existing detection components without duplicating their logic."""

    def __init__(
        self,
        *,
        classifier_service: MLClassifierService | None = None,
        reputation_providers: Sequence[ReputationProvider] = (),
        domain_collector: Callable[[object], object] | None = None,
        redirect_resolver: RedirectResolver | None = None,
        limits: ServiceLimits = ServiceLimits(),
    ) -> None:
        self.classifier_service = classifier_service or MLClassifierService()
        self.classifier_service.load()
        self.reputation_providers = tuple(reputation_providers)
        self.domain_collector = domain_collector or collect_domain_intelligence
        self.redirect_resolver = redirect_resolver or RedirectResolver()
        self.limits = limits

    def scan(self, input_value: str, input_type: str = "auto") -> ScanResult | MessageScanResult:
        self._validate_input(input_value, input_type)
        detected_type = self._detect_input_type(input_value, input_type)
        if detected_type == "message":
            return self._scan_message(input_value)
        return self._scan_url(input_value)

    def health(self) -> dict[str, object]:
        return {
            "status": "ok",
            "version": "1.0.0",
            "components": {
                "normalization": "available",
                "rules": "available",
                "ml": self.classifier_service.status.value,
                "shap": "unavailable",
                "reputation": "available" if self.reputation_providers else "not_configured",
                "domain_intelligence": "available",
                "redirect_analysis": "available",
            },
        }

    def _scan_url(self, value: str) -> ScanResult:
        from .normalization import normalize_url

        try:
            normalized = normalize_url(value)
        except URLNormalizationError as exc:
            raise ScanInputError(str(exc)) from exc
        reputation = self._reputation_signal(normalized.normalized_url)
        domain = self._domain_signal(normalized)
        redirect = self._redirect_signal(normalized.normalized_url)
        return build_scan_result(
            value,
            classifier=self.classifier_service.classifier,
            reputation=reputation,
            domain_intelligence=domain,
            redirect=redirect,
            input_type="url",
            scan_id=str(uuid4()),
        )

    def _scan_message(self, message: str) -> MessageScanResult:
        try:
            urls = extract_urls(message, limits=self.limits.extraction)
        except MessageScanError as exc:
            raise ScanInputError(str(exc)) from exc
        results = [self._scan_url(url) for url in urls]
        if not results:
            return MessageScanResult(
                input_type="message",
                original_message=message,
                extracted_urls=[],
                scan_results=[],
                overall_verdict="NO_URL",
                overall_risk_score=None,
                recommendation="No HTTP or HTTPS URL was detected in this message.",
                metadata={"aggregation_strategy": "maximum URL risk score", "url_count": 0},
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
            },
        )

    def _reputation_signal(self, url: str) -> SignalResult:
        if not self.reputation_providers:
            return SignalResult(SignalStatus.UNAVAILABLE, error="No reputation providers configured")
        try:
            results = [provider.check(url) for provider in self.reputation_providers]
            malicious = any(result.is_malicious is True for result in results)
            usable = any(result.as_signal_score() is not None for result in results)
            status = SignalStatus.AVAILABLE if usable else SignalStatus.FAILED
            score = 100.0 if malicious else (0.0 if usable else None)
            return SignalResult(
                status,
                {"provider_results": [result.to_dict() for result in results]},
                score,
                None if usable else "No reputation provider returned a usable result",
            )
        except Exception as exc:
            return SignalResult(SignalStatus.FAILED, error=f"Reputation failed: {exc.__class__.__name__}")

    def _domain_signal(self, normalized: object) -> SignalResult:
        try:
            result = self.domain_collector(normalized)
            status = SignalStatus.AVAILABLE if getattr(result, "risk_score", None) is not None else (
                SignalStatus.FAILED if getattr(result, "status", "") == "failed" else SignalStatus.UNAVAILABLE
            )
            return SignalResult(status, result.to_dict(), result.risk_score, None)
        except Exception as exc:
            return SignalResult(SignalStatus.FAILED, error=f"Domain intelligence failed: {exc.__class__.__name__}")

    def _redirect_signal(self, url: str) -> SignalResult:
        try:
            result = self.redirect_resolver.resolve(url)
            status = SignalStatus.AVAILABLE if result.risk_score is not None and result.status not in {"failed", "timeout"} else (
                SignalStatus.FAILED if result.status in {"failed", "timeout", "blocked"} else SignalStatus.UNAVAILABLE
            )
            return SignalResult(status, result.to_dict(), result.risk_score, None)
        except Exception as exc:
            return SignalResult(SignalStatus.FAILED, error=f"Redirect analysis failed: {exc.__class__.__name__}")

    def _validate_input(self, value: str, input_type: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ScanInputError("input must be a non-empty string")
        if len(value) > self.limits.max_input_length:
            raise ScanInputError("input exceeds the maximum allowed length")
        if input_type not in {"auto", "url", "message"}:
            raise ScanInputError("input_type must be one of: auto, url, message")

    @staticmethod
    def _detect_input_type(value: str, input_type: str) -> str:
        if input_type != "auto":
            return input_type
        return "url" if value.strip().lower().startswith(("http://", "https://")) else "message"
