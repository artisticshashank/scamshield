"""Provider-agnostic URL reputation intelligence.

Reputation lookups disclose the normalized URL to an external service. This
module never sends message text, credentials, or local data to providers.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import json
import os
import time
from typing import Callable, Mapping
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .normalization import normalize_url


class ReputationStatus(str, Enum):
    AVAILABLE = "available"
    NOT_FOUND = "not_found"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    MALFORMED = "malformed"


@dataclass(frozen=True)
class HTTPResponse:
    status_code: int
    body: bytes
    headers: Mapping[str, str]


HTTPClient = Callable[[str, str, Mapping[str, str], bytes | None, float], HTTPResponse]


@dataclass(frozen=True)
class ReputationResult:
    provider: str
    status: ReputationStatus
    queried_url: str
    is_malicious: bool | None
    confidence: float | None = None
    categories: tuple[str, ...] = ()
    source_metadata: dict[str, object] | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self) | {
            "status": self.status.value,
            "categories": list(self.categories),
        }

    def as_signal_score(self) -> float | None:
        if self.status not in {ReputationStatus.AVAILABLE, ReputationStatus.NOT_FOUND}:
            return None
        if self.is_malicious is True:
            return 100.0
        if self.is_malicious is False:
            return 0.0
        return None


@dataclass(frozen=True)
class ReputationAggregate:
    status: ReputationStatus
    queried_url: str
    provider_results: list[ReputationResult]
    is_malicious: bool | None
    matched_providers: list[str]
    categories: list[str]
    unavailable_providers: list[str]
    errors: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "queried_url": self.queried_url,
            "provider_results": [result.to_dict() for result in self.provider_results],
            "is_malicious": self.is_malicious,
            "matched_providers": self.matched_providers,
            "categories": self.categories,
            "unavailable_providers": self.unavailable_providers,
            "errors": self.errors,
        }

    def as_signal_score(self) -> float | None:
        if self.is_malicious is True:
            return 100.0
        if self.is_malicious is False and self.status in {
            ReputationStatus.AVAILABLE,
            ReputationStatus.NOT_FOUND,
        }:
            return 0.0
        return None


class ReputationProvider:
    name = "provider"

    def check(self, url: str) -> ReputationResult:
        raise NotImplementedError


class ReputationCache:
    def __init__(self, ttl_seconds: float = 300.0) -> None:
        if ttl_seconds < 0:
            raise ValueError("Cache TTL cannot be negative")
        self.ttl_seconds = ttl_seconds
        self._entries: dict[tuple[str, str], tuple[float, ReputationResult]] = {}

    def get(self, provider: str, url: str) -> ReputationResult | None:
        entry = self._entries.get((provider, url))
        if entry is None:
            return None
        created, result = entry
        if time.monotonic() - created > self.ttl_seconds:
            del self._entries[(provider, url)]
            return None
        return result

    def put(self, provider: str, url: str, result: ReputationResult) -> None:
        self._entries[(provider, url)] = (time.monotonic(), result)


class HTTPReputationProvider(ReputationProvider):
    def __init__(
        self,
        *,
        timeout_seconds: float = 5.0,
        client: HTTPClient | None = None,
        cache: ReputationCache | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("Timeout must be positive")
        self.timeout_seconds = timeout_seconds
        self.client = client or _default_http_client
        self.cache = cache

    def _cached_check(self, url: str, request: Callable[[str], ReputationResult]) -> ReputationResult:
        normalized_url = normalize_url(url).normalized_url
        if self.cache is not None:
            cached = self.cache.get(self.name, normalized_url)
            if cached is not None:
                return cached
        try:
            result = request(normalized_url)
        except TimeoutError:
            result = ReputationResult(
                self.name, ReputationStatus.UNAVAILABLE, normalized_url, None,
                error="provider timeout",
            )
        except OSError as exc:
            result = ReputationResult(
                self.name, ReputationStatus.UNAVAILABLE, normalized_url, None,
                error=f"provider unavailable: {exc.__class__.__name__}",
            )
        except (ValueError, json.JSONDecodeError) as exc:
            result = ReputationResult(
                self.name, ReputationStatus.MALFORMED, normalized_url, None,
                error=str(exc),
            )
        if self.cache is not None:
            self.cache.put(self.name, normalized_url, result)
        return result


class GoogleSafeBrowsingProvider(HTTPReputationProvider):
    name = "google_safe_browsing"

    def __init__(self, api_key: str | None = None, **kwargs: object) -> None:
        self.api_key = api_key if api_key is not None else os.getenv("SCAMSHIELD_GOOGLE_SAFE_BROWSING_API_KEY")
        super().__init__(**kwargs)

    def check(self, url: str) -> ReputationResult:
        normalized = normalize_url(url).normalized_url
        if not self.api_key:
            return ReputationResult(self.name, ReputationStatus.UNAVAILABLE, normalized, None,
                                    error="API key is not configured")

        def request(_: str) -> ReputationResult:
            endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?" + urlencode({"key": self.api_key})
            payload = json.dumps({
                "client": {"clientId": "scamshield", "clientVersion": "0.1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": normalized}],
                },
            }).encode()
            response = self.client(endpoint, "POST", {"Content-Type": "application/json"}, payload, self.timeout_seconds)
            if response.status_code == 429:
                return ReputationResult(self.name, ReputationStatus.RATE_LIMITED, normalized, None,
                                        error="provider rate limited request")
            if response.status_code >= 400:
                return ReputationResult(self.name, ReputationStatus.FAILED, normalized, None,
                                        error=f"provider HTTP {response.status_code}")
            data = _json_object(response.body)
            matches = data.get("matches", [])
            if not isinstance(matches, list):
                raise ValueError("Safe Browsing matches is not a list")
            categories = tuple(sorted({
                str(match.get("threatType"))
                for match in matches
                if isinstance(match, dict) and match.get("threatType")
            }))
            return ReputationResult(self.name, ReputationStatus.AVAILABLE, normalized, bool(matches),
                                    categories=categories, source_metadata={"match_count": len(matches)})

        return self._cached_check(normalized, request)


class PhishTankProvider(HTTPReputationProvider):
    name = "phishtank"
    endpoint = "https://checkurl.phishtank.com/checkurl/"

    def check(self, url: str) -> ReputationResult:
        normalized = normalize_url(url).normalized_url

        def request(_: str) -> ReputationResult:
            response = self.client(
                self.endpoint,
                "POST",
                {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
                urlencode({"url": normalized, "format": "json"}).encode(),
                self.timeout_seconds,
            )
            if response.status_code == 429:
                return ReputationResult(self.name, ReputationStatus.RATE_LIMITED, normalized, None,
                                        error="provider rate limited request")
            if response.status_code >= 400:
                return ReputationResult(self.name, ReputationStatus.FAILED, normalized, None,
                                        error=f"provider HTTP {response.status_code}")
            data = _json_object(response.body)
            results = data.get("results")
            if not isinstance(results, dict) or "in_database" not in results:
                raise ValueError("PhishTank response missing results.in_database")
            malicious = bool(results["in_database"] and results.get("valid", True))
            return ReputationResult(
                self.name,
                ReputationStatus.AVAILABLE if malicious else ReputationStatus.NOT_FOUND,
                normalized,
                malicious,
                categories=("phishing",) if malicious else (),
                source_metadata={"in_database": bool(results["in_database"])},
            )

        return self._cached_check(normalized, request)


class OpenPhishProvider(HTTPReputationProvider):
    name = "openphish"
    endpoint = "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt"

    def check(self, url: str) -> ReputationResult:
        normalized = normalize_url(url).normalized_url

        def request(_: str) -> ReputationResult:
            response = self.client(self.endpoint, "GET", {}, None, self.timeout_seconds)
            if response.status_code == 429:
                return ReputationResult(self.name, ReputationStatus.RATE_LIMITED, normalized, None,
                                        error="provider rate limited request")
            if response.status_code >= 400:
                return ReputationResult(self.name, ReputationStatus.FAILED, normalized, None,
                                        error=f"provider HTTP {response.status_code}")
            feed = response.body.decode("utf-8")
            entries = {line.strip() for line in feed.splitlines() if line.strip() and not line.startswith("#")}
            malicious = normalized in entries
            return ReputationResult(
                self.name,
                ReputationStatus.AVAILABLE if malicious else ReputationStatus.NOT_FOUND,
                normalized,
                malicious,
                categories=("phishing",) if malicious else (),
            )

        return self._cached_check(normalized, request)


class ReputationAggregator:
    def __init__(self, providers: list[ReputationProvider]) -> None:
        self.providers = tuple(providers)

    def check(self, url: str) -> ReputationAggregate:
        normalized = normalize_url(url).normalized_url
        results = [provider.check(normalized) for provider in self.providers]
        usable = [result for result in results if result.as_signal_score() is not None]
        matches = [result for result in results if result.is_malicious is True]
        errors = {
            result.provider: result.error
            for result in results
            if result.error is not None
        }
        unavailable = [
            result.provider
            for result in results
            if result.as_signal_score() is None
        ]
        if matches:
            aggregate_status = ReputationStatus.AVAILABLE
            malicious: bool | None = True
        elif usable:
            aggregate_status = ReputationStatus.NOT_FOUND
            malicious = False
        elif results:
            aggregate_status = ReputationStatus.UNAVAILABLE
            malicious = None
        else:
            aggregate_status = ReputationStatus.UNAVAILABLE
            malicious = None
        return ReputationAggregate(
            aggregate_status,
            normalized,
            results,
            malicious,
            [result.provider for result in matches],
            sorted({category for result in results for category in result.categories}),
            unavailable,
            errors,
        )


def _default_http_client(
    url: str,
    method: str,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout: float,
) -> HTTPResponse:
    request = Request(url, data=body, headers=dict(headers), method=method)
    with urlopen(request, timeout=timeout) as response:
        return HTTPResponse(response.status, response.read(), dict(response.headers.items()))


def _json_object(body: bytes) -> dict[str, object]:
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Provider response is not a JSON object")
    return data
