import json

import pytest

from core.reputation import (
    GoogleSafeBrowsingProvider,
    HTTPResponse,
    OpenPhishProvider,
    PhishTankProvider,
    ReputationAggregate,
    ReputationAggregator,
    ReputationCache,
    ReputationStatus,
)
from core.risk_fusion import SignalStatus, fuse_signals, ml_score
from core.ml_classifier import MLResult


def response(payload: object, status: int = 200) -> HTTPResponse:
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return HTTPResponse(status, body, {})


def test_google_malicious_result_is_normalized_without_confidence() -> None:
    calls: list[tuple] = []

    def client(*args: object) -> HTTPResponse:
        calls.append(args)
        return response({"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})

    result = GoogleSafeBrowsingProvider(api_key="secret", client=client).check(
        " HTTPS://Example.COM/login "
    )

    assert result.status == ReputationStatus.AVAILABLE
    assert result.is_malicious is True
    assert result.confidence is None
    assert result.queried_url == "https://example.com/login"
    assert calls[0][0].endswith("key=secret")
    assert "secret" not in str(result.to_dict())


def test_google_clean_and_missing_key() -> None:
    clean = GoogleSafeBrowsingProvider(
        api_key="key", client=lambda *args: response({})
    ).check("https://example.com")
    missing = GoogleSafeBrowsingProvider(api_key="", client=lambda *args: response({})).check(
        "https://example.com"
    )

    assert clean.is_malicious is False
    assert clean.status == ReputationStatus.AVAILABLE
    assert missing.status == ReputationStatus.UNAVAILABLE
    assert "key" not in str(missing.to_dict()).replace("API key", "")


@pytest.mark.parametrize("status", [429, 500])
def test_google_http_failures_are_not_safe(status: int) -> None:
    result = GoogleSafeBrowsingProvider(
        api_key="key", client=lambda *args: response({}, status)
    ).check("https://example.com")

    assert result.is_malicious is None
    assert result.status in {ReputationStatus.RATE_LIMITED, ReputationStatus.FAILED}


def test_phishtank_malicious_and_openphish_clean() -> None:
    phish = PhishTankProvider(
        client=lambda *args: response({"results": {"in_database": True, "valid": True}})
    ).check("https://bad.example/login")
    clean = OpenPhishProvider(
        client=lambda *args: response(b"https://other.example/\n")
    ).check("https://safe.example")

    assert phish.is_malicious is True
    assert clean.status == ReputationStatus.NOT_FOUND
    assert clean.is_malicious is False


def test_malformed_provider_response_is_explicit() -> None:
    result = PhishTankProvider(client=lambda *args: response({"wrong": True})).check(
        "https://example.com"
    )

    assert result.status == ReputationStatus.MALFORMED
    assert result.is_malicious is None


def test_timeout_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*args: object) -> HTTPResponse:
        raise TimeoutError

    result = OpenPhishProvider(client=timeout).check("https://example.com")

    assert result.status == ReputationStatus.UNAVAILABLE
    assert result.is_malicious is None


def test_aggregator_preserves_agreement_disagreement_and_errors() -> None:
    class Stub:
        def __init__(self, name: str, result: object) -> None:
            self.name = name
            self.result = result

        def check(self, url: str) -> object:
            return self.result

    malicious = GoogleSafeBrowsingProvider(api_key="x", client=lambda *args: response({"matches": [{}]})).check(
        "https://bad.example"
    )
    clean = OpenPhishProvider(client=lambda *args: response(b"")).check("https://bad.example")
    aggregate = ReputationAggregator([Stub("g", malicious), Stub("o", clean)]).check(
        "https://bad.example"
    )

    assert aggregate.is_malicious is True
    assert aggregate.matched_providers == ["google_safe_browsing"]
    assert len(aggregate.provider_results) == 2
    assert aggregate.to_dict()["queried_url"] == "https://bad.example/"


def test_all_providers_unavailable_do_not_become_safe() -> None:
    class Failed:
        def __init__(self, name: str) -> None:
            self.name = name

        def check(self, url: str):
            from core.reputation import ReputationResult
            return ReputationResult(self.name, ReputationStatus.UNAVAILABLE, url, None, error="offline")

    aggregate = ReputationAggregator([Failed("one"), Failed("two")]).check("https://example.com")

    assert aggregate.is_malicious is None
    assert aggregate.as_signal_score() is None
    assert aggregate.status == ReputationStatus.UNAVAILABLE


def test_cache_deduplicates_normalized_url() -> None:
    calls = 0

    def client(*args: object) -> HTTPResponse:
        nonlocal calls
        calls += 1
        return response({})

    provider = GoogleSafeBrowsingProvider(api_key="key", client=client, cache=ReputationCache())
    provider.check("HTTPS://EXAMPLE.COM/")
    provider.check(" https://example.com ")

    assert calls == 1


def test_valid_reputation_enters_fusion_but_unavailable_does_not() -> None:
    ml = MLResult("model", "1", 0.2, 0, 0.8, 1, {})
    clean = OpenPhishProvider(client=lambda *args: response(b"")).check("https://example.com")
    unavailable = GoogleSafeBrowsingProvider(api_key="", client=lambda *args: response({})).check(
        "https://example.com"
    )
    from core.risk_fusion import SignalResult

    with_rep = fuse_signals(
        ml_result=ml,
        reputation=SignalResult(SignalStatus.AVAILABLE, clean.to_dict(), clean.as_signal_score()),
    )
    without_rep = fuse_signals(
        ml_result=ml,
        reputation=SignalResult(SignalStatus.UNAVAILABLE, unavailable.to_dict()),
    )

    assert with_rep.score_breakdown.reputation_score == 0
    assert without_rep.score_breakdown.reputation_score is None
    assert "reputation" in without_rep.score_breakdown.unavailable_signals
