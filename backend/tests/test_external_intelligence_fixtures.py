"""Deterministic offline coverage for reputation, domain, and redirects."""

from __future__ import annotations

import json
import ssl
from datetime import datetime, timedelta, timezone

import pytest

from core.domain_intelligence import (
    CollectorStatus,
    DNSCollector,
    RegistrationCollector,
    TLSCollector,
    collect_domain_intelligence,
)
from core.ml_classifier import MLResult
from core.redirect_analysis import RedirectLimits, RedirectResponse, RedirectResolver
from core.reputation import (
    GoogleSafeBrowsingProvider,
    OpenPhishProvider,
    PhishTankProvider,
    ReputationAggregate,
    ReputationAggregator,
    ReputationResult,
    ReputationStatus,
)
from core.risk_fusion import (
    SignalResult,
    SignalStatus,
    build_scan_result,
    fuse_signals,
)
from fixtures.external_intelligence import (
    REPUTATION_CASES,
    REPUTATION_URL,
)


def test_reputation_provider_fixture_inventory_is_normalized() -> None:
    google_bad = GoogleSafeBrowsingProvider(
        api_key="fixture", client=lambda *args: REPUTATION_CASES["google_confirmed_malicious"]
    ).check(REPUTATION_URL)
    google_clean = GoogleSafeBrowsingProvider(
        api_key="fixture", client=lambda *args: REPUTATION_CASES["google_confirmed_clean"]
    ).check(REPUTATION_URL)
    phish_bad = PhishTankProvider(
        client=lambda *args: REPUTATION_CASES["phishtank_confirmed_malicious"]
    ).check(REPUTATION_URL)
    phish_clean = PhishTankProvider(
        client=lambda *args: REPUTATION_CASES["phishtank_confirmed_clean"]
    ).check(REPUTATION_URL)
    open_bad = OpenPhishProvider(
        client=lambda *args: REPUTATION_CASES["openphish_confirmed_malicious"]
    ).check(REPUTATION_URL)
    open_clean = OpenPhishProvider(
        client=lambda *args: REPUTATION_CASES["openphish_confirmed_clean"]
    ).check(REPUTATION_URL)

    assert all(result.status == ReputationStatus.AVAILABLE for result in (google_bad, phish_bad, open_bad))
    assert google_bad.is_malicious is True
    assert phish_bad.is_malicious is True
    assert open_bad.is_malicious is True
    assert phish_clean.status == ReputationStatus.NOT_FOUND
    assert open_clean.status == ReputationStatus.NOT_FOUND
    assert google_clean.is_malicious is False
    assert json.dumps(google_bad.to_dict())


def test_reputation_disagreement_unavailable_timeout_and_malformed_are_explicit() -> None:
    class Stub:
        def __init__(self, name: str, result: ReputationResult) -> None:
            self.name = name
            self.result = result

        def check(self, url: str) -> ReputationResult:
            return self.result

    malicious = ReputationResult("fixture_bad", ReputationStatus.AVAILABLE, REPUTATION_URL, True)
    clean = ReputationResult("fixture_clean", ReputationStatus.NOT_FOUND, REPUTATION_URL, False)
    disagreement = ReputationAggregator([Stub("bad", malicious), Stub("clean", clean)]).check(
        REPUTATION_URL
    )
    unavailable = ReputationResult(
        "offline", ReputationStatus.UNAVAILABLE, REPUTATION_URL, None, error="offline"
    )
    timeout = OpenPhishProvider(
        client=lambda *args: (_ for _ in ()).throw(TimeoutError())
    ).check(REPUTATION_URL)
    malformed = PhishTankProvider(
        client=lambda *args: REPUTATION_CASES["malformed"]
    ).check(REPUTATION_URL)
    failed = GoogleSafeBrowsingProvider(
        api_key="fixture", client=lambda *args: REPUTATION_CASES["provider_error"]
    ).check(REPUTATION_URL)

    assert disagreement.is_malicious is True
    assert disagreement.matched_providers == ["fixture_bad"]
    assert unavailable.as_signal_score() is None
    assert timeout.status == ReputationStatus.UNAVAILABLE
    assert malformed.status == ReputationStatus.MALFORMED
    assert failed.status == ReputationStatus.FAILED


def test_reputation_fixture_signals_enter_fusion_only_when_usable() -> None:
    ml = MLResult("model", "1", 0.2, 0, 0.8, 1, {})
    clean = SignalResult(SignalStatus.AVAILABLE, {"fixture": "clean"}, 0)
    unavailable = SignalResult(SignalStatus.UNAVAILABLE, {"fixture": "offline"})
    failed = SignalResult(SignalStatus.FAILED, error="fixture failure")

    with_clean = fuse_signals(ml_result=ml, reputation=clean)
    without_unavailable = fuse_signals(ml_result=ml, reputation=unavailable)
    without_failed = fuse_signals(ml_result=ml, reputation=failed)

    assert with_clean.score_breakdown.reputation_score == 0
    assert without_unavailable.score_breakdown.reputation_score is None
    assert without_failed.score_breakdown.reputation_score is None
    assert "reputation" in without_failed.score_breakdown.unavailable_signals


def test_domain_fixtures_cover_dns_private_ip_rdap_and_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    def dns_query(host: str, record_type: str, timeout: float) -> list[str]:
        return {
            "A": ["203.0.113.10", "169.254.169.254"],
            "AAAA": ["2001:db8::10"],
            "MX": ["10 mail.fixture.example."],
            "NS": ["ns.fixture.example."],
            "CNAME": [],
        }[record_type]

    created = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat().replace("+00:00", "Z")
    rdap = lambda *args: (
        200,
        json.dumps({"events": [{"eventAction": "registration", "eventDate": created}]}).encode(),
    )
    expired = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
        "%b %d %H:%M:%S %Y GMT"
    )
    tls = lambda *args: {
        "subject": "fixture",
        "issuer": "fixture-ca",
        "san": ["fixture.example"],
        "notBefore": expired,
        "notAfter": expired,
    }

    monkeypatch.setattr("socket.create_connection", lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("fixture DNS/domain collection must not connect")
    ))
    result = collect_domain_intelligence(
        "https://fixture.example",
        dns=DNSCollector(query=dns_query),
        registration=RegistrationCollector(client=rdap),
        tls=TLSCollector(client=tls),
    )

    assert result.status == CollectorStatus.AVAILABLE
    assert result.dns_result.value["resolved_ip_count"] == 3
    assert result.dns_result.value["private_or_special_ips"] == [
        "169.254.169.254",
        "2001:db8::10",
        "203.0.113.10",
    ]
    assert result.registration_result.value["domain_age_days"] in {6, 7}
    assert result.tls_result.value["days_until_expiry"] < 0
    assert result.risk_score is not None


@pytest.mark.parametrize(
    ("collector", "expected"),
    [
        (
            DNSCollector(query=lambda *args: (_ for _ in ()).throw(TimeoutError())).collect,
            CollectorStatus.UNAVAILABLE,
        ),
        (
            RegistrationCollector(client=lambda *args: (_ for _ in ()).throw(TimeoutError())).collect,
            CollectorStatus.UNAVAILABLE,
        ),
        (
            TLSCollector(client=lambda *args: (_ for _ in ()).throw(TimeoutError())).collect,
            CollectorStatus.UNAVAILABLE,
        ),
    ],
)
def test_domain_timeout_fixtures_are_unavailable(collector, expected: str) -> None:
    value = "https://fixture.example" if isinstance(collector.__self__, TLSCollector) else "fixture.example"
    assert collector(value).status == expected


def test_domain_tls_hostname_mismatch_and_malformed_rdap_are_failed() -> None:
    mismatch = TLSCollector(
        client=lambda *args: (_ for _ in ()).throw(ssl.CertificateError("hostname mismatch"))
    ).collect("https://fixture.example")
    malformed = RegistrationCollector(client=lambda *args: (200, b"[]")).collect(
        "fixture.example"
    )

    assert mismatch.status == CollectorStatus.FAILED
    assert mismatch.value["hostname_verified"] is False
    assert malformed.status == CollectorStatus.FAILED


def _redirect_resolver(routes, *, ips=None, limits=None, calls=None):
    def resolve(host: str) -> list[str]:
        return (ips or {}).get(host, ["93.184.216.34"])

    def request(url: str, ip: str, port: int, timeout: float, max_headers: int):
        if calls is not None:
            calls.append((url, ip))
        return routes.get(url, RedirectResponse(200, {}))

    return RedirectResolver(
        resolve_ips=resolve,
        request=request,
        limits=limits or RedirectLimits(),
    )


def test_redirect_fixture_inventory_covers_chains_loop_hop_and_malformed_location() -> None:
    one = _redirect_resolver(
        {"https://fixture.example/start": RedirectResponse(302, {"Location": "/final"})}
    ).resolve("https://fixture.example/start")
    multiple = _redirect_resolver(
        {
            "https://fixture.example/0": RedirectResponse(302, {"Location": "/1"}),
            "https://fixture.example/1": RedirectResponse(302, {"Location": "/2"}),
        }
    ).resolve("https://fixture.example/0")
    loop = _redirect_resolver(
        {
            "https://fixture.example/a": RedirectResponse(302, {"Location": "/b"}),
            "https://fixture.example/b": RedirectResponse(302, {"Location": "/a"}),
        }
    ).resolve("https://fixture.example/a")
    limited = _redirect_resolver(
        {
            f"https://fixture.example/{i}": RedirectResponse(302, {"Location": f"/{i + 1}"})
            for i in range(4)
        },
        limits=RedirectLimits(max_hops=2, max_chain_entries=2),
    ).resolve("https://fixture.example/0")
    malformed = _redirect_resolver(
        {"https://fixture.example/": RedirectResponse(302, {"Location": "javascript:bad"})}
    ).resolve("https://fixture.example/")

    assert one.status == "completed"
    assert multiple.hop_count == 3
    assert loop.status == "loop"
    assert limited.status == "hop_limit"
    assert malformed.status == "failed"


def test_redirect_fixture_ssrf_cases_never_call_request() -> None:
    calls: list[tuple] = []
    private = _redirect_resolver(
        {}, ips={"fixture.example": ["127.0.0.1"]}, calls=calls
    ).resolve("https://fixture.example/")
    metadata = _redirect_resolver(
        {}, ips={"fixture.example": ["169.254.169.254"]}, calls=calls
    ).resolve("https://fixture.example/")
    rebinding = _redirect_resolver(
        {}, ips={"fixture.example": ["93.184.216.34", "192.168.1.10"]}, calls=calls
    ).resolve("https://fixture.example/")

    assert private.status == "blocked"
    assert metadata.status == "blocked"
    assert rebinding.status == "blocked"
    assert calls == []


def test_redirect_timeout_fixture_and_signal_integration() -> None:
    timeout = _redirect_resolver(
        {},
        calls=[],
    )
    timeout.request = lambda *args: (_ for _ in ()).throw(TimeoutError())
    result = timeout.resolve("https://fixture.example/")
    signal = SignalResult(SignalStatus.AVAILABLE, result.to_dict(), result.risk_score)
    fused = fuse_signals(redirect=signal)

    assert result.status == "timeout"
    assert result.risk_score is not None
    assert fused.score_breakdown.redirect_score == result.risk_score


def test_evidence_aware_and_shap_remain_unchanged_in_fixture_integration() -> None:
    result = build_scan_result("https://fixture.example/")

    assert result.score_breakdown.ml_score is None
    assert result.shap_result.status == SignalStatus.UNAVAILABLE
    assert result.shap_result.score is None
    assert "shap" not in result.score_breakdown.weighted_contributions
