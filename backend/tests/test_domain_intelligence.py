import json
from datetime import datetime, timedelta, timezone
import socket
import ssl

import pytest

from core.domain_intelligence import (
    CollectorStatus,
    DNSCollector,
    RegistrationCollector,
    TLSCollector,
    collect_domain_intelligence,
)
from core.risk_fusion import SignalResult, SignalStatus, fuse_signals


def test_dns_collects_records_and_private_ip_evidence() -> None:
    def query(host: str, record_type: str, timeout: float) -> list[str]:
        return {
            "A": ["192.168.1.2", "203.0.113.1"],
            "AAAA": ["::1"],
            "MX": ["10 mail.example.com."],
            "NS": ["ns1.example.com."],
            "CNAME": [],
        }[record_type]

    result = DNSCollector(query=query).collect("example.com")

    assert result.status == CollectorStatus.AVAILABLE
    assert result.value["resolved_ip_count"] == 3
    assert "192.168.1.2" in result.value["private_or_special_ips"]
    assert "::1" in result.value["private_or_special_ips"]


def test_dns_timeout_and_malformed_response_are_explicit() -> None:
    def timeout(*args: object) -> list[str]:
        raise TimeoutError

    result = DNSCollector(query=timeout).collect("example.com")

    assert result.status == CollectorStatus.UNAVAILABLE
    assert result.error


def test_dns_never_connects_to_resolved_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    result = DNSCollector(query=lambda *args: ["169.254.169.254"]).collect("metadata.example")

    assert result.value["private_or_special_ips"] == ["169.254.169.254"]


def test_registration_calculates_actual_age_from_rdap_date() -> None:
    created = (datetime.now(timezone.utc) - timedelta(days=12)).isoformat().replace("+00:00", "Z")

    def client(host: str, timeout: float) -> tuple[int, bytes]:
        return 200, json.dumps({
            "events": [{"eventAction": "registration", "eventDate": created}],
            "entities": [],
        }).encode()

    result = RegistrationCollector(client=client).collect("example.com")

    assert result.status == CollectorStatus.AVAILABLE
    assert result.value["domain_age_days"] in {11, 12}
    assert result.derived_signals[0]["triggered"] is True


def test_registration_missing_malformed_and_timeout() -> None:
    missing = RegistrationCollector(client=lambda *args: (200, b'{"events": []}')).collect("example.com")
    malformed = RegistrationCollector(client=lambda *args: (200, b"[]")).collect("example.com")
    timeout = RegistrationCollector(client=lambda *args: (_ for _ in ()).throw(TimeoutError())).collect("example.com")

    assert missing.status == CollectorStatus.UNAVAILABLE
    assert malformed.status == CollectorStatus.FAILED
    assert timeout.status == CollectorStatus.UNAVAILABLE


def test_tls_http_is_not_applicable() -> None:
    result = TLSCollector(client=lambda *args: {}).collect("http://example.com")

    assert result.status == CollectorStatus.NOT_APPLICABLE


def test_tls_valid_metadata_and_expired_signal() -> None:
    expired = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%b %d %H:%M:%S %Y GMT")
    valid_from = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%b %d %H:%M:%S %Y GMT")
    result = TLSCollector(client=lambda *args: {
        "subject": "subject",
        "issuer": "issuer",
        "san": ["example.com"],
        "notBefore": valid_from,
        "notAfter": expired,
    }).collect("https://example.com")

    assert result.status == CollectorStatus.AVAILABLE
    assert result.value["hostname_verified"] is True
    assert result.derived_signals[0]["triggered"] is True


def test_tls_hostname_mismatch_and_timeout() -> None:
    mismatch = TLSCollector(client=lambda *args: (_ for _ in ()).throw(
        ssl.CertificateError("hostname mismatch")
    )).collect("https://example.com")
    timeout = TLSCollector(client=lambda *args: (_ for _ in ()).throw(TimeoutError())).collect(
        "https://example.com"
    )

    assert mismatch.status == CollectorStatus.FAILED
    assert timeout.status == CollectorStatus.UNAVAILABLE


@pytest.mark.parametrize(
    "resolved_ip",
    [
        "localhost",
        "127.0.0.1",
        "::1",
        "10.0.0.8",
        "fc00::8",
        "fe80::8",
        "169.254.169.254",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.8",
    ],
)
def test_tls_blocks_unsafe_resolution_without_connecting(
    monkeypatch: pytest.MonkeyPatch, resolved_ip: str
) -> None:
    monkeypatch.setattr(
        "core.domain_intelligence._resolve_ips",
        lambda hostname: [resolved_ip] if resolved_ip != "localhost" else ["127.0.0.1"],
    )
    attempts: list[object] = []
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *args, **kwargs: attempts.append(args) or pytest.fail("unsafe TLS connection attempted"),
    )

    result = TLSCollector().collect("https://example.com")

    assert result.status == CollectorStatus.FAILED
    assert attempts == []


def test_tls_blocks_resolution_when_any_address_is_unsafe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.domain_intelligence._resolve_ips",
        lambda hostname: ["93.184.216.34", "192.168.1.5"],
    )
    attempts: list[object] = []
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: attempts.append(args))

    result = TLSCollector().collect("https://example.com")

    assert result.status == CollectorStatus.FAILED
    assert attempts == []


def test_tls_connects_to_validated_public_ip_and_preserves_sni(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.domain_intelligence._resolve_ips",
        lambda hostname: ["93.184.216.34", "93.184.216.35"],
    )
    connections: list[object] = []

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def getpeercert(self) -> dict[str, object]:
            return {}

    def connect(address: object, timeout: float) -> FakeSocket:
        connections.append((address, timeout))
        return FakeSocket()

    class FakeContext:
        def wrap_socket(self, raw: FakeSocket, server_hostname: str) -> FakeSocket:
            connections.append(("sni", server_hostname))
            return raw

    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(ssl, "create_default_context", lambda: FakeContext())

    result = TLSCollector().collect("https://example.com")

    assert result.status == CollectorStatus.AVAILABLE
    assert connections[0][0] == ("93.184.216.34", 443)
    assert connections[1] == ("sni", "example.com")


def test_tls_dns_failure_and_timeout_are_explicit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.domain_intelligence._resolve_ips",
        lambda hostname: (_ for _ in ()).throw(socket.gaierror("DNS failure")),
    )
    failed = TLSCollector().collect("https://example.com")
    assert failed.status == CollectorStatus.FAILED

    monkeypatch.setattr(
        "core.domain_intelligence._resolve_ips",
        lambda hostname: ["93.184.216.34"],
    )
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(socket.timeout()),
    )
    timeout = TLSCollector().collect("https://example.com")
    assert timeout.status == CollectorStatus.UNAVAILABLE


def test_tls_malformed_resolution_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "core.domain_intelligence._resolve_ips",
        lambda hostname: (_ for _ in ()).throw(IndexError("malformed getaddrinfo result")),
    )
    attempts: list[object] = []
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: attempts.append(args))

    result = TLSCollector().collect("https://example.com")

    assert result.status == CollectorStatus.FAILED
    assert attempts == []


def test_complete_domain_result_partial_and_all_unavailable() -> None:
    dns = DNSCollector(query=lambda *args: [])
    registration = RegistrationCollector(client=lambda *args: (404, b""))
    tls = TLSCollector(client=lambda *args: {})
    result = collect_domain_intelligence(
        "https://example.com", dns=dns, registration=registration, tls=tls
    )

    assert result.hostname == "example.com"
    assert result.status == CollectorStatus.AVAILABLE
    json.dumps(result.to_dict())

    failed = collect_domain_intelligence(
        "https://example.com",
        dns=DNSCollector(query=lambda *args: (_ for _ in ()).throw(TimeoutError())),
        registration=RegistrationCollector(client=lambda *args: (_ for _ in ()).throw(TimeoutError())),
        tls=TLSCollector(client=lambda *args: (_ for _ in ()).throw(TimeoutError())),
    )
    assert failed.status == CollectorStatus.UNAVAILABLE
    assert failed.risk_score is None


def test_domain_score_enters_fusion_only_when_available() -> None:
    available = SignalResult(SignalStatus.AVAILABLE, {"dns": "observed"}, 25)
    unavailable = SignalResult(SignalStatus.UNAVAILABLE, {"dns": "timeout"})

    with_domain = fuse_signals(domain_intelligence=available)
    without_domain = fuse_signals(domain_intelligence=unavailable)

    assert with_domain.score_breakdown.domain_intelligence_score == 25
    assert without_domain.score_breakdown.domain_intelligence_score is None
    assert "domain_intelligence" in without_domain.score_breakdown.unavailable_signals
