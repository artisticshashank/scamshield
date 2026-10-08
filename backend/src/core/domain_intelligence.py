"""Independent DNS, RDAP registration, and TLS intelligence collectors."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
import json
import socket
import ssl
from typing import Callable, Mapping
from urllib.parse import urlsplit

import dns.resolver

from .normalization import NormalizedURL, normalize_url
from .redirect_analysis import _resolve_ips, blocked_ip_reason


class CollectorStatus(str):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class CollectorResult:
    status: str
    value: dict[str, object]
    derived_signals: list[dict[str, object]]
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DomainIntelligenceResult:
    hostname: str
    dns_result: CollectorResult
    registration_result: CollectorResult
    tls_result: CollectorResult
    derived_signals: list[dict[str, object]]
    status: str
    errors: dict[str, str]
    metadata: dict[str, object]
    risk_score: float | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


DNSQuery = Callable[[str, str, float], list[str]]
RDAPClient = Callable[[str, float], tuple[int, bytes]]
TLSClient = Callable[[str, int, float], dict[str, object]]


class DNSCollector:
    """Resolve DNS records only; never connects to returned addresses."""

    record_types = ("A", "AAAA", "MX", "NS", "CNAME")

    def __init__(self, query: DNSQuery | None = None, timeout_seconds: float = 3.0) -> None:
        self.query = query or _dns_query
        self.timeout_seconds = timeout_seconds

    def collect(self, hostname: str) -> CollectorResult:
        if self.timeout_seconds <= 0:
            raise ValueError("DNS timeout must be positive")
        records: dict[str, list[str]] = {}
        errors: dict[str, str] = {}
        for record_type in self.record_types:
            try:
                records[record_type] = sorted(
                    set(self.query(hostname, record_type, self.timeout_seconds))
                )
            except (TimeoutError, socket.timeout):
                errors[record_type] = "DNS query timeout"
            except Exception as exc:
                errors[record_type] = f"DNS query failed: {exc.__class__.__name__}"
        addresses = records.get("A", []) + records.get("AAAA", [])
        private_addresses = sorted({
            address for address in addresses if _is_sensitive_ip(address)
        })
        if addresses or records:
            status = CollectorStatus.AVAILABLE
        else:
            status = CollectorStatus.UNAVAILABLE
        signals = [
            {"signal": "resolves_to_ip", "triggered": bool(addresses), "value": bool(addresses)},
            {"signal": "multiple_addresses", "triggered": len(addresses) > 1, "value": len(addresses)},
            {"signal": "private_or_special_ip", "triggered": bool(private_addresses), "value": private_addresses},
            {"signal": "no_dns_resolution", "triggered": not bool(addresses) and not errors, "value": not bool(addresses) and not errors},
        ]
        return CollectorResult(
            status,
            {
                "records": records,
                "resolved_ip_count": len(addresses),
                "mx_count": len(records.get("MX", [])),
                "ns_count": len(records.get("NS", [])),
                "private_or_special_ips": private_addresses,
                "errors": errors,
            },
            signals,
            "; ".join(f"{key}: {value}" for key, value in errors.items()) or None,
        )


class RegistrationCollector:
    """Retrieve registration dates through RDAP, without inferring age."""

    def __init__(self, client: RDAPClient | None = None, timeout_seconds: float = 5.0) -> None:
        self.client = client or _rdap_client
        self.timeout_seconds = timeout_seconds

    def collect(self, hostname: str) -> CollectorResult:
        if self.timeout_seconds <= 0:
            raise ValueError("Registration timeout must be positive")
        try:
            status_code, body = self.client(hostname, self.timeout_seconds)
            if status_code == 404:
                return CollectorResult(CollectorStatus.UNAVAILABLE, {}, [], "registration data not found")
            if status_code >= 400:
                return CollectorResult(CollectorStatus.FAILED, {}, [], f"RDAP HTTP {status_code}")
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("RDAP response is not an object")
            dates = _rdap_dates(payload.get("events"))
            creation = dates.get("registration")
            if creation is None:
                return CollectorResult(CollectorStatus.UNAVAILABLE, {"events": dates}, [], "creation date unavailable")
            age_days = max(0, (datetime.now(timezone.utc) - creation).days)
            return CollectorResult(
                CollectorStatus.AVAILABLE,
                {
                    "creation_date": creation.isoformat(),
                    "expiration_date": dates.get("expiration").isoformat() if dates.get("expiration") else None,
                    "updated_date": dates.get("last changed").isoformat() if dates.get("last changed") else None,
                    "domain_age_days": age_days,
                    "registrar": _rdap_registrar(payload.get("entities")),
                },
                [{"signal": "very_new_domain", "triggered": age_days < 30, "value": age_days}],
            )
        except TimeoutError:
            return CollectorResult(CollectorStatus.UNAVAILABLE, {}, [], "registration lookup timeout")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            return CollectorResult(CollectorStatus.FAILED, {}, [], str(exc))


class TLSCollector:
    """Inspect verified HTTPS certificates; HTTP is explicitly not applicable."""

    def __init__(self, client: TLSClient | None = None, timeout_seconds: float = 5.0) -> None:
        self.client = client or _tls_client
        self.timeout_seconds = timeout_seconds

    def collect(self, url: NormalizedURL | str) -> CollectorResult:
        normalized = normalize_url(url) if isinstance(url, str) else url
        if normalized.scheme != "https":
            return CollectorResult(CollectorStatus.NOT_APPLICABLE, {}, [], "TLS applies only to HTTPS URLs")
        try:
            certificate = self.client(normalized.hostname, normalized.port or 443, self.timeout_seconds)
            expiry = _certificate_datetime(certificate.get("notAfter"))
            start = _certificate_datetime(certificate.get("notBefore"))
            days_until_expiry = (expiry - datetime.now(timezone.utc)).days if expiry else None
            signals = [
                {"signal": "certificate_expired", "triggered": days_until_expiry is not None and days_until_expiry < 0, "value": days_until_expiry},
            ]
            return CollectorResult(
                CollectorStatus.AVAILABLE,
                {
                    "subject": certificate.get("subject"),
                    "issuer": certificate.get("issuer"),
                    "san": certificate.get("san", []),
                    "valid_from": start.isoformat() if start else None,
                    "valid_until": expiry.isoformat() if expiry else None,
                    "days_until_expiry": days_until_expiry,
                    "hostname_verified": True,
                    "handshake_success": True,
                },
                signals,
            )
        except (TimeoutError, socket.timeout):
            return CollectorResult(CollectorStatus.UNAVAILABLE, {}, [], "TLS handshake timeout")
        except (ssl.CertificateError, ssl.SSLError) as exc:
            return CollectorResult(CollectorStatus.FAILED, {"hostname_verified": False, "handshake_success": False}, [], str(exc))
        except (OSError, ValueError) as exc:
            return CollectorResult(CollectorStatus.FAILED, {"handshake_success": False}, [], f"TLS connection failed: {exc.__class__.__name__}")


def collect_domain_intelligence(
    url: NormalizedURL | str,
    *,
    dns: DNSCollector | None = None,
    registration: RegistrationCollector | None = None,
    tls: TLSCollector | None = None,
) -> DomainIntelligenceResult:
    normalized = normalize_url(url) if isinstance(url, str) else url
    dns_result = (dns or DNSCollector()).collect(normalized.hostname)
    registration_result = (registration or RegistrationCollector()).collect(normalized.hostname)
    tls_result = (tls or TLSCollector()).collect(normalized)
    components = [dns_result, registration_result, tls_result]
    available = [component for component in components if component.status == CollectorStatus.AVAILABLE]
    statuses = {component.status for component in components}
    status = CollectorStatus.AVAILABLE if available else (
        CollectorStatus.FAILED if CollectorStatus.FAILED in statuses else CollectorStatus.UNAVAILABLE
    )
    derived = dns_result.derived_signals + registration_result.derived_signals + tls_result.derived_signals
    errors = {
        name: component.error
        for name, component in (("dns", dns_result), ("registration", registration_result), ("tls", tls_result))
        if component.error
    }
    component_scores = []
    if dns_result.status == CollectorStatus.AVAILABLE:
        component_scores.append(25.0 if dns_result.value["private_or_special_ips"] else 0.0)
    if registration_result.status == CollectorStatus.AVAILABLE:
        component_scores.append(20.0 if registration_result.value.get("domain_age_days", 30) < 30 else 0.0)
    if tls_result.status == CollectorStatus.AVAILABLE:
        component_scores.append(15.0 if any(signal["triggered"] for signal in tls_result.derived_signals) else 0.0)
    return DomainIntelligenceResult(
        normalized.hostname,
        dns_result,
        registration_result,
        tls_result,
        derived,
        status,
        errors,
        {"only_dns_resolution": True, "connections_to_resolved_ips": False},
        sum(component_scores) / len(component_scores) if component_scores else None,
    )


def _dns_query(hostname: str, record_type: str, timeout: float) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return [record.to_text().strip('"') for record in resolver.resolve(hostname, record_type)]


def _rdap_client(hostname: str, timeout: float) -> tuple[int, bytes]:
    import urllib.request
    with urllib.request.urlopen(f"https://rdap.org/domain/{hostname}", timeout=timeout) as response:
        return response.status, response.read()


def _tls_client(hostname: str, port: int, timeout: float) -> dict[str, object]:
    context = ssl.create_default_context()
    try:
        resolved_ips = _resolve_ips(hostname)
    except (IndexError, TypeError) as exc:
        raise OSError("malformed DNS resolution") from exc
    if not resolved_ips:
        raise OSError("hostname did not resolve")
    unsafe = next(
        (reason for address in resolved_ips if (reason := blocked_ip_reason(address))),
        None,
    )
    if unsafe:
        raise OSError(f"unsafe resolved address: {unsafe}")
    # Connect to the validated address while retaining the original hostname
    # for SNI and certificate hostname verification.
    with socket.create_connection((resolved_ips[0], port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as secure:
            certificate = secure.getpeercert()
            return {
                "subject": certificate.get("subject"),
                "issuer": certificate.get("issuer"),
                "san": [value for kind, value in certificate.get("subjectAltName", ()) if kind == "DNS"],
                "notBefore": certificate.get("notBefore"),
                "notAfter": certificate.get("notAfter"),
            }


def _is_sensitive_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or value == "169.254.169.254"
    )


def _rdap_dates(events: object) -> dict[str, datetime]:
    if not isinstance(events, list):
        raise ValueError("RDAP events are missing")
    result: dict[str, datetime] = {}
    for event in events:
        if not isinstance(event, dict) or event.get("eventAction") not in {"registration", "expiration", "last changed"}:
            continue
        date = event.get("eventDate")
        if isinstance(date, str):
            result[str(event["eventAction"])] = datetime.fromisoformat(date.replace("Z", "+00:00"))
    return result


def _rdap_registrar(entities: object) -> str | None:
    if not isinstance(entities, list):
        return None
    for entity in entities:
        if isinstance(entity, dict) and "registrar" in entity.get("roles", []):
            return str(entity.get("vcardArray", "")) or None
    return None


def _certificate_datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
