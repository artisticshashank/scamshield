"""Bounded redirect resolution with explicit SSRF and rebinding defenses."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
import socket
import ssl
import time
from typing import Callable, Mapping
from urllib.parse import urljoin, urlsplit

from .feature_extraction import extract_features
from .normalization import URLNormalizationError, normalize_url


@dataclass(frozen=True)
class RedirectLimits:
    max_hops: int = 5
    timeout_seconds: float = 3.0
    total_timeout_seconds: float = 10.0
    max_url_length: int = 2048
    max_header_bytes: int = 8192
    max_chain_entries: int = 5

    def __post_init__(self) -> None:
        if self.max_hops < 1 or self.max_chain_entries < 1:
            raise ValueError("Redirect limits must allow at least one hop")
        if self.timeout_seconds <= 0 or self.total_timeout_seconds <= 0:
            raise ValueError("Redirect timeouts must be positive")
        if self.max_url_length < 1 or self.max_header_bytes < 256:
            raise ValueError("Redirect size limits are too small")


@dataclass(frozen=True)
class RedirectResponse:
    status: int
    headers: Mapping[str, str]


@dataclass(frozen=True)
class RedirectHop:
    hop: int
    source_url: str
    destination_url: str | None
    status: int | None
    hostname: str | None
    blocked: bool
    blocked_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class RedirectResult:
    status: str
    original_url: str
    final_url: str | None
    hop_count: int
    chain: list[dict[str, object]]
    shortened_url: bool
    cross_domain_redirect: bool
    blocked_destination: bool
    blocked_reason: str | None
    loop_detected: bool
    timeout: bool
    errors: list[str]
    derived_signals: list[dict[str, object]]
    risk_score: float | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


ResolveIPs = Callable[[str], list[str]]
Request = Callable[[str, str, int, float, int], RedirectResponse]


class RedirectResolver:
    """Resolve only bounded HTTP(S) redirect chains."""

    def __init__(
        self,
        *,
        resolve_ips: ResolveIPs | None = None,
        request: Request | None = None,
        limits: RedirectLimits = RedirectLimits(),
    ) -> None:
        self.resolve_ips = resolve_ips or _resolve_ips
        self.request = request or _request_at_validated_ip
        self.limits = limits

    def resolve(self, original_url: str) -> RedirectResult:
        errors: list[str] = []
        try:
            current = normalize_url(original_url)
        except URLNormalizationError as exc:
            return _result(original_url, "failed", errors=[str(exc)])
        if len(current.normalized_url) > self.limits.max_url_length:
            return _result(original_url, "failed", errors=["URL exceeds redirect length limit"])
        if current.hostname == "localhost" or current.hostname.endswith(".localhost"):
            return _result(
                original_url,
                "blocked",
                errors=["localhost destinations are blocked"],
                blocked=True,
                blocked_reason="localhost destinations are blocked",
            )

        chain: list[RedirectHop] = []
        visited = {current.normalized_url}
        domains = {current.hostname}
        blocked_reason: str | None = None
        timed_out = False
        loop_detected = False
        status = "completed"
        started = time.monotonic()

        for hop in range(self.limits.max_hops + 1):
            if hop >= self.limits.max_chain_entries:
                status = "hop_limit"
                errors.append("Redirect chain entry limit reached")
                break
            remaining = self.limits.total_timeout_seconds - (time.monotonic() - started)
            if remaining <= 0:
                timed_out = True
                status = "timeout"
                errors.append("Total redirect-analysis timeout")
                break
            try:
                ips = sorted(set(self.resolve_ips(current.hostname)))
            except (TimeoutError, socket.timeout):
                timed_out = True
                status = "timeout"
                errors.append("DNS resolution timeout")
                break
            except Exception as exc:
                status = "failed"
                errors.append(f"DNS resolution failed: {exc.__class__.__name__}")
                break
            unsafe = next((reason for ip in ips if (reason := blocked_ip_reason(ip))), None)
            if unsafe:
                blocked_reason = unsafe
                status = "blocked"
                chain.append(RedirectHop(hop, current.normalized_url, None, None,
                                         current.hostname, True, unsafe))
                break
            if not ips:
                status = "failed"
                errors.append("Hostname did not resolve")
                break
            try:
                response = self.request(
                    current.normalized_url,
                    ips[0],
                    current.port or (443 if current.scheme == "https" else 80),
                    min(self.limits.timeout_seconds, remaining),
                    self.limits.max_header_bytes,
                )
            except (TimeoutError, socket.timeout):
                timed_out = True
                status = "timeout"
                errors.append("HTTP request timeout")
                break
            except Exception as exc:
                status = "failed"
                errors.append(f"HTTP request failed: {exc.__class__.__name__}")
                break

            location = _header(response.headers, "location")
            destination = urljoin(current.normalized_url, location) if location else None
            destination_text = destination
            if location and (not destination or len(destination) > self.limits.max_url_length):
                status = "failed"
                errors.append("Malformed or oversized redirect Location")
                chain.append(RedirectHop(hop, current.normalized_url, destination_text,
                                         response.status, None, True, errors[-1]))
                break
            if not (300 <= response.status < 400) or not location:
                chain.append(RedirectHop(hop, current.normalized_url, None, response.status,
                                         current.hostname, False))
                break
            try:
                next_url = normalize_url(destination)
            except (URLNormalizationError, TypeError) as exc:
                status = "failed"
                errors.append(f"Invalid redirect destination: {exc}")
                chain.append(RedirectHop(hop, current.normalized_url, destination,
                                         response.status, None, True, errors[-1]))
                break
            domains.add(next_url.hostname)
            if next_url.normalized_url in visited:
                loop_detected = True
                status = "loop"
                chain.append(RedirectHop(hop, current.normalized_url, next_url.normalized_url,
                                         response.status, next_url.hostname, False))
                break
            visited.add(next_url.normalized_url)
            chain.append(RedirectHop(hop, current.normalized_url, next_url.normalized_url,
                                     response.status, next_url.hostname, False))
            current = next_url
            if hop == self.limits.max_hops - 1:
                status = "hop_limit"
                errors.append("Maximum redirect hops reached")
                break

        final_url = current.normalized_url if status in {"completed", "loop", "hop_limit"} else None
        cross_domain = len(domains) > 1
        shortener = extract_features(normalize_url(original_url)).is_url_shortener
        risk = _risk_score(shortener, len(chain), cross_domain, blocked_reason, loop_detected)
        signals = [
            {"signal": "shortener_used", "triggered": shortener, "value": shortener},
            {"signal": "multiple_redirects", "triggered": len(chain) > 1, "value": len(chain)},
            {"signal": "cross_domain_redirect", "triggered": cross_domain, "value": cross_domain},
            {"signal": "blocked_private_destination", "triggered": bool(blocked_reason), "value": blocked_reason},
            {"signal": "redirect_loop", "triggered": loop_detected, "value": loop_detected},
            {"signal": "excessive_redirect_chain", "triggered": status == "hop_limit", "value": status == "hop_limit"},
        ]
        return RedirectResult(
            status=status,
            original_url=original_url,
            final_url=final_url,
            hop_count=len(chain),
            chain=[item.to_dict() for item in chain],
            shortened_url=shortener,
            cross_domain_redirect=cross_domain,
            blocked_destination=bool(blocked_reason),
            blocked_reason=blocked_reason,
            loop_detected=loop_detected,
            timeout=timed_out,
            errors=errors,
            derived_signals=signals,
            risk_score=risk,
        )


def blocked_ip_reason(value: str) -> str | None:
    try:
        address = ip_address(value)
    except ValueError:
        return "invalid resolved IP"
    if isinstance(address, IPv4Address):
        networks = (
            IPv4Network("0.0.0.0/8"), IPv4Network("10.0.0.0/8"),
            IPv4Network("100.64.0.0/10"), IPv4Network("127.0.0.0/8"),
            IPv4Network("169.254.0.0/16"), IPv4Network("172.16.0.0/12"),
            IPv4Network("192.0.0.0/24"), IPv4Network("192.0.2.0/24"),
            IPv4Network("192.168.0.0/16"), IPv4Network("198.18.0.0/15"),
            IPv4Network("198.51.100.0/24"), IPv4Network("203.0.113.0/24"),
            IPv4Network("224.0.0.0/4"), IPv4Network("240.0.0.0/4"),
        )
    else:
        networks = (
            IPv6Network("::/128"), IPv6Network("::1/128"), IPv6Network("fc00::/7"),
            IPv6Network("fe80::/10"), IPv6Network("ff00::/8"),
        )
        if address.ipv4_mapped is not None:
            mapped_reason = blocked_ip_reason(str(address.ipv4_mapped))
            if mapped_reason:
                return f"IPv4-mapped address: {mapped_reason}"
    return "private or special IP range" if any(address in network for network in networks) else None


def _resolve_ips(hostname: str) -> list[str]:
    return sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)})


def _request_at_validated_ip(url: str, ip: str, port: int, timeout: float, max_header_bytes: int) -> RedirectResponse:
    parsed = urlsplit(url)
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=parsed.hostname)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        host = parsed.hostname or ""
        if parsed.port is not None:
            host = f"{host}:{parsed.port}"
        sock.sendall(f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii"))
        data = b""
        while b"\r\n\r\n" not in data and len(data) <= max_header_bytes:
            chunk = sock.recv(min(1024, max_header_bytes + 1 - len(data)))
            if not chunk:
                break
            data += chunk
        if len(data) > max_header_bytes:
            raise ValueError("Response headers exceed configured limit")
        header = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
        lines = header.split("\r\n")
        status = int(lines[0].split()[1])
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.lower()] = value.strip()
        return RedirectResponse(status, headers)
    finally:
        sock.close()


def _header(headers: Mapping[str, str], name: str) -> str | None:
    return next((value for key, value in headers.items() if key.lower() == name), None)


def _risk_score(shortener: bool, hops: int, cross_domain: bool, blocked: str | None, loop: bool) -> float:
    score = (8 if shortener else 0) + min(20, max(0, hops - 1) * 5)
    score += 12 if cross_domain else 0
    score += 20 if blocked else 0
    score += 15 if loop else 0
    return min(100.0, float(score))


def _result(
    original_url: str,
    status: str,
    *,
    errors: list[str],
    blocked: bool = False,
    blocked_reason: str | None = None,
) -> RedirectResult:
    return RedirectResult(
        status,
        original_url,
        None,
        0,
        [],
        False,
        False,
        blocked,
        blocked_reason,
        False,
        False,
        errors,
        [],
        None,
    )
