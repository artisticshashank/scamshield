"""Safe URL parsing and canonicalization for the detection pipeline."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from ipaddress import ip_address
import re
from urllib.parse import quote, unquote, urlsplit, urlunsplit


class URLNormalizationError(ValueError):
    """Raised when an input cannot be safely interpreted as an HTTP(S) URL."""


@dataclass(frozen=True)
class NormalizedURL:
    """The normalized URL contract shared by later detection stages."""

    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    query: str
    fragment: str
    is_ip_host: bool
    is_punycode: bool
    has_suspicious_encoding: bool

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation for future API use."""

        return asdict(self)


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_url(value: str) -> NormalizedURL:
    """Parse and canonicalize a URL without changing its security semantics.

    A missing scheme is accepted as a convenience for pasted browser URLs and
    is interpreted as HTTPS. Only HTTP and HTTPS are accepted by this layer.
    Percent-encoded components are decoded once for analysis, while the
    canonical URL retains escaping for delimiters that would change parsing.
    """

    if not isinstance(value, str):
        raise URLNormalizationError("URL must be a string")

    original_url = value.strip()
    if not original_url:
        raise URLNormalizationError("URL must not be empty")
    if _CONTROL_CHARACTERS.search(original_url):
        raise URLNormalizationError("URL contains control characters")

    candidate = original_url
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", candidate):
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise URLNormalizationError(f"Malformed URL: {exc}") from exc

    if scheme not in {"http", "https"}:
        raise URLNormalizationError("Only HTTP and HTTPS URLs are supported")
    if not hostname:
        raise URLNormalizationError("URL must contain a hostname")
    hostname = _normalize_hostname(hostname)
    decoded_path = unquote(parsed.path or "/")
    decoded_query = unquote(parsed.query)
    decoded_fragment = unquote(parsed.fragment)
    if _has_malformed_encoding(parsed.path, parsed.query, parsed.fragment):
        raise URLNormalizationError("URL contains malformed percent encoding")
    has_suspicious_encoding = _has_suspicious_encoding(
        parsed.path, parsed.query, parsed.fragment
    )
    is_ip_host = _is_ip_address(hostname)
    is_punycode = any(label.lower().startswith("xn--") for label in hostname.split("."))

    canonical_netloc = _format_netloc(hostname, port, scheme)
    normalized_url = urlunsplit(
        (
            scheme,
            canonical_netloc,
            _canonical_path(decoded_path),
            _canonical_component(decoded_query, safe="=&?"),
            _canonical_component(decoded_fragment, safe=""),
        )
    )

    return NormalizedURL(
        original_url=original_url,
        normalized_url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=decoded_path,
        query=decoded_query,
        fragment=decoded_fragment,
        is_ip_host=is_ip_host,
        is_punycode=is_punycode,
        has_suspicious_encoding=has_suspicious_encoding,
    )


def _normalize_hostname(hostname: str) -> str:
    """Lowercase and IDNA-normalize a hostname, preserving IPv6 brackets out."""

    normalized = hostname.rstrip(".").lower()
    if not normalized:
        raise URLNormalizationError("URL must contain a hostname")
    if any(character.isspace() for character in normalized):
        raise URLNormalizationError("Hostname contains whitespace")
    try:
        return normalized.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise URLNormalizationError("Hostname contains invalid characters") from exc


def _is_ip_address(hostname: str) -> bool:
    try:
        ip_address(hostname)
    except ValueError:
        return False
    return True


def _format_netloc(hostname: str, port: int | None, scheme: str) -> str:
    display_hostname = f"[{hostname}]" if ":" in hostname else hostname
    if port is None or port == _DEFAULT_PORTS[scheme]:
        return display_hostname
    return f"{display_hostname}:{port}"


def _canonical_path(path: str) -> str:
    return quote(path or "/", safe="/:@!$&'()*+,;=-._~")


def _canonical_component(value: str, *, safe: str) -> str:
    return quote(value, safe=safe + ":@!$'()*+,;=-._~")


def _has_suspicious_encoding(*components: str) -> bool:
    """Flag malformed escapes and encoded URL delimiters/control characters."""

    for component in components:
        if re.search(r"%(?:2f|2F|3f|3F|23|40|5c|5C|00|0d|0a)", component):
            return True
    return False


def _has_malformed_encoding(*components: str) -> bool:
    return any(re.search(r"%(?![0-9A-Fa-f]{2})", component) for component in components)
