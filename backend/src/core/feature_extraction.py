"""Deterministic URL features shared by rules and the ML baseline."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
import math
import re
from urllib.parse import parse_qsl

from .normalization import NormalizedURL


@dataclass(frozen=True)
class URLFeatures:
    """Numeric and boolean feature schema for one normalized URL."""

    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    dot_count: int
    hyphen_count: int
    underscore_count: int
    digit_count: int
    special_character_count: int
    subdomain_count: int
    path_depth: int
    query_parameter_count: int
    fragment_length: int
    percent_encoded_character_count: int
    entropy: float
    digit_ratio: float
    special_character_ratio: float
    is_https: bool
    is_ip_host: bool
    has_at_symbol: bool
    has_double_slash_in_path: bool
    is_punycode: bool
    has_suspicious_tld: bool
    has_excessive_subdomains: bool
    has_suspicious_port: bool
    is_url_shortener: bool
    has_suspicious_keywords: bool
    has_credential_keywords: bool
    has_payment_keywords: bool
    has_urgency_keywords: bool
    has_brand_name: bool
    possible_brand_impersonation: bool
    has_homoglyph_similarity: bool

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable feature mapping."""

        return asdict(self)


_SUSPICIOUS_TLDS = frozenset(
    {"click", "download", "fit", "gdn", "live", "loan", "work", "zip"}
)
_URL_SHORTENERS = frozenset(
    {
        "bit.ly",
        "cutt.ly",
        "is.gd",
        "ow.ly",
        "rebrand.ly",
        "shorturl.at",
        "t.co",
        "tinyurl.com",
    }
)
_CREDENTIAL_KEYWORDS = frozenset(
    {"account", "authenticate", "credential", "login", "password", "signin", "verify"}
)
_PAYMENT_KEYWORDS = frozenset(
    {"billing", "card", "checkout", "invoice", "payment", "pay", "wallet"}
)
_URGENCY_KEYWORDS = frozenset(
    {"alert", "expire", "immediately", "now", "urgent", "warning", "within"}
)
_BRAND_DOMAINS = {
    "apple": frozenset({"apple.com"}),
    "amazon": frozenset({"amazon.com", "amazon.in", "amazon.co.uk"}),
    "google": frozenset({"google.com"}),
    "microsoft": frozenset({"microsoft.com", "live.com", "office.com"}),
    "paypal": frozenset({"paypal.com"}),
}
_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


def extract_features(url: NormalizedURL) -> URLFeatures:
    """Extract the complete Phase 1 feature schema without network access."""

    searchable = " ".join((url.hostname, url.path, url.query, url.fragment)).lower()
    tokens = set(_TOKEN_PATTERN.findall(searchable))
    tld = url.hostname.rsplit(".", maxsplit=1)[-1] if "." in url.hostname else ""
    labels = url.hostname.split(".")
    subdomain_count = max(0, len(labels) - 2) if not url.is_ip_host else 0
    host_and_path = f"{url.hostname}{url.path}".lower()
    brands = {
        brand
        for brand, official_domains in _BRAND_DOMAINS.items()
        if brand in tokens
        or any(
            url.hostname == domain or url.hostname.endswith(f".{domain}")
            for domain in official_domains
        )
    }
    has_brand_name = bool(brands)
    possible_brand_impersonation = any(
        brand in host_and_path
        and not any(
            url.hostname == domain or url.hostname.endswith(f".{domain}")
            for domain in official_domains
        )
        for brand, official_domains in _BRAND_DOMAINS.items()
    )
    special_character_count = sum(
        not character.isalnum() for character in url.normalized_url
    )
    total_length = len(url.normalized_url)

    return URLFeatures(
        url_length=total_length,
        hostname_length=len(url.hostname),
        path_length=len(url.path),
        query_length=len(url.query),
        dot_count=url.hostname.count("."),
        hyphen_count=url.normalized_url.count("-"),
        underscore_count=url.normalized_url.count("_"),
        digit_count=sum(character.isdigit() for character in url.normalized_url),
        special_character_count=special_character_count,
        subdomain_count=subdomain_count,
        path_depth=len([part for part in url.path.split("/") if part]),
        query_parameter_count=len(parse_qsl(url.query, keep_blank_values=True)),
        fragment_length=len(url.fragment),
        percent_encoded_character_count=len(
            re.findall(r"%[0-9A-Fa-f]{2}", url.original_url)
        ),
        entropy=_shannon_entropy(url.normalized_url),
        digit_ratio=_ratio(
            sum(character.isdigit() for character in url.normalized_url), total_length
        ),
        special_character_ratio=_ratio(special_character_count, total_length),
        is_https=url.scheme == "https",
        is_ip_host=url.is_ip_host,
        has_at_symbol="@" in url.original_url,
        has_double_slash_in_path="//" in url.path,
        is_punycode=url.is_punycode,
        has_suspicious_tld=tld in _SUSPICIOUS_TLDS,
        has_excessive_subdomains=subdomain_count >= 4,
        has_suspicious_port=url.port is not None
        and url.port not in {80, 443},
        is_url_shortener=url.hostname in _URL_SHORTENERS,
        has_suspicious_keywords=bool(
            tokens & (_CREDENTIAL_KEYWORDS | _PAYMENT_KEYWORDS | _URGENCY_KEYWORDS)
        ),
        has_credential_keywords=bool(tokens & _CREDENTIAL_KEYWORDS),
        has_payment_keywords=bool(tokens & _PAYMENT_KEYWORDS),
        has_urgency_keywords=bool(tokens & _URGENCY_KEYWORDS),
        has_brand_name=has_brand_name,
        possible_brand_impersonation=possible_brand_impersonation,
        has_homoglyph_similarity=url.is_punycode,
    )


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )
