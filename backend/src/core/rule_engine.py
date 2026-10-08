"""Modular, explainable security rules for normalized URLs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Callable, Final

from .feature_extraction import URLFeatures
from .normalization import NormalizedURL


@dataclass(frozen=True)
class RuleThresholds:
    """Centralized thresholds and contribution weights for the rule layer."""

    excessive_url_length: int = 200
    excessive_percent_encoded_characters: int = 3
    ip_host_score: int = 18
    userinfo_score: int = 16
    punycode_score: int = 10
    homoglyph_score: int = 0
    excessive_subdomains_score: int = 8
    suspicious_tld_score: int = 5
    suspicious_port_score: int = 4
    no_https_score: int = 3
    obfuscation_score: int = 8
    excessive_url_length_score: int = 3
    suspicious_keywords_score: int = 0
    credential_keywords_score: int = 6
    payment_keywords_score: int = 6
    urgency_keywords_score: int = 4
    url_shortener_score: int = 3
    double_slash_score: int = 5
    brand_impersonation_score: int = 15


DEFAULT_THRESHOLDS: Final = RuleThresholds()


@dataclass(frozen=True)
class RuleEvidence:
    """One explainable rule result, suitable for JSON serialization."""

    rule_id: str
    category: str
    severity: str
    triggered: bool
    score: int
    explanation: str
    feature: str
    value: object

    @property
    def contribution(self) -> int:
        """Alias used by consumers that call rule weights contributions."""

        return self.score

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["contribution"] = self.contribution
        return result


Rule = Callable[[NormalizedURL, URLFeatures, RuleThresholds], RuleEvidence]


def _evidence(
    rule_id: str,
    category: str,
    severity: str,
    triggered: bool,
    score: int,
    explanation: str,
    feature: str,
    value: object,
) -> RuleEvidence:
    return RuleEvidence(
        rule_id=rule_id,
        category=category,
        severity=severity,
        triggered=triggered,
        score=score if triggered else 0,
        explanation=explanation,
        feature=feature,
        value=value,
    )


def rule_ip_host(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_IP_HOST", "host", "high", features.is_ip_host, t.ip_host_score,
        "The URL uses an IP address instead of a normal domain.",
        "is_ip_host", features.is_ip_host,
    )


def rule_userinfo(url: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_USERINFO_TRICK", "structure", "high", features.has_at_symbol, t.userinfo_score,
        "The URL contains user-info syntax that can hide the actual destination host.",
        "has_at_symbol", features.has_at_symbol,
    )


def rule_punycode(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_PUNYCODE", "domain", "medium", features.is_punycode, t.punycode_score,
        "The hostname contains an IDN punycode label; inspect it for lookalike abuse.",
        "is_punycode", features.is_punycode,
    )


def rule_homoglyph(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_HOMOGLYPH_SIGNAL", "domain", "medium",
        features.has_homoglyph_similarity, t.homoglyph_score,
        "The hostname has a homoglyph-like signal. This overlaps with punycode and "
        "therefore adds no extra score.",
        "has_homoglyph_similarity", features.has_homoglyph_similarity,
    )


def rule_excessive_subdomains(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_EXCESSIVE_SUBDOMAINS", "domain", "medium",
        features.has_excessive_subdomains, t.excessive_subdomains_score,
        "The hostname contains an unusually large number of subdomain labels.",
        "subdomain_count", features.subdomain_count,
    )


def rule_suspicious_tld(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_SUSPICIOUS_TLD", "domain", "medium", features.has_suspicious_tld,
        t.suspicious_tld_score,
        "The hostname uses a TLD that is commonly associated with suspicious links.",
        "has_suspicious_tld", features.has_suspicious_tld,
    )


def rule_suspicious_port(url: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_SUSPICIOUS_PORT", "network", "medium", features.has_suspicious_port,
        t.suspicious_port_score,
        "The URL uses a non-standard HTTP(S) port.",
        "port", url.port,
    )


def rule_no_https(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    triggered = not features.is_https
    return _evidence(
        "URL_NO_HTTPS", "transport", "low", triggered, t.no_https_score,
        "The URL does not use HTTPS. This is a risk signal, not proof of phishing.",
        "is_https", features.is_https,
    )


def rule_obfuscation(url: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    triggered = (
        features.percent_encoded_character_count
        >= t.excessive_percent_encoded_characters
        or url.has_suspicious_encoding
    )
    return _evidence(
        "URL_OBFUSCATION", "structure", "medium", triggered, t.obfuscation_score,
        "The URL contains suspicious or excessive percent encoding.",
        "percent_encoded_character_count", features.percent_encoded_character_count,
    )


def rule_excessive_length(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    triggered = features.url_length > t.excessive_url_length
    return _evidence(
        "URL_EXCESSIVE_LENGTH", "structure", "low", triggered,
        t.excessive_url_length_score,
        "The URL is unusually long and may contain obfuscating content.",
        "url_length", features.url_length,
    )


def rule_suspicious_keywords(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    # Category-specific rules carry the score; this umbrella evidence is context only.
    triggered = (
        features.has_suspicious_keywords
        and not features.has_credential_keywords
        and not features.has_payment_keywords
        and not features.has_urgency_keywords
    )
    return _evidence(
        "URL_SUSPICIOUS_KEYWORDS", "content", "medium", triggered,
        t.suspicious_keywords_score,
        "The path or query contains a security-sensitive keyword pattern.",
        "has_suspicious_keywords", features.has_suspicious_keywords,
    )


def rule_credential_keywords(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_CREDENTIAL_KEYWORDS", "content", "medium",
        features.has_credential_keywords, t.credential_keywords_score,
        "The path or query contains credential-related keywords.",
        "has_credential_keywords", features.has_credential_keywords,
    )


def rule_payment_keywords(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_PAYMENT_KEYWORDS", "content", "medium",
        features.has_payment_keywords, t.payment_keywords_score,
        "The path or query contains payment-related keywords.",
        "has_payment_keywords", features.has_payment_keywords,
    )


def rule_urgency_keywords(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_URGENCY_KEYWORDS", "content", "medium",
        features.has_urgency_keywords, t.urgency_keywords_score,
        "The path or query contains urgency-related keywords.",
        "has_urgency_keywords", features.has_urgency_keywords,
    )


def rule_url_shortener(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_SHORTENER", "domain", "medium", features.is_url_shortener,
        t.url_shortener_score,
        "The hostname belongs to a known URL-shortening service.",
        "is_url_shortener", features.is_url_shortener,
    )


def rule_double_slash(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_DOUBLE_SLASH_PATH", "structure", "medium",
        features.has_double_slash_in_path, t.double_slash_score,
        "The path contains a double slash that may be used for obfuscation.",
        "has_double_slash_in_path", features.has_double_slash_in_path,
    )


def rule_brand_impersonation(_: NormalizedURL, features: URLFeatures, t: RuleThresholds) -> RuleEvidence:
    return _evidence(
        "URL_BRAND_IMPERSONATION", "brand", "high",
        features.possible_brand_impersonation, t.brand_impersonation_score,
        "A known brand appears in a non-official hostname or path.",
        "possible_brand_impersonation", features.possible_brand_impersonation,
    )


RULES: Final[tuple[Rule, ...]] = (
    rule_ip_host,
    rule_userinfo,
    rule_punycode,
    rule_homoglyph,
    rule_excessive_subdomains,
    rule_suspicious_tld,
    rule_suspicious_port,
    rule_no_https,
    rule_obfuscation,
    rule_excessive_length,
    rule_suspicious_keywords,
    rule_credential_keywords,
    rule_payment_keywords,
    rule_urgency_keywords,
    rule_url_shortener,
    rule_double_slash,
    rule_brand_impersonation,
)


def evaluate_rules(
    url: NormalizedURL,
    features: URLFeatures,
    thresholds: RuleThresholds = DEFAULT_THRESHOLDS,
) -> list[RuleEvidence]:
    """Evaluate all rules and return only triggered evidence in stable order."""

    return [
        evidence
        for rule in RULES
        if (evidence := rule(url, features, thresholds)).triggered
    ]
