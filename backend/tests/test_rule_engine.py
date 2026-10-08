from dataclasses import replace

import pytest

from core.feature_extraction import extract_features
from core.normalization import normalize_url
from core.rule_engine import (
    DEFAULT_THRESHOLDS,
    RuleEvidence,
    evaluate_rules,
    rule_brand_impersonation,
    rule_ip_host,
    rule_no_https,
    rule_punycode,
)


def _scan(value: str) -> list[RuleEvidence]:
    normalized = normalize_url(value)
    return evaluate_rules(normalized, extract_features(normalized))


def _ids(value: str) -> set[str]:
    return {evidence.rule_id for evidence in _scan(value)}


def test_benign_https_url_has_no_rules() -> None:
    assert _scan("https://www.example.com/about") == []


def test_ip_url_triggers_structured_high_severity_evidence() -> None:
    evidence = next(item for item in _scan("https://192.0.2.10/login") if item.rule_id == "URL_IP_HOST")

    assert evidence.category == "host"
    assert evidence.severity == "high"
    assert evidence.triggered is True
    assert evidence.score > 0
    assert evidence.feature == "is_ip_host"
    assert evidence.value is True
    assert evidence.explanation
    assert evidence.to_dict()["contribution"] == evidence.score


def test_at_trick_is_detected() -> None:
    assert "URL_USERINFO_TRICK" in _ids("https://login.example.com@evil.example/login")


def test_punycode_and_homoglyph_signals_are_explainable_without_double_score() -> None:
    evidence = _scan("https://xn--pple-43d.example/login")
    by_id = {item.rule_id: item for item in evidence}

    assert {"URL_PUNYCODE", "URL_HOMOGLYPH_SIGNAL"} <= by_id.keys()
    assert by_id["URL_PUNYCODE"].score > 0
    assert by_id["URL_HOMOGLYPH_SIGNAL"].score == 0


def test_lookalike_brand_domain_is_detected_but_official_domain_is_not() -> None:
    assert "URL_BRAND_IMPERSONATION" in _ids("https://secure-paypal.example/login")
    assert "URL_BRAND_IMPERSONATION" not in _ids("https://www.paypal.com/signin")


def test_domain_and_transport_rules() -> None:
    ids = _ids("http://a.b.c.d.example.zip:8080/login")

    assert {
        "URL_EXCESSIVE_SUBDOMAINS",
        "URL_SUSPICIOUS_TLD",
        "URL_SUSPICIOUS_PORT",
        "URL_NO_HTTPS",
    } <= ids


def test_obfuscation_and_length_rules() -> None:
    encoded = "%2F".join(["a"] * 5)
    url = f"https://example.com/{encoded}/" + ("x" * 220)
    ids = _ids(url)

    assert "URL_OBFUSCATION" in ids
    assert "URL_EXCESSIVE_LENGTH" in ids


@pytest.mark.parametrize(
    ("url", "rule_id"),
    [
        ("https://example.com/account/login", "URL_CREDENTIAL_KEYWORDS"),
        ("https://example.com/checkout/payment", "URL_PAYMENT_KEYWORDS"),
        ("https://example.com/urgent/verify", "URL_URGENCY_KEYWORDS"),
        ("https://tinyurl.com/example", "URL_SHORTENER"),
        ("https://example.com/a//b", "URL_DOUBLE_SLASH_PATH"),
    ],
)
def test_content_and_structure_rules(url: str, rule_id: str) -> None:
    assert rule_id in _ids(url)


def test_keyword_rules_do_not_mark_legitimate_login_or_payment_as_impersonation() -> None:
    login_ids = _ids("https://accounts.google.com/signin/v2/identifier")
    payment_ids = _ids("https://www.paypal.com/checkout")

    assert "URL_BRAND_IMPERSONATION" not in login_ids
    assert "URL_BRAND_IMPERSONATION" not in payment_ids


def test_shortener_rule_does_not_trigger_for_an_unrelated_long_domain() -> None:
    assert "URL_SHORTENER" not in _ids("https://example.com/redirect/to/content")


def test_individual_rules_are_callable_and_respect_thresholds() -> None:
    normalized = normalize_url("https://192.0.2.10/login")
    features = extract_features(normalized)

    assert rule_ip_host(normalized, features, DEFAULT_THRESHOLDS).triggered
    assert rule_punycode(normalized, features, DEFAULT_THRESHOLDS).triggered is False
    assert rule_no_https(normalized, features, DEFAULT_THRESHOLDS).triggered is False
    assert rule_brand_impersonation(normalized, features, DEFAULT_THRESHOLDS).triggered is False


def test_custom_thresholds_change_only_rule_evaluation() -> None:
    normalized = normalize_url("https://example.com/" + ("a" * 20))
    features = extract_features(normalized)
    thresholds = replace(DEFAULT_THRESHOLDS, excessive_url_length=10)

    evidence = evaluate_rules(normalized, features, thresholds)

    assert "URL_EXCESSIVE_LENGTH" in {item.rule_id for item in evidence}
    assert normalized.normalized_url == "https://example.com/" + ("a" * 20)
