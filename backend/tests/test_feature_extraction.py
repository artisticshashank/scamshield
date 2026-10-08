from core.feature_extraction import extract_features
from core.normalization import normalize_url


def test_extracts_url_shape_features() -> None:
    url = normalize_url(
        "https://shop.example.com/account/login?next=home&lang=en#details"
    )

    features = extract_features(url)

    assert features.hostname_length == len("shop.example.com")
    assert features.subdomain_count == 1
    assert features.path_depth == 2
    assert features.query_parameter_count == 2
    assert features.fragment_length == len("details")
    assert features.is_https is True
    assert features.entropy > 0


def test_extracts_adversarial_security_features() -> None:
    url = normalize_url(
        "http://login-paypal.example.com:8080/a//b/verify?"
        "password=x&urgent=now"
    )

    features = extract_features(url)

    assert features.is_https is False
    assert features.has_suspicious_port is True
    assert features.has_double_slash_in_path is True
    assert features.has_credential_keywords is True
    assert features.has_urgency_keywords is True
    assert features.has_brand_name is True
    assert features.possible_brand_impersonation is True


def test_extracts_ip_punycode_and_encoding_features() -> None:
    url = normalize_url("https://xn--pple-43d.example/%2Flogin?id=1")

    features = extract_features(url)

    assert features.is_punycode is True
    assert features.has_homoglyph_similarity is True
    assert features.percent_encoded_character_count == 1
    assert features.is_ip_host is False


def test_identifies_shortener_suspicious_tld_and_excessive_subdomains() -> None:
    url = normalize_url(
        "https://a.b.c.d.tinyurl.com/download/file.zip"
    )

    features = extract_features(url)

    assert features.is_url_shortener is False
    assert features.has_suspicious_tld is False
    assert features.has_excessive_subdomains is True

    short_url = extract_features(normalize_url("https://tinyurl.com/abc"))
    assert short_url.is_url_shortener is True

    suspicious_tld = extract_features(normalize_url("https://example.zip/file"))
    assert suspicious_tld.has_suspicious_tld is True


def test_legitimate_login_url_has_no_impersonation_signal() -> None:
    features = extract_features(
        normalize_url("https://accounts.google.com/signin/v2/identifier")
    )

    assert features.has_brand_name is True
    assert features.possible_brand_impersonation is False
    assert features.has_suspicious_port is False


def test_feature_schema_serializes_all_values() -> None:
    features = extract_features(normalize_url("https://example.com"))

    serialized = features.to_dict()

    assert serialized["url_length"] == len("https://example.com/")
    assert serialized["path_depth"] == 0
    assert set(serialized) == set(features.__dataclass_fields__)
