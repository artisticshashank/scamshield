import pytest

from core.normalization import URLNormalizationError, normalize_url


def test_normalizes_scheme_host_and_default_port() -> None:
    result = normalize_url(" HTTPS://Example.COM:443/login?next=home#section ")

    assert result.normalized_url == "https://example.com/login?next=home#section"
    assert result.scheme == "https"
    assert result.hostname == "example.com"
    assert result.port == 443
    assert result.path == "/login"
    assert result.query == "next=home"
    assert result.fragment == "section"


def test_adds_https_for_a_pasted_host() -> None:
    result = normalize_url("login.example.com/account")

    assert result.scheme == "https"
    assert result.normalized_url == "https://login.example.com/account"


def test_decodes_components_once_and_flags_encoded_delimiters() -> None:
    result = normalize_url("https://example.com/%6C%6F%67%69%6E?next=%2Fadmin")

    assert result.path == "/login"
    assert result.query == "next=/admin"
    assert result.has_suspicious_encoding is True
    assert result.normalized_url == "https://example.com/login?next=%2Fadmin"


def test_identifies_ip_host() -> None:
    result = normalize_url("http://192.0.2.10/login")

    assert result.is_ip_host is True
    assert result.hostname == "192.0.2.10"


def test_identifies_ipv6_host() -> None:
    result = normalize_url("https://[2001:db8::10]:8443/login")

    assert result.is_ip_host is True
    assert result.hostname == "2001:db8::10"
    assert result.port == 8443
    assert result.normalized_url == "https://[2001:db8::10]:8443/login"


def test_identifies_punycode() -> None:
    result = normalize_url("https://xn--pple-43d.example/login")

    assert result.is_punycode is True
    assert result.hostname == "xn--pple-43d.example"


def test_at_trick_uses_the_actual_host_after_userinfo() -> None:
    result = normalize_url("https://login.example.com@evil.example/login")

    assert result.hostname == "evil.example"
    assert result.normalized_url == "https://evil.example/login"


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not a url",
        "ftp://example.com/file",
        "https:///missing-host",
        "https://example.com:invalid/",
        "https://example.com/%",
        "https://example.com/\x00",
    ],
)
def test_rejects_malformed_or_unsupported_urls(value: str) -> None:
    with pytest.raises(URLNormalizationError):
        normalize_url(value)


def test_legitimate_login_url_remains_normalized_without_security_labels() -> None:
    result = normalize_url("https://accounts.google.com/signin/v2/identifier")

    assert result.normalized_url == "https://accounts.google.com/signin/v2/identifier"
    assert result.is_ip_host is False
    assert result.is_punycode is False
    assert result.has_suspicious_encoding is False


def test_to_dict_matches_the_future_contract_shape() -> None:
    result = normalize_url("https://example.com")

    assert result.to_dict() == {
        "original_url": "https://example.com",
        "normalized_url": "https://example.com/",
        "scheme": "https",
        "hostname": "example.com",
        "port": None,
        "path": "/",
        "query": "",
        "fragment": "",
        "is_ip_host": False,
        "is_punycode": False,
        "has_suspicious_encoding": False,
    }
