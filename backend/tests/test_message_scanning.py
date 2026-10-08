import json
from types import SimpleNamespace

import pytest

from core.message_scanning import (
    ExtractionLimits,
    MessageScanError,
    extract_urls,
    scan_message,
    scan_url,
)
from core.ml_classifier import URLClassifier, URLRecord
from core.risk_fusion import SignalStatus


def test_extracts_single_http_and_https_url() -> None:
    message = "Visit http://example.com and https://secure.example.com/login"

    assert extract_urls(message) == [
        "http://example.com",
        "https://secure.example.com/login",
    ]


@pytest.mark.parametrize(
    "message",
    [
        "(https://example.com/path)",
        "[https://example.com/path]",
        '"https://example.com/path"',
        "https://example.com/path,",
        "https://example.com/path.",
        "https://example.com/path!?",
    ],
)
def test_trims_wrackets_quotes_and_trailing_punctuation(message: str) -> None:
    assert extract_urls(message) == ["https://example.com/path"]


def test_extracts_multiple_urls_deduplicates_and_preserves_order() -> None:
    message = (
        "A https://one.example/a, B https://two.example/b; "
        "again https://one.example/a."
    )

    assert extract_urls(message) == [
        "https://one.example/a",
        "https://two.example/b",
    ]


def test_extraction_does_not_normalize_or_extract_arbitrary_text() -> None:
    assert extract_urls("example.com and www.example.com only") == []
    assert extract_urls("example.com/path") == []
    assert extract_urls(" HTTP://EXAMPLE.COM/Path ") == ["HTTP://EXAMPLE.COM/Path"]


def test_malformed_url_is_extracted_as_input_but_normalization_stays_separate() -> None:
    extracted = extract_urls("Broken: https:///missing-host")

    assert extracted == ["https:///missing-host"]
    with pytest.raises(ValueError):
        scan_message("Broken: https:///missing-host")


def test_no_url_message_has_explicit_no_url_state() -> None:
    result = scan_message("Your account has no link. Call support.")

    assert result.extracted_urls == []
    assert result.scan_results == []
    assert result.overall_verdict == "no_url_detected"
    assert result.overall_risk_score is None


def test_empty_and_unicode_messages_are_supported() -> None:
    assert scan_message("").overall_verdict == "no_url_detected"
    assert scan_message("नमस्ते — सुरक्षित संदेश").overall_verdict == "no_url_detected"
    assert scan_message("   ").overall_verdict == "no_url_detected"


def test_limits_reject_pathologically_large_messages_and_url_counts() -> None:
    with pytest.raises(MessageScanError):
        extract_urls("x" * 11, limits=ExtractionLimits(max_message_length=10))
    with pytest.raises(MessageScanError):
        extract_urls(
            "https://a.example https://b.example",
            limits=ExtractionLimits(max_urls=1),
        )


def test_overlong_url_is_not_returned() -> None:
    result = extract_urls(
        "https://example.com/" + ("x" * 20),
        limits=ExtractionLimits(max_url_length=10),
    )

    assert result == []


def test_message_scans_urls_independently_and_uses_highest_risk() -> None:
    records = [
        URLRecord("https://example.com/about", 0),
        URLRecord("https://safe.example.org/home", 0),
        URLRecord("http://secure-login.invalid/account", 1),
        URLRecord("http://verify-payment.invalid/card", 1),
    ]
    model = URLClassifier.fit(records)
    message = "Try https://example.com/about then http://secure-login.invalid/account"

    result = scan_message(message, classifier=model)

    assert result.extracted_urls == [
        "https://example.com/about",
        "http://secure-login.invalid/account",
    ]
    assert len(result.scan_results) == 2
    assert result.overall_risk_score == max(
        scan.risk_score for scan in result.scan_results
    )
    assert result.overall_verdict == max(
        result.scan_results, key=lambda scan: scan.risk_score
    ).verdict


@pytest.mark.parametrize(
    ("verdicts", "scores", "expected_verdict", "expected_score"),
    [
        (["SAFE", "SUSPICIOUS"], [1.4, 53.6], "SUSPICIOUS", 53.6),
        (["SAFE", "SUSPICIOUS", "DANGEROUS"], [1.4, 53.6, 91.2], "DANGEROUS", 91.2),
    ],
)
def test_message_aggregation_preserves_all_results_and_highest_severity(
    monkeypatch: pytest.MonkeyPatch,
    verdicts: list[str],
    scores: list[float],
    expected_verdict: str,
    expected_score: float,
) -> None:
    fake_results = iter(
        SimpleNamespace(risk_score=score, verdict=verdict, recommendation=f"{verdict} recommendation")
        for score, verdict in zip(scores, verdicts)
    )
    monkeypatch.setattr(
        "core.message_scanning.build_scan_result",
        lambda *args, **kwargs: next(fake_results),
    )

    result = scan_message(
        " ".join(f"https://example{index}.com" for index in range(len(scores)))
    )

    assert len(result.scan_results) == len(scores)
    assert [scan.risk_score for scan in result.scan_results] == scores
    assert result.overall_verdict == expected_verdict
    assert result.overall_risk_score == expected_score


def test_legitimate_and_suspicious_sms_examples() -> None:
    legitimate = scan_message(
        "Our help page is https://www.example.com/help. Thank you."
    )
    suspicious = scan_message(
        "URGENT! Verify now: (http://192.0.2.10/login)."
    )

    assert legitimate.scan_results[0].input_type == "url"
    assert suspicious.scan_results[0].risk_score > legitimate.scan_results[0].risk_score


def test_message_result_is_json_serializable_and_future_states_are_explicit() -> None:
    result = scan_message("See https://example.com/help")
    serialized = result.to_dict()

    json.dumps(serialized)
    scan = result.scan_results[0]
    assert scan.reputation_result.status == SignalStatus.NOT_IMPLEMENTED
    assert scan.domain_intelligence_result.status == SignalStatus.NOT_IMPLEMENTED
    assert scan.redirect_result.status == SignalStatus.NOT_IMPLEMENTED


def test_single_url_wrapper_preserves_scan_result_contract() -> None:
    result = scan_url("https://example.com/help")

    assert result.input_type == "url"
    assert result.normalized_urls[0]["normalized_url"] == "https://example.com/help"


def test_no_url_scanning_does_not_make_network_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access is forbidden in message scanning")

    monkeypatch.setattr("socket.create_connection", fail_network)
    result = scan_message("https://example.com")

    assert result.scan_results[0].risk_score >= 0
