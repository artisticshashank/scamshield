import json
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from api import app as api_module
from core.message_scanning import ExtractionLimits
from core.redirect_analysis import RedirectResponse
from core.reputation import ReputationResult, ReputationStatus
from core.risk_fusion import SignalStatus
from core.scan_service import MLClassifierService, ScanInputError, ScanService, ServiceLimits


class FakeRedirect:
    def resolve(self, url: str):
        class Result:
            status = "completed"
            risk_score = 12.0

            def to_dict(self):
                return {
                    "status": self.status,
                    "original_url": url,
                    "final_url": url,
                    "risk_score": self.risk_score,
                    "chain": [],
                }

        return Result()


@dataclass
class FakeDomain:
    risk_score: float = 8.0
    status: str = "available"

    def to_dict(self):
        return {"status": self.status, "hostname": "example.com", "risk_score": self.risk_score}


class FakeProvider:
    name = "fake"

    def check(self, url: str):
        return ReputationResult(
            provider=self.name,
            status=ReputationStatus.AVAILABLE,
            queried_url=url,
            is_malicious=False,
        )


def make_service(**kwargs) -> ScanService:
    return ScanService(
        classifier_service=MLClassifierService(),
        domain_collector=lambda _: FakeDomain(),
        redirect_resolver=FakeRedirect(),
        **kwargs,
    )


def test_url_scan_uses_shared_pipeline_and_explicit_unavailable_components() -> None:
    result = make_service().scan("https://example.com/login", "url")
    serialized = result.to_dict()

    json.dumps(serialized)
    assert result.input_type == "url"
    assert result.ml_result.status == SignalStatus.UNAVAILABLE
    assert result.shap_result.status == SignalStatus.UNAVAILABLE
    assert result.reputation_result.status == SignalStatus.UNAVAILABLE
    assert result.domain_intelligence_result.status == SignalStatus.AVAILABLE
    assert result.redirect_result.status == SignalStatus.AVAILABLE


def test_configured_reputation_is_included_without_exposing_provider_objects() -> None:
    result = make_service(reputation_providers=[FakeProvider()]).scan(
        "https://example.com", "url"
    )

    assert result.reputation_result.status == SignalStatus.AVAILABLE
    assert result.reputation_result.score == 0
    assert "fake" in result.reputation_result.value["provider_results"][0]["provider"]


def test_message_scans_each_url_deduplicated_and_uses_maximum_risk() -> None:
    result = make_service().scan(
        "Visit https://example.com/a, https://example.com/b and https://example.com/a.",
        "message",
    )

    assert result.extracted_urls == ["https://example.com/a", "https://example.com/b"]
    assert len(result.scan_results) == 2
    assert result.overall_risk_score == max(scan.risk_score for scan in result.scan_results)


def test_message_without_urls_is_not_safe() -> None:
    result = make_service().scan("Your account is locked.", "message")

    assert result.overall_verdict == "NO_URL"
    assert result.overall_risk_score is None


def test_auto_selects_url_or_message() -> None:
    service = make_service()
    assert service.scan("https://example.com", "auto").input_type == "url"
    assert service.scan("See https://example.com", "auto").input_type == "message"


@pytest.mark.parametrize(
    "value",
    ["", "   "],
)
def test_invalid_input_is_rejected(value: str) -> None:
    with pytest.raises(ScanInputError):
        make_service().scan(value)


def test_limits_and_input_type_are_enforced() -> None:
    service = make_service(
        limits=ServiceLimits(
            max_input_length=10,
            extraction=ExtractionLimits(max_message_length=10),
        )
    )
    with pytest.raises(ScanInputError):
        service.scan("https://example.com")
    with pytest.raises(ScanInputError):
        make_service().scan("https://example.com", "invalid")


def test_api_scan_health_validation_and_no_network_controls() -> None:
    original = api_module.service
    api_module.service = make_service()
    try:
        client = TestClient(api_module.app)
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["components"]["ml"] == "unavailable"

        response = client.post("/scan", json={"input": "https://example.com", "input_type": "url"})
        assert response.status_code == 200
        assert response.json()["input_type"] == "url"

        message = client.post(
            "/scan",
            json={"input": "Visit https://example.com/login", "input_type": "message"},
        )
        assert message.status_code == 200
        assert message.json()["overall_verdict"] != "NO_URL"

        assert client.post("/scan", json={"input": ""}).status_code == 422
        assert client.post("/scan", json={"input": "https://example.com", "input_type": "bad"}).status_code == 422
        assert client.post(
            "/scan",
            json={"input": "https://example.com", "proxy": "http://internal"},
        ).status_code == 200
        assert "proxy" not in client.post(
            "/scan", json={"input": "https://example.com"}
        ).json()
        assert client.post("/scan", content="{not-json").status_code == 422
    finally:
        api_module.service = original


def test_api_rejects_oversized_input() -> None:
    original = api_module.service
    api_module.service = make_service(
        limits=ServiceLimits(max_input_length=5)
    )
    try:
        response = TestClient(api_module.app).post(
            "/scan", json={"input": "https://example.com"}
        )
        assert response.status_code == 422
    finally:
        api_module.service = original


def test_api_scan_cors_preflight_is_allowed() -> None:
    response = TestClient(api_module.app).options(
        "/scan",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "POST" in response.headers["access-control-allow-methods"]
    assert "content-type" in response.headers["access-control-allow-headers"].lower()


def test_guest_cookie_secure_flag_is_environment_aware(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCAMSHIELD_COOKIE_SECURE", raising=False)
    monkeypatch.setenv("SCAMSHIELD_ENV", "development")
    assert api_module.guest_cookie_secure() is False
    monkeypatch.setenv("SCAMSHIELD_ENV", "production")
    assert api_module.guest_cookie_secure() is True


def test_authenticated_request_id_reuse_with_different_payload_returns_409(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_service = api_module.service
    original_store = api_module.store
    original_verify = api_module.verify_bearer
    api_module.service = make_service()
    api_module.store = api_module.ProductStore()
    api_module.verify_bearer = lambda _: "00000000-0000-0000-0000-000000000001"
    try:
        client = TestClient(api_module.app)
        first = client.post(
            "/scan",
            headers={"Authorization": "Bearer valid"},
            json={"input": "https://first.example", "input_type": "url", "request_id": "00000000-0000-0000-0000-000000000010"},
        )
        assert first.status_code == 200
        retry = client.post(
            "/scan",
            headers={"Authorization": "Bearer valid"},
            json={"input": "https://first.example", "input_type": "url", "request_id": "00000000-0000-0000-0000-000000000010"},
        )
        assert retry.status_code == 200
        assert retry.json() == first.json()
        conflict = client.post(
            "/scan",
            headers={"Authorization": "Bearer valid"},
            json={"input": "https://second.example", "input_type": "url", "request_id": "00000000-0000-0000-0000-000000000010"},
        )
        assert conflict.status_code == 409
    finally:
        api_module.service = original_service
        api_module.store = original_store
        api_module.verify_bearer = original_verify
