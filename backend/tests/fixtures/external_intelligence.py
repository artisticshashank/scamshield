"""Offline fixture payloads shared by external-intelligence tests."""

from __future__ import annotations

import json

from core.reputation import HTTPResponse


def http_json(payload: object, status: int = 200) -> HTTPResponse:
    return HTTPResponse(status, json.dumps(payload).encode("utf-8"), {})


REPUTATION_URL = "https://fixture.example/login"

REPUTATION_CASES = {
    "google_confirmed_malicious": http_json(
        {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]}
    ),
    "google_confirmed_clean": http_json({}),
    "phishtank_confirmed_malicious": http_json(
        {"results": {"in_database": True, "valid": True}}
    ),
    "phishtank_confirmed_clean": http_json(
        {"results": {"in_database": False, "valid": False}}
    ),
    "openphish_confirmed_malicious": HTTPResponse(
        200, f"{REPUTATION_URL}\n".encode("utf-8"), {}
    ),
    "openphish_confirmed_clean": HTTPResponse(200, b"", {}),
    "provider_disagreement_clean": HTTPResponse(200, b"", {}),
    "malformed": http_json({"unexpected": True}),
    "provider_error": http_json({}, status=503),
    "rate_limited": http_json({}, status=429),
}
