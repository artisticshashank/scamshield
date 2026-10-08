"""FastAPI entrypoint for unified ScamShield scans."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core.scan_service import MLClassifierService, ScanInputError, ScanService
from product_layer import (
    GuestQuotaError,
    IdempotencyError,
    InvalidTokenError,
    ProductStoreError,
    ProductStore,
    verify_bearer,
)
from uuid import uuid4


def guest_cookie_secure() -> bool:
    """Use Secure cookies in production while keeping local HTTP development usable.

    Set SCAMSHIELD_COOKIE_SECURE explicitly when deployment behavior must
    override the SCAMSHIELD_ENV-based default.
    """

    configured = os.getenv("SCAMSHIELD_COOKIE_SECURE")
    if configured is not None:
        return configured.strip().lower() in {"1", "true", "yes", "on"}
    return os.getenv("SCAMSHIELD_ENV", "development").strip().lower() == "production"


class ScanRequest(BaseModel):
    input: str = Field(min_length=1)
    input_type: str = Field(default="auto")
    request_id: str | None = None


_artifact_path = Path(__file__).resolve().parents[2] / "artifacts" / (
    "scamshield_domain_grouped_baseline.pkl"
)
service = ScanService(
    classifier_service=MLClassifierService(artifact_path=_artifact_path)
)
app = FastAPI(title="ScamShield API", version="1.0.0")
store = ProductStore()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://scamshield-theta-seven.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.exception_handler(ScanInputError)
async def scan_input_error(_: Request, exc: ScanInputError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"error": str(exc)})


@app.post("/scan")
async def scan(
    payload: ScanRequest,
    request: Request,
    response: Response,
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    try:
        user_id = verify_bearer(authorization)
    except InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    try:
        service._validate_input(payload.input, payload.input_type)
    except ScanInputError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    quota_enabled = (
        os.getenv("SCAMSHIELD_ENFORCE_GUEST_QUOTA", "").lower() == "true"
        or bool(os.getenv("SUPABASE_URL"))
    )
    request_id = payload.request_id or str(uuid4())
    if user_id:
        result = service.scan(payload.input, payload.input_type).to_dict()
        try:
            existing = store.persist_user(
                user_id, request_id, result, payload.input, payload.input_type
            )
        except IdempotencyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ProductStoreError as exc:
            raise HTTPException(
                status_code=503, detail="Product persistence is unavailable"
            ) from exc
        return existing or result

    if not quota_enabled:
        return service.scan(payload.input, payload.input_type).to_dict()

    guest_id, guest_token, new_cookie = store.guest_for(request.cookies.get("scamshield_guest"))
    try:
        reservation = store.reserve(
            guest_id,
            request_id,
            store.payload_hash(payload.input, payload.input_type),
        )
    except IdempotencyError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except GuestQuotaError as exc:
        raise HTTPException(
            status_code=401,
            detail={"code": "AUTH_REQUIRED", "pending_scan_required": True, "message": str(exc)},
        ) from exc
    except ProductStoreError as exc:
        raise HTTPException(status_code=503, detail="Product persistence is unavailable") from exc
    if reservation.status == "committed" and reservation.result is not None:
        return reservation.result
    try:
        result = service.scan(payload.input, payload.input_type).to_dict()
        committed_result = store.commit(reservation, result)
    except Exception:
        store.rollback(reservation)
        raise
    if new_cookie:
        response.set_cookie(
            "scamshield_guest",
            guest_token,
            httponly=True,
            secure=guest_cookie_secure(),
            samesite="lax",
            max_age=604800,
        )
    return committed_result


@app.get("/history")
async def history(authorization: str | None = Header(default=None)) -> dict[str, object]:
    try:
        user_id = verify_bearer(authorization)
    except InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    return {"items": store.history(user_id)}


@app.get("/health")
async def health() -> dict[str, object]:
    return service.health()
