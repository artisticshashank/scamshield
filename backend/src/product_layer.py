"""Product-layer authentication, durable persistence, and guest quota.

The detection engine is deliberately not imported here except through its
public ScanResult contract.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import httpx

try:
    import jwt
except ImportError:  # pragma: no cover - optional until auth is configured
    jwt = None


GUEST_LIMIT = int(os.getenv("SCAMSHIELD_GUEST_SCAN_LIMIT", "2"))
GUEST_TTL = int(os.getenv("SCAMSHIELD_GUEST_TTL_SECONDS", "604800"))
GUEST_RESULT_TTL = int(os.getenv("SCAMSHIELD_GUEST_RESULT_TTL_SECONDS", "86400"))


class InvalidTokenError(ValueError):
    pass


class GuestQuotaError(ValueError):
    pass


class IdempotencyError(ValueError):
    pass


class ProductStoreError(RuntimeError):
    pass


@dataclass
class Reservation:
    guest_id: str
    request_id: str
    payload_hash: str
    status: str = "reserved"
    result: dict[str, object] | None = None


class SupabaseRepository:
    """Supabase REST/PostgREST repository.

    All calls use the server-only service-role key. Atomic quota transitions
    are implemented by PostgreSQL functions in the product migration.
    """

    def __init__(self, url: str, service_role_key: str) -> None:
        self.base_url = url.rstrip("/")
        self.client = httpx.Client(
            base_url=f"{self.base_url}/rest/v1",
            headers={
                "apikey": service_role_key,
                "Authorization": f"Bearer {service_role_key}",
                "Content-Type": "application/json",
            },
            timeout=10.0,
        )

    @staticmethod
    def payload_hash(input_value: str, input_type: str) -> str:
        return hashlib.sha256(f"{input_type}\0{input_value}".encode()).hexdigest()

    def _rpc(self, name: str, payload: dict[str, object]) -> object:
        response = self.client.post(f"/rpc/{name}", json=payload)
        if response.status_code >= 400:
            detail = response.json() if response.content else response.text
            message = str(detail)
            if "P0001" in message or "Authentication required" in message:
                raise GuestQuotaError("Authentication required to continue scanning")
            if "P0002" in message or "different input" in message:
                raise IdempotencyError("request_id was reused with different input")
            raise ProductStoreError(message)
        return response.json()

    def guest_for(self, token: str | None) -> tuple[str, str, bool]:
        token_hash = hashlib.sha256(token.encode()).hexdigest() if token else None
        if token_hash:
            response = self.client.get(
                "/guest_sessions",
                params={"select": "id,expires_at", "token_hash": f"eq.{token_hash}", "limit": "1"},
            )
            response.raise_for_status()
            rows = response.json()
            if rows and datetime.fromisoformat(rows[0]["expires_at"].replace("Z", "+00:00")) > datetime.now(timezone.utc):
                return str(rows[0]["id"]), token, False

        raw = secrets.token_urlsafe(32)
        response = self.client.post(
            "/guest_sessions",
            json={
                "token_hash": hashlib.sha256(raw.encode()).hexdigest(),
                "scan_limit": GUEST_LIMIT,
                "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=GUEST_TTL)).isoformat(),
            },
            headers={"Prefer": "return=representation"},
        )
        response.raise_for_status()
        return str(response.json()[0]["id"]), raw, True

    def reserve(self, guest_id: str, request_id: str, payload_hash: str) -> Reservation:
        try:
            data = self._rpc(
                "reserve_guest_scan",
                {
                    "p_guest_session_id": guest_id,
                    "p_request_id": request_id,
                    "p_payload_hash": payload_hash,
                    "p_scan_limit": GUEST_LIMIT,
                    "p_retention_seconds": GUEST_RESULT_TTL,
                    "p_lease_seconds": 120,
                },
            )
        except GuestQuotaError:
            raise
        return Reservation(
            guest_id=guest_id,
            request_id=request_id,
            payload_hash=payload_hash,
            status=str(data["status"]),
            result=data.get("result_json"),
        )

    def commit(self, reservation: Reservation, result: dict[str, object]) -> dict[str, object]:
        data = self._rpc(
            "commit_guest_scan",
            {
                "p_guest_session_id": reservation.guest_id,
                "p_request_id": reservation.request_id,
                "p_result": result,
            },
        )
        return data if isinstance(data, dict) else result

    def rollback(self, reservation: Reservation) -> None:
        self._rpc(
            "rollback_guest_scan",
            {
                "p_guest_session_id": reservation.guest_id,
                "p_request_id": reservation.request_id,
            },
        )

    def persist_user(
        self,
        user_id: str,
        request_id: str,
        result: dict[str, object],
        input_value: str = "",
        input_type: str = "auto",
    ) -> dict[str, object] | None:
        payload_hash = self.payload_hash(input_value, input_type)
        existing = self.client.get(
            "/scans",
            params={"select": "response_json,payload_hash", "user_id": f"eq.{user_id}", "request_id": f"eq.{request_id}", "limit": "1"},
        )
        existing.raise_for_status()
        existing_rows = existing.json()
        if existing_rows:
            if existing_rows[0]["payload_hash"] != payload_hash:
                raise IdempotencyError("request_id was reused with different input")
            return existing_rows[0]["response_json"]
        scan_id = str(result.get("scan_id") or uuid4())
        risk = result.get("risk_score", result.get("overall_risk_score"))
        verdict = str(result.get("verdict", result.get("overall_verdict", "NO_URL")))
        scan_payload = {
            "id": scan_id,
            "user_id": user_id,
            "request_id": request_id,
            "payload_hash": payload_hash,
            "input_type": input_type,
            "original_input": input_value,
            "verdict": verdict,
            "risk_score": float(risk or 0),
            "response_json": result,
        }
        response = self.client.post(
            "/scans",
            params={"on_conflict": "user_id,request_id"},
            json=scan_payload,
            headers={"Prefer": "resolution=ignore-duplicates,return=representation"},
        )
        response.raise_for_status()
        if not response.json():
            return self.persist_user(user_id, request_id, result, input_value, input_type)
        urls = result.get("scan_results") if isinstance(result.get("scan_results"), list) else [result]
        rows = []
        for position, item in enumerate(urls):
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "scan_id": scan_id,
                    "position": position,
                    "original_url": str(item.get("original_input", "")),
                    "normalized_url": (item.get("normalized_urls") or [{}])[0].get("normalized_url")
                    if isinstance(item.get("normalized_urls"), list)
                    else None,
                    "verdict": str(item.get("verdict", verdict)),
                    "risk_score": float(item.get("risk_score", risk or 0)),
                    "result_json": item,
                }
            )
        if rows:
            child_response = self.client.post("/scan_urls", json=rows)
            child_response.raise_for_status()
        return None

    def history(self, user_id: str) -> list[dict[str, object]]:
        response = self.client.get(
            "/scans",
            params={"select": "id,request_id,response_json,created_at", "user_id": f"eq.{user_id}", "order": "created_at.desc"},
        )
        response.raise_for_status()
        return [
            {"id": row["id"], "request_id": row["request_id"], "response": row["response_json"], "saved_at": row["created_at"]}
            for row in response.json()
        ]


class _MemoryProductStore:
    """Test/development fallback when no Supabase server configuration exists."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.guests: dict[str, dict[str, object]] = {}
        self.reservations: dict[tuple[str, str], Reservation] = {}
        self.user_scans: dict[str, list[dict[str, object]]] = {}

    @staticmethod
    def payload_hash(input_value: str, input_type: str) -> str:
        return hashlib.sha256(f"{input_type}\0{input_value}".encode()).hexdigest()

    def guest_for(self, token: str | None) -> tuple[str, str, bool]:
        with self._lock:
            if token:
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                for guest_id, guest in self.guests.items():
                    if guest["token_hash"] == token_hash and guest["expires_at"] > datetime.now(timezone.utc):
                        return guest_id, token, False
            raw = secrets.token_urlsafe(32)
            guest_id = str(uuid4())
            self.guests[guest_id] = {
                "token_hash": hashlib.sha256(raw.encode()).hexdigest(),
                "expires_at": datetime.now(timezone.utc) + timedelta(seconds=GUEST_TTL),
                "committed": 0,
            }
            return guest_id, raw, True

    def reserve(self, guest_id: str, request_id: str, payload_hash: str) -> Reservation:
        with self._lock:
            key = (guest_id, request_id)
            existing = self.reservations.get(key)
            if existing:
                if existing.payload_hash != payload_hash:
                    raise IdempotencyError("request_id was reused with different input")
                if existing.status == "committed":
                    return existing
                if existing.status in {"reserved", "processing"}:
                    return existing
            guest = self.guests[guest_id]
            active = sum(
                r.status in {"reserved", "processing"} and r.guest_id == guest_id
                for r in self.reservations.values()
            )
            if int(guest["committed"]) + active >= GUEST_LIMIT:
                raise GuestQuotaError("Authentication required to continue scanning")
            reservation = Reservation(guest_id, request_id, payload_hash)
            self.reservations[key] = reservation
            return reservation

    def commit(self, reservation: Reservation, result: dict[str, object]) -> dict[str, object]:
        with self._lock:
            current = self.reservations[(reservation.guest_id, reservation.request_id)]
            if current.status == "committed":
                return current.result or result
            current.status = "committed"
            current.result = result
            self.guests[current.guest_id]["committed"] = int(self.guests[current.guest_id]["committed"]) + 1
            return result

    def rollback(self, reservation: Reservation) -> None:
        with self._lock:
            current = self.reservations.get((reservation.guest_id, reservation.request_id))
            if current and current.status != "committed":
                current.status = "rolled_back"

    def persist_user(
        self,
        user_id: str,
        request_id: str,
        result: dict[str, object],
        input_value: str = "",
        input_type: str = "auto",
    ) -> dict[str, object] | None:
        with self._lock:
            records = self.user_scans.setdefault(user_id, [])
            existing = next((item for item in records if item["request_id"] == request_id), None)
            if existing:
                if existing["payload_hash"] != self.payload_hash(input_value, input_type):
                    raise IdempotencyError("request_id was reused with different input")
                return existing["response"]
            records.append(
                {
                    "request_id": request_id,
                    "payload_hash": self.payload_hash(input_value, input_type),
                    "response": result,
                }
            )
            return None

    def history(self, user_id: str) -> list[dict[str, object]]:
        with self._lock:
            return list(reversed(self.user_scans.get(user_id, [])))


class ProductStore:
    """Durable store in configured environments, memory adapter otherwise."""

    def __init__(self) -> None:
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        self._store = SupabaseRepository(url, key) if url and key else _MemoryProductStore()

    @staticmethod
    def payload_hash(input_value: str, input_type: str) -> str:
        return hashlib.sha256(f"{input_type}\0{input_value}".encode()).hexdigest()

    def __getattr__(self, name: str):
        return getattr(self._store, name)


def verify_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    if not authorization.startswith("Bearer "):
        raise InvalidTokenError("Invalid authorization header")
    token = authorization[7:].strip()
    if jwt is None:
        raise InvalidTokenError("Authentication is not configured")
    try:
        secret = os.getenv("SUPABASE_JWT_SECRET")
        if secret:
            claims = jwt.decode(token, secret, algorithms=["HS256"], audience=os.getenv("SUPABASE_JWT_AUDIENCE", "authenticated"), issuer=os.getenv("SUPABASE_JWT_ISSUER"))
        else:
            jwks_url = os.getenv("SUPABASE_JWKS_URL")
            if not jwks_url and os.getenv("SUPABASE_URL"):
                jwks_url = f"{os.environ['SUPABASE_URL'].rstrip('/')}/auth/v1/.well-known/jwks.json"
            if not jwks_url:
                raise InvalidTokenError("Authentication is not configured")
            key = jwt.PyJWKClient(jwks_url).get_signing_key_from_jwt(token).key
            claims = jwt.decode(token, key, algorithms=["RS256", "ES256"], audience=os.getenv("SUPABASE_JWT_AUDIENCE", "authenticated"), issuer=os.getenv("SUPABASE_JWT_ISSUER"))
        subject = claims.get("sub")
        if not isinstance(subject, str):
            raise InvalidTokenError("Token subject is missing")
        UUID(subject)
        return subject
    except Exception as exc:
        raise InvalidTokenError("Invalid or expired access token") from exc
