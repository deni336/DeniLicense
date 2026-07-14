from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from denilicense import auth
from denilicense.api import create_app
from denilicense.config import Settings
from denilicense.crypto import ACTIVATION_RECEIPT_SIGNER, SigningKey
from denilicense.domain import Principal, Product, Role, User
from denilicense.schemas import CreateLicenseRequest


class FastPasswordManager:
    def hash(self, password: str) -> str:
        return "hashed:" + password

    def verify(self, encoded_hash: str, password: str) -> bool:
        return encoded_hash == "hashed:" + password


class FakeStore:
    def __init__(self, principal: Principal | None = None) -> None:
        self.principal = principal
        now = datetime.now(UTC)
        self.products = [Product(uuid4(), "DESKTOP", "Desktop", "", "active", now, now)]

    def ping(self) -> None:
        pass

    def list_products(self, include_retired: bool = False) -> list[Product]:
        del include_retired
        return self.products

    def principal_by_access_hash(self, digest: bytes, now: datetime) -> Principal:
        del digest, now
        if self.principal is None:
            raise RuntimeError("missing test principal")
        return self.principal


def settings(*, origins: tuple[str, ...] = ()) -> Settings:
    secret = b"s" * 32
    return Settings(
        environment="test",
        http_host="127.0.0.1",
        http_port=8080,
        database_url="postgresql://test:test@localhost/test",
        token_pepper=secret,
        device_pepper=b"d" * 32,
        issuance_pepper=b"i" * 32,
        password_pepper=b"",
        access_token_ttl=timedelta(minutes=15),
        refresh_token_ttl=timedelta(days=30),
        verification_ttl=timedelta(minutes=30),
        password_reset_ttl=timedelta(minutes=30),
        activation_lease_ttl=timedelta(hours=24),
        registration_mode="open",
        allowed_origins=origins,
        trusted_proxy_cidrs=(),
        expose_dev_tokens=True,
        public_app_url="http://localhost:3000",
        email_webhook_url="",
        email_webhook_bearer="",
        activation_issuer="test-activation-issuer",
        activation_key_file=Path("activation.key"),
        activation_key_passphrase_file=None,
        activation_verification_key_files=(),
        auto_migrate=False,
        shutdown_timeout=timedelta(seconds=1),
    )


def user_principal(role: Role = Role.CUSTOMER, *, verified: bool = True) -> Principal:
    now = datetime.now(UTC)
    user = User(
        id=uuid4(),
        email="user@example.com",
        role=role,
        status="active",
        email_verified_at=now if verified else None,
        created_at=now,
    )
    return Principal(user, uuid4())


def app(store: FakeStore | None = None, **settings_kwargs: Any) -> Any:
    signer = SigningKey.generate(ACTIVATION_RECEIPT_SIGNER)
    return create_app(
        settings(**settings_kwargs),
        store or FakeStore(),  # type: ignore[arg-type]
        FastPasswordManager(),  # type: ignore[arg-type]
        signer,
    )


def bearer(config: Settings) -> dict[str, str]:
    token = auth.new_token(auth.ACCESS_TOKEN)
    # The fake store accepts every well-formed token; hashing still executes in the dependency.
    auth.hash_token(config.token_pepper, auth.ACCESS_TOKEN, token)
    return {"Authorization": f"Bearer {token}"}


def test_health_public_products_and_security_headers() -> None:
    with TestClient(app()) as client:
        live = client.get("/live")
        products = client.get("/api/v1/products")
    assert live.status_code == 200
    assert live.json() == {"status": "ok"}
    assert len(live.headers["x-request-id"]) == 32
    assert live.headers["x-content-type-options"] == "nosniff"
    assert live.headers["cache-control"] == "no-store"
    assert products.json()["items"][0]["code"] == "DESKTOP"


def test_strict_json_rejects_missing_content_type_duplicates_and_unknown_fields() -> None:
    with TestClient(app()) as client:
        missing = client.post(
            "/api/v1/auth/register",
            content=b'{"email":"u@example.com","password":"long enough password"}',
        )
        duplicate = client.post(
            "/api/v1/auth/register",
            content=b'{"email":"u@example.com","Email":"x@example.com","password":"long enough"}',
            headers={"Content-Type": "application/json"},
        )
        unknown = client.post(
            "/api/v1/auth/register",
            json={"email": "u@example.com", "password": "long enough password", "extra": True},
        )
    for response in (missing, duplicate, unknown):
        assert response.status_code == 400
        assert response.headers["content-type"].startswith("application/problem+json")
        assert response.json()["code"] == "invalid_request"


def test_authentication_email_verification_and_rbac() -> None:
    cfg = settings()
    token_headers = bearer(cfg)
    unverified = FakeStore(user_principal(verified=False))
    customer = FakeStore(user_principal())
    with TestClient(
        create_app(cfg, unverified, FastPasswordManager(), SigningKey.generate(ACTIVATION_RECEIPT_SIGNER))  # type: ignore[arg-type]
    ) as client:
        verification_response = client.get("/api/v1/licenses", headers=token_headers)
    with TestClient(
        create_app(cfg, customer, FastPasswordManager(), SigningKey.generate(ACTIVATION_RECEIPT_SIGNER))  # type: ignore[arg-type]
    ) as client:
        admin_response = client.post(
            "/api/v1/admin/products",
            json={"code": "PRO", "name": "Pro", "description": ""},
            headers=token_headers,
        )
    assert verification_response.status_code == 403
    assert verification_response.json()["code"] == "email_verification_required"
    assert admin_response.status_code == 403
    assert admin_response.json()["code"] == "forbidden"


def test_cors_denies_unknown_origins_and_allows_configured_origin() -> None:
    configured = "https://console.example.com"
    with TestClient(app(origins=(configured,))) as client:
        denied = client.get("/live", headers={"Origin": "https://evil.example"})
        allowed = client.get("/live", headers={"Origin": configured})
        preflight = client.options(
            "/api/v1/auth/login",
            headers={"Origin": configured, "Access-Control-Request-Method": "POST"},
        )
    assert denied.status_code == 403
    assert denied.json()["code"] == "forbidden"
    assert allowed.headers["access-control-allow-origin"] == configured
    assert preflight.status_code == 204
    assert preflight.headers["access-control-allow-origin"] == configured


def test_route_surface_and_jwks_are_complete() -> None:
    service = app()
    paths = {route.path for route in service.routes}
    expected = {
        "/api/v1/auth/register",
        "/api/v1/auth/verify-email",
        "/api/v1/auth/verification/request",
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
        "/api/v1/auth/password-reset/request",
        "/api/v1/auth/password-reset/confirm",
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/v1/licenses/claim",
        "/api/v1/licenses",
        "/api/v1/licenses/{license_id}",
        "/api/v1/licenses/{license_id}/activations",
        "/api/v1/activations/{activation_id}",
        "/api/v1/activation-challenges",
        "/api/v1/activation-challenges/complete",
        "/api/v1/admin/licenses",
        "/api/v1/admin/licenses/import",
        "/api/v1/admin/audit-events",
    }
    assert expected <= paths
    with TestClient(service) as client:
        response = client.get("/.well-known/denilicense-activation-keys.json")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=300"
    assert response.json()["keys"][0]["kty"] == "OKP"


def test_request_timestamps_are_strict_rfc3339_strings() -> None:
    request = CreateLicenseRequest.model_validate(
        {
            "productCode": "DESKTOP",
            "expiresAt": "2026-07-13T12:34:56.123456Z",
            "maxActivations": 1,
            "entitlements": {},
        }
    )
    assert request.expires_at == datetime(2026, 7, 13, 12, 34, 56, 123456, tzinfo=UTC)
    for invalid in (1_720_000_000, "2026-07-13 12:34:56Z", "2026-07-13T12:34:56"):
        with pytest.raises(ValidationError):
            CreateLicenseRequest.model_validate(
                {
                    "productCode": "DESKTOP",
                    "expiresAt": invalid,
                    "maxActivations": 1,
                    "entitlements": {},
                }
            )
