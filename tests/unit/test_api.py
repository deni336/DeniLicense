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
from denilicense.domain import AccountSession, Principal, Product, Role, User, UserCredential
from denilicense.schemas import (
    ApproveLicenseRequest,
    CreateCustomerLicenseRequest,
    CreateLicenseRequest,
    DeleteLicenseRequest,
)


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


class AccountSecurityStore(FakeStore):
    def __init__(self, role: Role = Role.CUSTOMER) -> None:
        super().__init__(user_principal(role))
        now = datetime.now(UTC)
        self.other_session_id = uuid4()
        self.sessions = [
            AccountSession(
                self.principal.session_id,
                now - timedelta(hours=2),
                now - timedelta(minutes=1),
                now + timedelta(minutes=14),
                now + timedelta(days=30),
            ),
            AccountSession(
                self.other_session_id,
                now - timedelta(days=1),
                now - timedelta(hours=1),
                now + timedelta(minutes=5),
                now + timedelta(days=29),
            ),
        ]
        self.changed_password: tuple[Any, ...] | None = None
        self.revoked_session: tuple[Any, ...] | None = None
        self.revoked_others: tuple[Any, ...] | None = None
        self.product_update: tuple[Any, ...] | None = None

    def user_credential_by_id(self, user_id: Any) -> UserCredential:
        assert user_id == self.principal.user.id
        return UserCredential(self.principal.user, "hashed:current password value")

    def change_password(self, *args: Any) -> None:
        self.changed_password = args

    def list_account_sessions(self, user_id: Any, _now: datetime) -> list[AccountSession]:
        assert user_id == self.principal.user.id
        return self.sessions

    def revoke_user_session(self, *args: Any) -> None:
        self.revoked_session = args

    def revoke_other_user_sessions(self, *args: Any) -> int:
        self.revoked_others = args
        return 1

    def update_product_status(self, *args: Any) -> Product:
        self.product_update = args
        current = self.products[0]
        return Product(
            current.id,
            current.code,
            current.name,
            current.description,
            args[1],
            current.created_at,
            datetime.now(UTC),
            revision=args[3] + 1,
        )


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
        public_config = client.get("/api/v1/public/config")
    assert live.status_code == 200
    assert live.json() == {"status": "ok"}
    assert len(live.headers["x-request-id"]) == 32
    assert live.headers["x-content-type-options"] == "nosniff"
    assert live.headers["cache-control"] == "no-store"
    assert products.json()["items"][0]["code"] == "DESKTOP"
    assert public_config.json() == {"registrationOpen": True, "passwordMinCharacters": 15}
    assert public_config.headers["cache-control"] == "public, max-age=60"


def test_entitlement_guide_is_available_without_authentication() -> None:
    with TestClient(app()) as client:
        response = client.get("/docs/entitlements")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert response.headers["cache-control"] == "public, max-age=300"
    assert "# License entitlements" in response.text


def test_protected_routes_issue_a_bearer_challenge() -> None:
    with TestClient(app()) as client:
        response = client.get("/api/v1/auth/me")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_strict_json_rejects_missing_content_type_duplicates_and_unknown_fields() -> None:
    with TestClient(app()) as client:
        missing = client.post(
            "/api/v1/auth/register",
            content=b'{"email":"u@example.com"}',
        )
        duplicate = client.post(
            "/api/v1/auth/register",
            content=b'{"email":"u@example.com","Email":"x@example.com"}',
            headers={"Content-Type": "application/json"},
        )
        unknown = client.post(
            "/api/v1/auth/register",
            json={"email": "u@example.com", "password": "attacker selected password"},
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


def test_account_can_change_password_and_manage_its_sessions() -> None:
    cfg = settings()
    headers = bearer(cfg)
    store = AccountSecurityStore()

    with TestClient(app(store)) as client:
        sessions = client.get("/api/v1/auth/sessions", headers=headers)
        wrong_password = client.post(
            "/api/v1/auth/password/change",
            json={"currentPassword": "wrong password value", "newPassword": "new password value 123"},
            headers=headers,
        )
        changed = client.post(
            "/api/v1/auth/password/change",
            json={
                "currentPassword": "current password value",
                "newPassword": "new password value 123",
            },
            headers=headers,
        )
        revoked_others = client.post(
            "/api/v1/auth/sessions/revoke-others",
            headers=headers,
        )
        revoked = client.delete(
            f"/api/v1/auth/sessions/{store.other_session_id}",
            headers=headers,
        )

    assert sessions.status_code == 200
    assert [item["isCurrent"] for item in sessions.json()["items"]] == [True, False]
    assert wrong_password.status_code == 400
    assert changed.status_code == revoked_others.status_code == revoked.status_code == 204
    assert store.changed_password is not None
    assert store.changed_password[0:4] == (
        store.principal.user.id,
        store.principal.session_id,
        "hashed:current password value",
        "hashed:new password value 123",
    )
    assert store.revoked_others is not None
    assert store.revoked_others[0:2] == (store.principal.user.id, store.principal.session_id)
    assert store.revoked_session is not None
    assert store.revoked_session[0:2] == (store.principal.user.id, store.other_session_id)


def test_product_status_change_requires_revision_and_normalizes_code() -> None:
    cfg = settings()
    headers = bearer(cfg)
    store = AccountSecurityStore(Role.PLATFORM_OWNER)

    with TestClient(app(store)) as client:
        missing_revision = client.post(
            "/api/v1/admin/products/desktop/status",
            json={"status": "retired"},
            headers=headers,
        )
        retired = client.post(
            "/api/v1/admin/products/desktop/status",
            json={"status": "retired", "expectedRevision": 1},
            headers=headers,
        )

    assert missing_revision.status_code == 400
    assert retired.status_code == 200
    assert retired.json()["product"]["status"] == "retired"
    assert retired.json()["product"]["revision"] == 2
    assert store.product_update is not None
    assert store.product_update[0:4] == ("DESKTOP", "retired", store.principal.user.id, 1)


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
        "/api/v1/public/config",
        "/api/v1/auth/verify-email",
        "/api/v1/auth/verification/request",
        "/api/v1/auth/login",
        "/api/v1/auth/refresh",
        "/api/v1/auth/password-reset/request",
        "/api/v1/auth/password-reset/confirm",
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/v1/auth/password/change",
        "/api/v1/auth/sessions",
        "/api/v1/auth/sessions/revoke-others",
        "/api/v1/auth/sessions/{session_id}",
        "/api/v1/licenses/claim",
        "/api/v1/license-requests",
        "/api/v1/license-requests/{request_id}",
        "/api/v1/license-requests/{request_id}/cancel",
        "/api/v1/licenses",
        "/api/v1/licenses/{license_id}",
        "/api/v1/licenses/{license_id}/activations",
        "/api/v1/activations/{activation_id}",
        "/api/v1/activation-challenges",
        "/api/v1/activation-challenges/complete",
        "/api/v1/admin/licenses",
        "/api/v1/admin/licenses/import",
        "/api/v1/admin/license-requests",
        "/api/v1/admin/license-requests/{request_id}",
        "/api/v1/admin/license-requests/{request_id}/approve",
        "/api/v1/admin/license-requests/{request_id}/deny",
        "/api/v1/admin/licenses/{license_id}/archive",
        "/api/v1/admin/licenses/{license_id}/restore",
        "/api/v1/admin/licenses/{license_id}/delete",
        "/api/v1/admin/users/{user_id}/archive",
        "/api/v1/admin/users/{user_id}/restore",
        "/api/v1/admin/users/{user_id}/delete",
        "/api/v1/admin/users/{user_id}/invitation/resend",
        "/api/v1/admin/products/{product_code}/status",
        "/api/v1/admin/audit-events",
    }
    assert expected <= paths
    with TestClient(service) as client:
        response = client.get("/.well-known/denilicense-activation-keys.json")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "public, max-age=300"
    assert response.json()["keys"][0]["kty"] == "OKP"


def test_openapi_declares_bearer_security_only_for_protected_routes() -> None:
    schema = app().openapi()

    bearer = schema["components"]["securitySchemes"]["BearerAuth"]
    assert bearer["type"] == "http"
    assert bearer["scheme"] == "bearer"
    assert "security" not in schema["paths"]["/api/v1/products"]["get"]
    assert schema["paths"]["/api/v1/auth/sessions"]["get"]["security"] == [{"BearerAuth": []}]


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


def test_license_request_and_lifecycle_schemas_are_strict() -> None:
    requested = CreateCustomerLicenseRequest.model_validate(
        {
            "productCode": "DESKTOP",
            "requestedActivations": 3,
            "message": "  Three engineering workstations.  ",
        }
    )
    assert requested.message == "Three engineering workstations."
    approval = ApproveLicenseRequest.model_validate(
        {
            "maxActivations": 3,
            "perpetual": True,
            "entitlements": {"feature.reporting": True, "limits.projects": 100},
        }
    )
    assert approval.entitlements["feature.reporting"] is True

    for payload in (
        {"productCode": "DESKTOP", "requestedActivations": "3", "message": ""},
        {"productCode": "DESKTOP", "requestedActivations": 3, "message": "bad\x00note"},
        {"productCode": "DESKTOP", "requestedActivations": 3, "message": "", "role": "owner"},
    ):
        with pytest.raises(ValidationError):
            CreateCustomerLicenseRequest.model_validate(payload)

    with pytest.raises(ValidationError):
        DeleteLicenseRequest.model_validate({"serial": str(uuid4()), "expectedRevision": "1"})

    for entitlements in (
        {"plan": "😀" * 1_025},
        {"plan": "safe\u202etext"},
        {f"feature.value_{index}": "x" * 3_500 for index in range(4)},
    ):
        with pytest.raises(ValidationError):
            ApproveLicenseRequest.model_validate(
                {
                    "maxActivations": 1,
                    "perpetual": True,
                    "entitlements": entitlements,
                }
            )
