from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from denilicense import auth
from denilicense.api import create_app
from denilicense.config import Settings
from denilicense.domain import ConflictError, Principal, Role, User
from denilicense.store import CreateManagedUserParams, UpdateUserAccessParams


class RecordingPasswordManager:
    def __init__(self) -> None:
        self.plaintexts: list[str] = []

    def hash(self, password: str) -> str:
        self.plaintexts.append(password)
        return f"hashed:{password}"

    def verify(self, encoded_hash: str, password: str) -> bool:
        return encoded_hash == f"hashed:{password}"


class AdminStore:
    def __init__(self, role: Role = Role.PLATFORM_OWNER, *, verified: bool = True) -> None:
        now = datetime.now(UTC)
        self.principal = Principal(
            User(
                id=uuid4(),
                email="actor@example.com",
                role=role,
                status="active",
                email_verified_at=now if verified else None,
                created_at=now,
            ),
            uuid4(),
        )
        self.created: CreateManagedUserParams | None = None
        self.updated: UpdateUserAccessParams | None = None
        self.fail_create = False

    def ping(self) -> None:
        pass

    def principal_by_access_hash(self, digest: bytes, now: datetime) -> Principal:
        del digest, now
        return self.principal

    def create_managed_user(self, params: CreateManagedUserParams) -> User:
        self.created = params
        if self.fail_create:
            raise ConflictError("duplicate normalized email")
        now = datetime.now(UTC)
        return User(params.id, params.email, params.role, "active", now, now)

    def update_user_access(self, params: UpdateUserAccessParams) -> User:
        self.updated = params
        now = datetime.now(UTC)
        return User(
            params.user_id,
            "target@example.com",
            params.role or Role.CUSTOMER,
            params.status or "active",
            now,
            now,
        )


def settings(*, expose_dev_tokens: bool = True) -> Settings:
    return Settings(
        environment="test",
        http_host="127.0.0.1",
        http_port=8080,
        database_url="postgresql://test:test@localhost/test",
        token_pepper=b"t" * 32,
        device_pepper=b"d" * 32,
        issuance_pepper=b"i" * 32,
        password_pepper=b"",
        access_token_ttl=timedelta(minutes=15),
        refresh_token_ttl=timedelta(days=30),
        verification_ttl=timedelta(minutes=30),
        password_reset_ttl=timedelta(minutes=30),
        activation_lease_ttl=timedelta(hours=24),
        registration_mode="open",
        allowed_origins=(),
        trusted_proxy_cidrs=(),
        expose_dev_tokens=expose_dev_tokens,
        public_app_url="http://localhost:8080",
        email_webhook_url="",
        email_webhook_bearer="",
        activation_issuer="",
        activation_key_file=Path("activation.key"),
        activation_key_passphrase_file=None,
        activation_verification_key_files=(),
        auto_migrate=False,
        shutdown_timeout=timedelta(seconds=1),
    )


def authorization() -> dict[str, str]:
    return {"Authorization": f"Bearer {auth.new_token(auth.ACCESS_TOKEN)}"}


def service(
    store: AdminStore,
    *,
    expose_dev_tokens: bool = True,
) -> tuple[Any, RecordingPasswordManager, Settings]:
    config = settings(expose_dev_tokens=expose_dev_tokens)
    passwords = RecordingPasswordManager()
    return create_app(config, store, passwords), passwords, config  # type: ignore[arg-type]


def invite(client: TestClient, *, email: str = "New.Admin@Example.com") -> Any:
    return client.post(
        "/api/v1/admin/users",
        json={"email": email, "role": "license_admin"},
        headers=authorization(),
    )


def test_owner_invitation_normalizes_email_and_never_returns_generated_password() -> None:
    store = AdminStore()
    app, passwords, config = service(store)

    with TestClient(app) as client:
        response = invite(client, email="  New.Admin@Example.COM  ")

    assert response.status_code == 201
    payload = response.json()
    assert payload["user"]["email"] == "New.Admin@Example.COM"
    assert payload["user"]["role"] == "license_admin"
    assert payload["user"]["status"] == "active"
    assert payload["user"]["emailVerifiedAt"]
    assert payload["passwordSetupRequired"] is True
    assert payload["invitationDelivery"] == "manual"
    assert "password" not in payload["user"]
    assert store.created is not None
    assert store.created.normalized_email == "new.admin@example.com"
    assert store.created.actor_user_id == store.principal.user.id
    assert store.created.role is Role.LICENSE_ADMIN
    setup_token = payload["developmentPasswordResetToken"]
    assert auth.hash_token(config.token_pepper, auth.PASSWORD_RESET_TOKEN, setup_token) == (
        store.created.password_reset_token_hash
    )
    assert len(passwords.plaintexts) == 2
    generated_password = passwords.plaintexts[1]
    assert len(generated_password) >= 64
    assert generated_password != setup_token
    assert store.created.password_hash == f"hashed:{generated_password}"
    assert generated_password not in response.text


def test_invitation_token_is_not_exposed_when_development_tokens_are_disabled() -> None:
    store = AdminStore()
    app, _, _ = service(store, expose_dev_tokens=False)

    with TestClient(app) as client:
        response = invite(client)

    assert response.status_code == 201
    assert "developmentPasswordResetToken" not in response.json()
    assert store.created is not None
    assert len(store.created.password_reset_token_hash) == 32


@pytest.mark.parametrize(
    "role",
    [Role.LICENSE_ADMIN, Role.SUPPORT, Role.AUDITOR, Role.CUSTOMER],
)
def test_non_owners_cannot_create_users_or_change_access(role: Role) -> None:
    store = AdminStore(role)
    app, _, _ = service(store)
    target_id = uuid4()

    with TestClient(app) as client:
        create_response = invite(client)
        access_response = client.post(
            f"/api/v1/admin/users/{target_id}/access",
            json={"role": "auditor", "status": "active"},
            headers=authorization(),
        )

    assert create_response.status_code == 403
    assert create_response.json()["code"] == "forbidden"
    assert access_response.status_code == 403
    assert access_response.json()["code"] == "forbidden"
    assert store.created is None
    assert store.updated is None


def test_unverified_owner_cannot_administer_users() -> None:
    store = AdminStore(verified=False)
    app, _, _ = service(store)

    with TestClient(app) as client:
        response = invite(client)

    assert response.status_code == 403
    assert response.json()["code"] == "email_verification_required"
    assert store.created is None


def test_duplicate_normalized_email_is_a_conflict_without_secret_disclosure() -> None:
    store = AdminStore()
    store.fail_create = True
    app, _, _ = service(store)

    with TestClient(app) as client:
        response = invite(client, email="OWNER@example.com")

    assert response.status_code == 409
    assert response.json()["code"] == "conflict"
    assert "token" not in response.text.lower()
    assert "owner@example.com" not in response.text.lower()


def test_atomic_access_endpoint_passes_actor_role_and_status_together() -> None:
    store = AdminStore()
    app, _, _ = service(store)
    target_id = uuid4()

    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/admin/users/{target_id}/access",
            json={"role": "support", "status": "disabled"},
            headers=authorization(),
        )

    assert response.status_code == 200
    assert response.json()["user"]["role"] == "support"
    assert response.json()["user"]["status"] == "disabled"
    assert store.updated is not None
    assert store.updated.user_id == target_id
    assert store.updated.actor_user_id == store.principal.user.id
    assert store.updated.role is Role.SUPPORT
    assert store.updated.status == "disabled"


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/v1/admin/users", {"email": "admin@example.com"}),
        (
            "/api/v1/admin/users",
            {"email": "admin@example.com", "role": "license_admin", "permissions": ["all"]},
        ),
        (
            "/api/v1/admin/users/{target}/access",
            {"role": "support"},
        ),
        (
            "/api/v1/admin/users/{target}/access",
            {"role": "superuser", "status": "active"},
        ),
    ],
)
def test_user_administration_requests_are_strict_role_bundles(
    path: str,
    body: dict[str, Any],
) -> None:
    store = AdminStore()
    app, _, _ = service(store)
    path = path.format(target=uuid4())

    with TestClient(app) as client:
        response = client.post(path, json=body, headers=authorization())

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_request"


def test_access_endpoint_rejects_noncanonical_user_identifier() -> None:
    store = AdminStore()
    app, _, _ = service(store)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/admin/users/not-a-uuid/access",
            json={"role": "auditor", "status": "active"},
            headers=authorization(),
        )

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_request"
    assert store.updated is None
