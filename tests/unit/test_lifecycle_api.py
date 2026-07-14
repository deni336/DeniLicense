from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from denilicense import auth
from denilicense.api import create_app
from denilicense.config import Settings
from denilicense.domain import License, Principal, Role, User


class Passwords:
    def hash(self, password: str) -> str:
        return f"hashed:{password}"


def config() -> Settings:
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
        expose_dev_tokens=True,
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


class LifecycleStore:
    def __init__(self, role: Role = Role.PLATFORM_OWNER) -> None:
        now = datetime.now(UTC)
        actor = User(uuid4(), "owner@example.com", role, "active", now, now)
        self.principal = Principal(actor, uuid4())
        self.user = User(
            uuid4(),
            "target@example.com",
            Role.CUSTOMER,
            "disabled",
            now,
            now,
            archived_at=now,
            revision=4,
        )
        self.license = License(
            id=uuid4(),
            serial=uuid4(),
            product_id=uuid4(),
            product_code="DESKTOP",
            owner_user_id=None,
            owner_email="",
            source="online",
            state="revoked",
            subject="",
            issued_at=now,
            not_before=now,
            expires_at=None,
            max_activations=1,
            offline_grace_seconds=86400,
            entitlements={},
            metadata={},
            revision=7,
            claim_code_suffix="ABCD",
            claimed_at=None,
            created_at=now,
            updated_at=now,
            archived_at=now,
        )
        self.calls: list[tuple[str, int | None]] = []

    def principal_by_access_hash(self, digest: bytes, now: datetime) -> Principal:
        del digest, now
        return self.principal

    def license_by_id(self, license_id: UUID) -> License:
        assert license_id == self.license.id
        return self.license

    def archive_license(
        self, license_id: UUID, actor_id: UUID, now: datetime, audit: Any, *, expected_revision: int
    ) -> License:
        del license_id, actor_id, now, audit
        self.calls.append(("archive_license", expected_revision))
        return self.license

    def restore_license(
        self, license_id: UUID, actor_id: UUID, now: datetime, audit: Any, *, expected_revision: int
    ) -> License:
        del license_id, actor_id, now, audit
        self.calls.append(("restore_license", expected_revision))
        return self.license

    def delete_license(
        self, license_id: UUID, actor_id: UUID, now: datetime, audit: Any, *, expected_revision: int
    ) -> License:
        del license_id, actor_id, now, audit
        self.calls.append(("delete_license", expected_revision))
        return replace(self.license, deleted_at=datetime.now(UTC))

    def user_by_id(self, user_id: UUID, *, include_deleted: bool = False) -> User:
        del include_deleted
        assert user_id == self.user.id
        return self.user

    def archive_user(
        self, user_id: UUID, actor_id: UUID, now: datetime, audit: Any, *, expected_revision: int
    ) -> User:
        del user_id, actor_id, now, audit
        self.calls.append(("archive_user", expected_revision))
        return self.user

    def restore_user(
        self, user_id: UUID, actor_id: UUID, now: datetime, audit: Any, *, expected_revision: int
    ) -> User:
        del user_id, actor_id, now, audit
        self.calls.append(("restore_user", expected_revision))
        return self.user

    def delete_user(
        self, user_id: UUID, actor_id: UUID, now: datetime, audit: Any, *, expected_revision: int
    ) -> User:
        del user_id, actor_id, now, audit
        self.calls.append(("delete_user", expected_revision))
        return replace(self.user, deleted_at=datetime.now(UTC))


def headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {auth.new_token(auth.ACCESS_TOKEN)}"}


def test_revision_and_typed_confirmation_reach_lifecycle_operations() -> None:
    store = LifecycleStore()
    app = create_app(config(), store, Passwords())  # type: ignore[arg-type]
    with TestClient(app) as client:
        archived = client.post(
            f"/api/v1/admin/licenses/{store.license.id}/archive",
            headers=headers(),
            json={"expectedRevision": 7},
        )
        deleted = client.post(
            f"/api/v1/admin/licenses/{store.license.id}/delete",
            headers=headers(),
            json={"serial": str(store.license.serial), "expectedRevision": 7},
        )
        user_deleted = client.post(
            f"/api/v1/admin/users/{store.user.id}/delete",
            headers=headers(),
            json={"email": "TARGET@example.com", "expectedRevision": 4},
        )

    assert archived.status_code == 200
    assert deleted.status_code == 204
    assert user_deleted.status_code == 204
    assert store.calls == [
        ("archive_license", 7),
        ("delete_license", 7),
        ("delete_user", 4),
    ]


def test_delete_rejects_stale_human_confirmation_before_store_mutation() -> None:
    store = LifecycleStore()
    app = create_app(config(), store, Passwords())  # type: ignore[arg-type]
    with TestClient(app) as client:
        license_response = client.post(
            f"/api/v1/admin/licenses/{store.license.id}/delete",
            headers=headers(),
            json={"serial": str(uuid4()), "expectedRevision": 7},
        )
        user_response = client.post(
            f"/api/v1/admin/users/{store.user.id}/delete",
            headers=headers(),
            json={"email": "someone-else@example.com", "expectedRevision": 4},
        )

    assert license_response.status_code == 409
    assert user_response.status_code == 409
    assert store.calls == []


def test_license_admin_can_archive_but_only_an_owner_can_delete() -> None:
    store = LifecycleStore(Role.LICENSE_ADMIN)
    app = create_app(config(), store, Passwords())  # type: ignore[arg-type]
    with TestClient(app) as client:
        archived = client.post(
            f"/api/v1/admin/licenses/{store.license.id}/archive",
            headers=headers(),
            json={"expectedRevision": 7},
        )
        deleted = client.post(
            f"/api/v1/admin/licenses/{store.license.id}/delete",
            headers=headers(),
            json={"serial": str(store.license.serial), "expectedRevision": 7},
        )

    assert archived.status_code == 200
    assert deleted.status_code == 403
    assert store.calls == [("archive_license", 7)]
