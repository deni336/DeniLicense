from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient

from denilicense import auth
from denilicense.api import create_app
from denilicense.config import Settings
from denilicense.domain import Role, User, UserCredential
from denilicense.store import RegisterPendingUserParams


class RecordingPasswords:
    def __init__(self) -> None:
        self.hashed: list[str] = []
        self.verified_hashes: list[str] = []

    def hash(self, password: str) -> str:
        self.hashed.append(password)
        return f"hashed:{password}"

    def verify(self, encoded_hash: str, password: str) -> bool:
        self.verified_hashes.append(encoded_hash)
        return encoded_hash == f"hashed:{password}"


class RegistrationStore:
    def __init__(self) -> None:
        now = datetime.now(UTC)
        self.pending = User(
            uuid4(),
            "victim@example.com",
            Role.CUSTOMER,
            "active",
            None,
            now,
            password_setup_required=True,
        )
        self.registrations: list[RegisterPendingUserParams] = []
        self.verifications: list[tuple[bytes, str, datetime]] = []
        self.sessions_created = 0

    def ping(self) -> None:
        pass

    def register_pending_user(self, params: RegisterPendingUserParams) -> tuple[str, bool]:
        self.registrations.append(params)
        return params.email, True

    def verify_email(self, token_hash: bytes, password_hash: str, now: datetime) -> User:
        self.verifications.append((token_hash, password_hash, now))
        return User(
            self.pending.id,
            self.pending.email,
            Role.CUSTOMER,
            "active",
            now,
            self.pending.created_at,
        )

    def user_credential_by_email(self, normalized_email: str) -> UserCredential:
        assert normalized_email == self.pending.email
        return UserCredential(self.pending, "hashed:attacker-known-password")

    def create_session(self, _params: Any) -> None:
        self.sessions_created += 1


def settings() -> Settings:
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


def service() -> tuple[Any, RegistrationStore, RecordingPasswords, Settings]:
    store = RegistrationStore()
    passwords = RecordingPasswords()
    config = settings()
    return create_app(config, store, passwords), store, passwords, config  # type: ignore[arg-type]


def test_registration_accepts_only_email_and_rotates_the_pending_token() -> None:
    app, store, passwords, config = service()
    with TestClient(app) as client:
        rejected = client.post(
            "/api/v1/auth/register",
            json={"email": "victim@example.com", "password": "attacker-known-password"},
        )
        first = client.post("/api/v1/auth/register", json={"email": "victim@example.com"})
        second = client.post("/api/v1/auth/register", json={"email": "victim@example.com"})

    assert rejected.status_code == 400
    assert rejected.json()["code"] == "invalid_request"
    assert first.status_code == second.status_code == 202
    first_token = first.json()["developmentVerificationToken"]
    second_token = second.json()["developmentVerificationToken"]
    assert first_token != second_token
    assert len(store.registrations) == 2
    assert auth.hash_token(config.token_pepper, auth.EMAIL_VERIFICATION_TOKEN, second_token) == (
        store.registrations[-1].verification_token_hash
    )
    assert "attacker-known-password" not in passwords.hashed


def test_verification_token_holder_must_choose_the_first_password() -> None:
    app, store, passwords, config = service()
    chosen_password = "victim chooses this new password"  # noqa: S105 - test fixture
    with TestClient(app) as client:
        registered = client.post("/api/v1/auth/register", json={"email": "victim@example.com"})
        token = registered.json()["developmentVerificationToken"]
        missing_password = client.post("/api/v1/auth/verify-email", json={"token": token})
        verified = client.post(
            "/api/v1/auth/verify-email",
            json={"token": token, "newPassword": chosen_password},
        )

    assert missing_password.status_code == 400
    assert verified.status_code == 200
    assert verified.json()["user"]["passwordSetupRequired"] is False
    assert len(store.verifications) == 1
    token_hash, password_hash, _ = store.verifications[0]
    assert token_hash == auth.hash_token(config.token_pepper, auth.EMAIL_VERIFICATION_TOKEN, token)
    assert password_hash == f"hashed:{chosen_password}"
    assert chosen_password in passwords.hashed


def test_pending_registration_cannot_authenticate_with_a_legacy_seeded_password() -> None:
    app, store, passwords, _ = service()
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "victim@example.com", "password": "attacker-known-password"},
        )

    assert response.status_code == 401
    assert response.json()["code"] == "authentication_required"
    assert store.sessions_created == 0
    assert passwords.verified_hashes == ["hashed:dummy password used for timing only"]
