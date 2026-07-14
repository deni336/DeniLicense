from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient

from denilicense import auth
from denilicense.api import create_app
from denilicense.config import Settings
from denilicense.domain import License, LicenseRequest, Principal, Product, Role, User
from denilicense.store import CreateLicenseParams, CreateLicenseRequestParams


class Passwords:
    def hash(self, password: str) -> str:
        return f"hashed:{password}"

    def verify(self, encoded_hash: str, password: str) -> bool:
        return encoded_hash == f"hashed:{password}"


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


class RequestStore:
    def __init__(self, role: Role) -> None:
        self.now = datetime.now(UTC)
        self.requester = User(uuid4(), "customer@example.com", Role.CUSTOMER, "active", self.now, self.now)
        actor = (
            self.requester
            if role is Role.CUSTOMER
            else User(uuid4(), "owner@example.com", role, "active", self.now, self.now)
        )
        self.principal = Principal(actor, uuid4())
        self.product = Product(uuid4(), "DESKTOP", "Desktop", "", "active", self.now, self.now)
        self.item = LicenseRequest(
            id=uuid4(),
            requester_user_id=self.requester.id,
            requester_email=self.requester.email,
            product_id=self.product.id,
            product_code=self.product.code,
            product_name=self.product.name,
            requested_activations=3,
            message="Three workstations",
            status="pending",
            admin_notes="",
            reviewed_by=None,
            reviewed_at=None,
            fulfilled_license_id=None,
            created_at=self.now,
            updated_at=self.now,
        )
        self.created: CreateLicenseRequestParams | None = None
        self.approved: CreateLicenseParams | None = None
        self.replayed = False

    def principal_by_access_hash(self, digest: bytes, now: datetime) -> Principal:
        del digest, now
        return self.principal

    def product_by_code(self, code: str) -> Product:
        assert code == self.product.code
        return self.product

    def create_license_request(self, params: CreateLicenseRequestParams) -> LicenseRequest:
        self.created = params
        return replace(
            self.item,
            id=params.id,
            requester_user_id=params.requester_user_id,
            requested_activations=params.requested_activations,
            message=params.message,
        )

    def list_user_license_requests(
        self, user_id: Any, status: str = "", limit: int = 100
    ) -> list[LicenseRequest]:
        assert user_id == self.requester.id
        assert status == ""
        assert limit == 100
        return [self.item]

    def license_request_by_id(self, request_id: Any) -> LicenseRequest:
        assert request_id == self.item.id
        return self.item

    def approve_license_request(
        self,
        request_id: Any,
        license_params: CreateLicenseParams,
        admin_notes: str,
        now: datetime,
        audit: Any,
    ) -> tuple[LicenseRequest, License, bool]:
        del admin_notes, now, audit
        assert request_id == self.item.id
        self.approved = license_params
        licensed = License(
            id=license_params.id,
            serial=license_params.serial,
            product_id=self.product.id,
            product_code=self.product.code,
            owner_user_id=self.requester.id,
            owner_email=self.requester.email,
            source="online",
            state="active",
            subject=license_params.subject,
            issued_at=license_params.issued_at,
            not_before=license_params.not_before,
            expires_at=license_params.expires_at,
            max_activations=license_params.max_activations,
            offline_grace_seconds=license_params.offline_grace_seconds,
            entitlements=license_params.entitlements,
            metadata=license_params.metadata,
            revision=1,
            claim_code_suffix=license_params.claim_code_suffix,
            claimed_at=license_params.issued_at,
            created_at=license_params.issued_at,
            updated_at=license_params.issued_at,
        )
        fulfilled = replace(
            self.item,
            status="fulfilled",
            fulfilled_license_id=licensed.id,
            reviewed_by=self.principal.user.id,
            reviewed_at=self.now,
        )
        return fulfilled, licensed, self.replayed


def authorization() -> dict[str, str]:
    return {"Authorization": f"Bearer {auth.new_token(auth.ACCESS_TOKEN)}"}


def service(store: RequestStore) -> Any:
    return create_app(config(), store, Passwords())  # type: ignore[arg-type]


def test_customer_creates_and_lists_only_their_own_license_requests() -> None:
    store = RequestStore(Role.CUSTOMER)
    with TestClient(service(store)) as client:
        created = client.post(
            "/api/v1/license-requests",
            headers=authorization(),
            json={
                "productCode": "desktop",
                "requestedActivations": 3,
                "message": "  Three workstations  ",
            },
        )
        listed = client.get("/api/v1/license-requests", headers=authorization())
        spoofed = client.post(
            "/api/v1/license-requests",
            headers=authorization(),
            json={
                "productCode": "DESKTOP",
                "requestedActivations": 1,
                "message": "",
                "requesterUserId": str(uuid4()),
            },
        )

    assert created.status_code == 201
    assert created.json()["request"]["requesterUserId"] == str(store.requester.id)
    assert listed.status_code == 200
    assert listed.json()["items"][0]["productCode"] == "DESKTOP"
    assert spoofed.status_code == 400
    assert store.created is not None
    assert store.created.requester_user_id == store.requester.id
    assert store.created.message == "Three workstations"


def test_approval_assigns_the_license_without_exposing_a_claim_secret() -> None:
    store = RequestStore(Role.PLATFORM_OWNER)
    body = {
        "subject": "contract-42",
        "maxActivations": 3,
        "offlineGraceSeconds": 86400,
        "perpetual": True,
        "entitlements": {"feature.reporting": True, "limits.projects": 100},
    }
    path = f"/api/v1/admin/license-requests/{store.item.id}/approve"
    with TestClient(service(store)) as client:
        approved = client.post(path, headers=authorization(), json=body)
        store.replayed = True
        replayed = client.post(path, headers=authorization(), json=body)

    assert approved.status_code == 201
    assert replayed.status_code == 200
    assert approved.json()["request"]["status"] == "fulfilled"
    assert approved.json()["license"]["ownerUserId"] == str(store.requester.id)
    assert "claimCode" not in approved.json()
    assert store.approved is not None
    assert store.approved.product_id == store.product.id
    assert store.approved.metadata == {"licenseRequestId": str(store.item.id)}
    assert len(store.approved.creation_request_hash or b"") == 32


def test_request_routes_enforce_customer_and_administrator_roles() -> None:
    customer_store = RequestStore(Role.CUSTOMER)
    owner_store = RequestStore(Role.PLATFORM_OWNER)
    approval = {
        "maxActivations": 1,
        "perpetual": True,
        "entitlements": {},
    }
    with TestClient(service(customer_store)) as client:
        customer_admin = client.post(
            f"/api/v1/admin/license-requests/{customer_store.item.id}/approve",
            headers=authorization(),
            json=approval,
        )
    with TestClient(service(owner_store)) as client:
        owner_customer = client.post(
            "/api/v1/license-requests",
            headers=authorization(),
            json={"productCode": "DESKTOP", "requestedActivations": 1, "message": ""},
        )

    assert customer_admin.status_code == 403
    assert owner_customer.status_code == 403
