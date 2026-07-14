"""Live-container integration coverage for the complete licensing lifecycle."""

from __future__ import annotations

import base64
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from denilicense.client import (
    JWKS,
    RenewalChallenge,
    VerifyOptions,
    device_key_thumbprint,
    sign_renewal_challenge,
    verify_lease_jwk,
)
from denilicense.crypto import (
    OFFLINE_LICENSE_ISSUER,
    LicenseClaims,
    SigningKey,
    generate_claim_code,
    generate_serial,
    marshal_public_key,
    sign_token,
)
from denilicense.crypto.license import encode_claim_code_digest


class APIClient:
    """Small JSON client that keeps failed-response context in assertions."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.http = httpx.Client(base_url=self.base_url, timeout=10.0, follow_redirects=False)

    def close(self) -> None:
        self.http.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        bearer: str = "",
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        request_headers = dict(headers or {})
        if bearer:
            request_headers["Authorization"] = f"Bearer {bearer}"
        return self.http.request(method, path, headers=request_headers, json=body)


def require_status(response: httpx.Response, expected: int) -> None:
    assert response.status_code == expected, (
        f"{response.request.method} {response.request.url}: HTTP {response.status_code}, "
        f"expected {expected}; body={response.text[:4096]!r}"
    )


def login(client: APIClient, email: str, password: str) -> dict[str, Any]:
    response = client.request("POST", "/api/v1/auth/login", body={"email": email, "password": password})
    require_status(response, 200)
    result = response.json()
    assert result["accessToken"]
    assert result["refreshToken"]
    return result


def contains_id(items: list[dict[str, Any]], expected: str) -> bool:
    return any(item.get("id") == expected for item in items)


def verify_activation_lease(
    client: APIClient,
    token: str,
    product_code: str,
    device_public_key: bytes,
) -> None:
    response = client.request("GET", "/.well-known/denilicense-activation-keys.json")
    require_status(response, 200)
    keys = JWKS.from_dict(response.json())
    assert len(keys.keys) == 1
    verify_lease_jwk(
        token,
        keys.keys[0],
        VerifyOptions(
            expected_issuer=os.environ.get("DENILICENSE_INTEGRATION_ISSUER", client.base_url),
            expected_audience=product_code,
            expected_device_key_thumbprint=device_key_thumbprint(device_public_key),
            now=datetime.now(UTC),
            clock_leeway=timedelta(minutes=1),
        ),
    )


def alternate_base64_character(value: str) -> str:
    return value[:-1] + ("B" if value[-1] == "A" else "A")


def test_end_to_end_licensing_flow() -> None:
    base_url = os.environ.get("DENILICENSE_INTEGRATION_URL", "").rstrip("/")
    if not base_url:
        pytest.skip("set DENILICENSE_INTEGRATION_URL to run PostgreSQL/API integration tests")

    owner_email = os.environ.get("DENILICENSE_INTEGRATION_OWNER_EMAIL", "owner@example.com")
    owner_password = os.environ.get("DENILICENSE_INTEGRATION_OWNER_PASSWORD", "correct horse battery staple")
    client = APIClient(base_url)
    try:
        owner = login(client, owner_email, owner_password)
        owner_access = owner["accessToken"]
        unique = os.urandom(4).hex().upper()
        product_code = f"T{unique}"

        response = client.request(
            "POST",
            "/api/v1/admin/products",
            bearer=owner_access,
            body={
                "code": product_code,
                "name": "Integration Product",
                "description": "Automated end-to-end test",
            },
        )
        require_status(response, 201)
        created_product = response.json()["product"]
        assert created_product["revision"] == 1

        expires_at = datetime.now(UTC) + timedelta(hours=24)
        online_request = {
            "productCode": product_code,
            "subject": "online-integration",
            "expiresAt": expires_at.isoformat(),
            "maxActivations": 2,
            "entitlements": {"feature.online": True},
        }
        idempotency_key = f"integration-{unique.lower()}"
        response = client.request(
            "POST",
            "/api/v1/admin/licenses",
            bearer=owner_access,
            headers={"Idempotency-Key": idempotency_key},
            body=online_request,
        )
        require_status(response, 201)
        online_created = response.json()

        response = client.request(
            "POST",
            "/api/v1/admin/licenses",
            bearer=owner_access,
            headers={"Idempotency-Key": idempotency_key},
            body=online_request,
        )
        require_status(response, 200)
        online_retried = response.json()
        assert online_retried["idempotent"] is True
        assert online_retried["license"]["id"] == online_created["license"]["id"]
        assert online_retried["claimCode"] == online_created["claimCode"]

        changed_online_request = {
            **online_request,
            "subject": "changed-request",
        }
        response = client.request(
            "POST",
            "/api/v1/admin/licenses",
            bearer=owner_access,
            headers={"Idempotency-Key": idempotency_key},
            body=changed_online_request,
        )
        require_status(response, 409)

        issuer_key = SigningKey.generate(OFFLINE_LICENSE_ISSUER)
        issuer = f"integration/{unique.lower()}"
        response = client.request(
            "POST",
            "/api/v1/admin/issuers",
            bearer=owner_access,
            body={
                "issuer": issuer,
                "publicKeyDocument": marshal_public_key(issuer_key.verification_key).decode(),
                "notBefore": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
            },
        )
        require_status(response, 201)

        claim_code = generate_claim_code()
        now = datetime.now(UTC).replace(microsecond=0)
        offline_expires_at = now + timedelta(hours=24)
        serial = generate_serial()
        artifact = sign_token(
            LicenseClaims(
                issuer=issuer,
                key_id=issuer_key.key_id,
                audience=product_code,
                serial=serial,
                subject="integration-customer",
                claim_code_sha256=encode_claim_code_digest(claim_code.digest),
                claim_code_suffix=claim_code.suffix,
                issued_at=now,
                not_before=now,
                expires_at=offline_expires_at,
                max_activations=1,
                entitlements={"feature.integration": True, "projects.max": 5},
            ),
            issuer_key,
        )
        response = client.request(
            "POST",
            "/api/v1/admin/licenses/import",
            bearer=owner_access,
            body={"artifact": artifact},
        )
        require_status(response, 201)
        imported = response.json()
        imported_license_id = imported["license"]["id"]
        assert imported["idempotent"] is False
        assert imported_license_id

        response = client.request(
            "POST",
            "/api/v1/admin/licenses/import",
            bearer=owner_access,
            body={"artifact": artifact},
        )
        require_status(response, 200)
        assert response.json()["idempotent"] is True

        conflicting_claim_code = generate_claim_code()
        conflicting_artifact = sign_token(
            LicenseClaims(
                issuer=issuer,
                key_id=issuer_key.key_id,
                audience=product_code,
                serial=serial,
                subject="conflicting-customer",
                claim_code_sha256=encode_claim_code_digest(conflicting_claim_code.digest),
                claim_code_suffix=conflicting_claim_code.suffix,
                issued_at=now,
                not_before=now,
                expires_at=offline_expires_at,
                max_activations=1,
                entitlements={"feature.integration": True},
            ),
            issuer_key,
        )
        response = client.request(
            "POST",
            "/api/v1/admin/licenses/import",
            bearer=owner_access,
            body={"artifact": conflicting_artifact},
        )
        require_status(response, 409)

        response = client.request(
            "POST",
            "/api/v1/admin/licenses/import",
            bearer=owner_access,
            body={"artifact": alternate_base64_character(artifact)},
        )
        assert 400 <= response.status_code < 500

        response = client.request(
            "GET",
            f"/api/v1/admin/licenses/{imported_license_id}",
            bearer=owner_access,
        )
        require_status(response, 200)
        assert response.json()["license"]["id"] == imported_license_id

        response = client.request(
            "GET",
            f"/api/v1/admin/licenses?claimCodeSuffix={claim_code.suffix}",
            bearer=owner_access,
        )
        require_status(response, 200)
        assert contains_id(response.json()["items"], imported_license_id)

        customer_email = f"customer-{unique.lower()}@example.com"
        customer_password = "another correct horse battery staple"  # noqa: S105 - test fixture
        response = client.request(
            "POST",
            "/api/v1/auth/register",
            body={"email": customer_email},
        )
        require_status(response, 202)
        first_verification_token = response.json().get("developmentVerificationToken", "")
        assert first_verification_token, "development verification token missing"

        response = client.request(
            "POST",
            "/api/v1/auth/register",
            body={"email": customer_email},
        )
        require_status(response, 202)
        verification_token = response.json().get("developmentVerificationToken", "")
        assert verification_token and verification_token != first_verification_token

        response = client.request(
            "POST",
            "/api/v1/auth/verify-email",
            body={
                "token": first_verification_token,
                "newPassword": "attacker selected password is rejected",
            },
        )
        require_status(response, 400)
        assert response.json()["code"] == "invalid_request"

        response = client.request(
            "GET",
            f"/api/v1/admin/users?email={quote(customer_email)}",
            bearer=owner_access,
        )
        require_status(response, 200)
        pending_customer = response.json()["items"][0]
        assert pending_customer["role"] == "customer"
        assert pending_customer["emailVerifiedAt"] is None
        assert pending_customer["passwordSetupRequired"] is True
        response = client.request(
            "POST",
            f"/api/v1/admin/users/{pending_customer['id']}/access",
            bearer=owner_access,
            body={
                "role": "auditor",
                "status": "active",
                "expectedRevision": pending_customer["revision"],
            },
        )
        require_status(response, 409)

        response = client.request(
            "POST",
            "/api/v1/auth/verify-email",
            body={"token": verification_token, "newPassword": customer_password},
        )
        require_status(response, 200)
        customer = login(client, customer_email, customer_password)
        customer_access = customer["accessToken"]

        license_request_body = {
            "productCode": product_code,
            "requestedActivations": 2,
            "message": "Two integration workstations",
        }
        response = client.request(
            "POST",
            "/api/v1/license-requests",
            bearer=customer_access,
            body=license_request_body,
        )
        require_status(response, 201)
        cancelled_request_id = response.json()["request"]["id"]
        response = client.request(
            "POST",
            f"/api/v1/license-requests/{cancelled_request_id}/cancel",
            bearer=customer_access,
        )
        require_status(response, 200)
        assert response.json()["request"]["status"] == "cancelled"

        response = client.request(
            "POST",
            "/api/v1/license-requests",
            bearer=customer_access,
            body=license_request_body,
        )
        require_status(response, 201)
        license_request_id = response.json()["request"]["id"]
        approval_body = {
            "subject": "request-integration",
            "expiresAt": (datetime.now(UTC) + timedelta(hours=24)).isoformat(),
            "maxActivations": 2,
            "offlineGraceSeconds": 86_400,
            "perpetual": False,
            "entitlements": {"feature.requested": True, "limits.projects": 20},
        }
        approval_path = f"/api/v1/admin/license-requests/{license_request_id}/approve"
        response = client.request(
            "POST",
            approval_path,
            bearer=owner_access,
            body=approval_body,
        )
        require_status(response, 201)
        fulfilled = response.json()
        requested_license_id = fulfilled["license"]["id"]
        assert fulfilled["request"]["status"] == "fulfilled"
        assert fulfilled["license"]["ownerUserId"] == customer["user"]["id"]
        assert "claimCode" not in fulfilled

        response = client.request(
            "POST",
            approval_path,
            bearer=owner_access,
            body=approval_body,
        )
        require_status(response, 200)
        assert response.json()["idempotent"] is True
        assert response.json()["license"]["id"] == requested_license_id

        response = client.request("GET", "/api/v1/license-requests", bearer=customer_access)
        require_status(response, 200)
        assert contains_id(response.json()["items"], license_request_id)
        response = client.request("GET", "/api/v1/licenses", bearer=customer_access)
        require_status(response, 200)
        assert contains_id(response.json()["items"], requested_license_id)

        response = client.request(
            "POST",
            "/api/v1/licenses/claim",
            bearer=customer_access,
            body={"claimCode": claim_code.display},
        )
        require_status(response, 200)
        claimed_license_id = response.json()["license"]["id"]
        assert claimed_license_id == imported_license_id

        device_private_key = Ed25519PrivateKey.generate()
        device_public_key = device_private_key.public_key().public_bytes_raw()
        response = client.request(
            "POST",
            f"/api/v1/licenses/{claimed_license_id}/activations",
            bearer=customer_access,
            body={
                "devicePublicKey": base64.urlsafe_b64encode(device_public_key).rstrip(b"=").decode(),
                "label": "integration device",
            },
        )
        require_status(response, 201)
        activated = response.json()
        activation_id = activated["activation"]["id"]
        verify_activation_lease(client, activated["lease"], product_code, device_public_key)

        response = client.request(
            "GET",
            f"/api/v1/licenses/{claimed_license_id}/activations",
            bearer=customer_access,
        )
        require_status(response, 200)
        assert contains_id(response.json()["items"], activation_id)

        response = client.request(
            "GET",
            f"/api/v1/admin/licenses/{claimed_license_id}/activations",
            bearer=owner_access,
        )
        require_status(response, 200)
        assert contains_id(response.json()["items"], activation_id)

        second_private_key = Ed25519PrivateKey.generate()
        second_public_key = second_private_key.public_key().public_bytes_raw()
        second_public_text = base64.urlsafe_b64encode(second_public_key).rstrip(b"=").decode()
        response = client.request(
            "POST",
            f"/api/v1/licenses/{claimed_license_id}/activations",
            bearer=customer_access,
            body={"devicePublicKey": second_public_text, "label": "seat overflow"},
        )
        require_status(response, 409)

        response = client.request(
            "POST",
            "/api/v1/activation-challenges",
            body={"activationId": activation_id},
        )
        require_status(response, 201)
        challenge = RenewalChallenge.from_dict(
            {
                key: value
                for key, value in response.json().items()
                if key in {"challengeId", "activationId", "nonce", "algorithm", "transcript"}
            }
        )
        renewal_signature = sign_renewal_challenge(device_private_key, challenge, activation_id)
        renewal_body = {
            "challengeId": challenge.challenge_id,
            "nonce": challenge.nonce,
            "signature": renewal_signature,
        }
        response = client.request("POST", "/api/v1/activation-challenges/complete", body=renewal_body)
        require_status(response, 200)
        renewed = response.json()
        verify_activation_lease(client, renewed["lease"], product_code, device_public_key)

        response = client.request("POST", "/api/v1/activation-challenges/complete", body=renewal_body)
        assert 400 <= response.status_code < 500

        def overflow_activation(_: int) -> int:
            public_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
            response = client.request(
                "POST",
                f"/api/v1/licenses/{claimed_license_id}/activations",
                bearer=customer_access,
                body={
                    "devicePublicKey": base64.urlsafe_b64encode(public_key).rstrip(b"=").decode(),
                    "label": "concurrent overflow",
                },
            )
            return response.status_code

        with ThreadPoolExecutor(max_workers=8) as executor:
            statuses = list(executor.map(overflow_activation, range(8)))
        assert statuses == [409] * 8

        response = client.request(
            "DELETE",
            f"/api/v1/admin/activations/{activation_id}",
            bearer=owner_access,
        )
        require_status(response, 204)
        response = client.request(
            "DELETE",
            f"/api/v1/admin/activations/{activation_id}",
            bearer=owner_access,
        )
        require_status(response, 204)
        response = client.request(
            "DELETE",
            f"/api/v1/activations/{activation_id}",
            bearer=customer_access,
        )
        require_status(response, 204)

        response = client.request(
            "POST",
            f"/api/v1/licenses/{claimed_license_id}/activations",
            bearer=customer_access,
            body={"devicePublicKey": second_public_text, "label": "replacement device"},
        )
        require_status(response, 201)
        replacement_activation_id = response.json()["activation"]["id"]

        managed_email = f"admin-{unique.lower()}@example.com"
        response = client.request(
            "POST",
            "/api/v1/admin/users",
            bearer=owner_access,
            body={"email": managed_email, "role": "license_admin"},
        )
        require_status(response, 201)
        managed = response.json()
        assert managed["user"]["email"] == managed_email
        assert managed["user"]["role"] == "license_admin"
        assert managed["user"]["status"] == "active"
        assert managed["user"]["emailVerifiedAt"]
        assert managed["passwordSetupRequired"] is True
        managed_setup_token = managed.get("developmentPasswordResetToken")
        assert managed_setup_token
        managed_id = managed["user"]["id"]

        response = client.request(
            "POST",
            f"/api/v1/admin/users/{managed_id}/invitation/resend",
            bearer=owner_access,
        )
        require_status(response, 202)
        resent_setup_token = response.json().get("developmentPasswordResetToken")
        assert resent_setup_token and resent_setup_token != managed_setup_token

        managed_password = "managed admin correct horse password"  # noqa: S105 - test fixture
        response = client.request(
            "POST",
            "/api/v1/auth/password-reset/confirm",
            body={"token": managed_setup_token, "newPassword": managed_password},
        )
        require_status(response, 400)
        response = client.request(
            "POST",
            "/api/v1/auth/password-reset/confirm",
            body={"token": resent_setup_token, "newPassword": managed_password},
        )
        require_status(response, 204)
        managed_session = login(client, managed_email, managed_password)
        managed_other_session = login(client, managed_email, managed_password)
        response = client.request(
            "GET",
            "/api/v1/auth/sessions",
            bearer=managed_session["accessToken"],
        )
        require_status(response, 200)
        account_sessions = response.json()["items"]
        assert len(account_sessions) >= 2
        assert sum(bool(item["isCurrent"]) for item in account_sessions) == 1
        response = client.request(
            "POST",
            "/api/v1/auth/sessions/revoke-others",
            bearer=managed_session["accessToken"],
        )
        require_status(response, 204)
        response = client.request(
            "GET",
            "/api/v1/auth/me",
            bearer=managed_other_session["accessToken"],
        )
        require_status(response, 401)
        changed_managed_password = "managed administrator replacement password"  # noqa: S105
        response = client.request(
            "POST",
            "/api/v1/auth/password/change",
            bearer=managed_session["accessToken"],
            body={
                "currentPassword": managed_password,
                "newPassword": changed_managed_password,
            },
        )
        require_status(response, 204)
        managed_password = changed_managed_password
        response = client.request(
            "GET",
            "/api/v1/admin/dashboard",
            bearer=managed_session["accessToken"],
        )
        require_status(response, 200)
        response = client.request(
            "GET",
            "/api/v1/admin/users",
            bearer=managed_session["accessToken"],
        )
        require_status(response, 403)

        response = client.request(
            "POST",
            "/api/v1/admin/users",
            bearer=owner_access,
            body={"email": managed_email.upper(), "role": "auditor"},
        )
        require_status(response, 409)
        assert "developmentPasswordResetToken" not in response.json()

        response = client.request(
            "GET",
            f"/api/v1/admin/users?email={quote(owner_email)}",
            bearer=owner_access,
        )
        require_status(response, 200)
        owner_users = response.json()["items"]
        assert len(owner_users) == 1
        response = client.request(
            "POST",
            f"/api/v1/admin/users/{owner_users[0]['id']}/access",
            bearer=owner_access,
            body={
                "role": "platform_owner",
                "status": "disabled",
                "expectedRevision": owner_users[0]["revision"],
            },
        )
        require_status(response, 409)

        response = client.request(
            "GET",
            f"/api/v1/admin/users/{managed_id}",
            bearer=owner_access,
        )
        require_status(response, 200)
        managed_before_access_change = response.json()["user"]
        response = client.request(
            "POST",
            f"/api/v1/admin/users/{managed_id}/access",
            bearer=owner_access,
            body={
                "role": "auditor",
                "status": "active",
                "expectedRevision": managed_before_access_change["revision"],
            },
        )
        require_status(response, 200)
        assert response.json()["user"]["role"] == "auditor"
        response = client.request("GET", "/api/v1/auth/me", bearer=managed_session["accessToken"])
        require_status(response, 401)
        response = client.request(
            "POST",
            "/api/v1/auth/refresh",
            body={"refreshToken": managed_session["refreshToken"]},
        )
        require_status(response, 401)

        auditor = login(client, managed_email, managed_password)
        auditor_access = auditor["accessToken"]
        response = client.request(
            "GET",
            "/api/v1/admin/audit-events?action=user.access_change",
            bearer=auditor_access,
        )
        require_status(response, 200)
        audits = response.json()["items"]
        assert audits
        assert audits[0]["targetId"] == managed_id

        response = client.request(
            "GET",
            f"/api/v1/admin/licenses/{claimed_license_id}",
            bearer=auditor_access,
        )
        require_status(response, 200)
        response = client.request(
            "DELETE",
            f"/api/v1/admin/activations/{replacement_activation_id}",
            bearer=auditor_access,
        )
        require_status(response, 403)

        license_state_path = f"/api/v1/admin/licenses/{claimed_license_id}/state"
        response = client.request(
            "POST",
            license_state_path,
            bearer=owner_access,
            body={"state": "revoked"},
        )
        require_status(response, 204)
        response = client.request(
            "POST",
            license_state_path,
            bearer=owner_access,
            body={"state": "revoked"},
        )
        require_status(response, 204)

        third_public_key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        response = client.request(
            "POST",
            f"/api/v1/licenses/{claimed_license_id}/activations",
            bearer=customer_access,
            body={
                "devicePublicKey": base64.urlsafe_b64encode(third_public_key).rstrip(b"=").decode(),
                "label": "revoked license",
            },
        )
        require_status(response, 409)

        issuer_status_path = f"/api/v1/admin/issuers/{issuer_key.key_id}/status"
        response = client.request(
            "POST",
            issuer_status_path,
            bearer=owner_access,
            body={"status": "revoked"},
        )
        require_status(response, 204)
        response = client.request(
            "POST",
            "/api/v1/admin/licenses/import",
            bearer=owner_access,
            body={"artifact": artifact},
        )
        require_status(response, 200)
        assert response.json()["idempotent"] is True

        rejected_claim_code = generate_claim_code()
        rejected_artifact = sign_token(
            LicenseClaims(
                issuer=issuer,
                key_id=issuer_key.key_id,
                audience=product_code,
                serial=generate_serial(),
                subject="revoked-issuer",
                claim_code_sha256=encode_claim_code_digest(rejected_claim_code.digest),
                claim_code_suffix=rejected_claim_code.suffix,
                issued_at=now,
                not_before=now,
                expires_at=offline_expires_at,
                max_activations=1,
                entitlements={},
            ),
            issuer_key,
        )
        response = client.request(
            "POST",
            "/api/v1/admin/licenses/import",
            bearer=owner_access,
            body={"artifact": rejected_artifact},
        )
        require_status(response, 400)
        response = client.request(
            "POST",
            issuer_status_path,
            bearer=owner_access,
            body={"status": "active"},
        )
        require_status(response, 409)

        response = client.request(
            "GET",
            f"/api/v1/admin/licenses/{claimed_license_id}",
            bearer=owner_access,
        )
        require_status(response, 200)
        revoked_license = response.json()["license"]
        assert revoked_license["state"] == "revoked"
        response = client.request(
            "POST",
            f"/api/v1/admin/licenses/{claimed_license_id}/archive",
            bearer=owner_access,
            body={"expectedRevision": revoked_license["revision"]},
        )
        require_status(response, 200)
        archived_license = response.json()["license"]
        assert archived_license["archivedAt"]
        response = client.request(
            "POST",
            f"/api/v1/admin/licenses/{claimed_license_id}/delete",
            bearer=owner_access,
            body={
                "serial": archived_license["serial"],
                "expectedRevision": archived_license["revision"],
            },
        )
        require_status(response, 204)
        response = client.request(
            "GET",
            f"/api/v1/licenses/{claimed_license_id}",
            bearer=customer_access,
        )
        require_status(response, 404)
        response = client.request(
            "GET",
            f"/api/v1/admin/licenses?lifecycle=deleted&serial={archived_license['serial']}",
            bearer=owner_access,
        )
        require_status(response, 200)
        assert contains_id(response.json()["items"], claimed_license_id)
        response = client.request(
            "GET",
            f"/api/v1/admin/licenses/{claimed_license_id}/activations",
            bearer=owner_access,
        )
        require_status(response, 200)
        assert response.json()["items"]
        response = client.request(
            "POST",
            "/api/v1/admin/licenses/import",
            bearer=owner_access,
            body={"artifact": artifact},
        )
        require_status(response, 409)

        response = client.request(
            "POST",
            f"/api/v1/admin/licenses/{requested_license_id}/state",
            bearer=owner_access,
            body={"state": "revoked"},
        )
        require_status(response, 204)
        response = client.request(
            "GET",
            f"/api/v1/admin/licenses/{requested_license_id}",
            bearer=owner_access,
        )
        require_status(response, 200)
        requested_license = response.json()["license"]
        response = client.request(
            "POST",
            f"/api/v1/admin/licenses/{requested_license_id}/archive",
            bearer=owner_access,
            body={"expectedRevision": requested_license["revision"]},
        )
        require_status(response, 200)
        requested_license = response.json()["license"]
        response = client.request(
            "POST",
            f"/api/v1/admin/licenses/{requested_license_id}/delete",
            bearer=owner_access,
            body={
                "serial": requested_license["serial"],
                "expectedRevision": requested_license["revision"],
            },
        )
        require_status(response, 204)
        response = client.request(
            "POST",
            approval_path,
            bearer=owner_access,
            body=approval_body,
        )
        require_status(response, 409)

        response = client.request(
            "GET",
            f"/api/v1/admin/users/{managed_id}",
            bearer=owner_access,
        )
        require_status(response, 200)
        managed_record = response.json()["user"]
        response = client.request(
            "POST",
            f"/api/v1/admin/users/{managed_id}/archive",
            bearer=owner_access,
            body={"expectedRevision": managed_record["revision"]},
        )
        require_status(response, 200)
        archived_user = response.json()["user"]
        assert archived_user["status"] == "disabled"
        response = client.request("GET", "/api/v1/auth/me", bearer=auditor_access)
        require_status(response, 401)
        response = client.request(
            "POST",
            f"/api/v1/admin/users/{managed_id}/delete",
            bearer=owner_access,
            body={"email": managed_email, "expectedRevision": archived_user["revision"]},
        )
        require_status(response, 204)
        response = client.request(
            "GET",
            f"/api/v1/admin/users/{managed_id}",
            bearer=owner_access,
        )
        require_status(response, 200)
        deleted_user = response.json()["user"]
        assert deleted_user["deletedAt"]
        assert deleted_user["email"] != managed_email
        response = client.request(
            "POST",
            "/api/v1/auth/register",
            body={"email": managed_email},
        )
        require_status(response, 202)
        assert response.json().get("developmentVerificationToken")

        product_status_path = f"/api/v1/admin/products/{product_code}/status"
        response = client.request(
            "POST",
            product_status_path,
            bearer=owner_access,
            body={"status": "retired", "expectedRevision": created_product["revision"]},
        )
        require_status(response, 200)
        retired_product = response.json()["product"]
        assert retired_product["status"] == "retired"
        response = client.request("GET", "/api/v1/products")
        require_status(response, 200)
        assert all(item["code"] != product_code for item in response.json()["items"])
        response = client.request(
            "POST",
            "/api/v1/admin/licenses",
            bearer=owner_access,
            headers={"Idempotency-Key": idempotency_key},
            body=online_request,
        )
        require_status(response, 200)
        assert response.json()["license"]["id"] == online_created["license"]["id"]
        response = client.request(
            "POST",
            "/api/v1/admin/licenses",
            bearer=owner_access,
            headers={"Idempotency-Key": f"retired-{unique.lower()}"},
            body=online_request,
        )
        require_status(response, 409)
        response = client.request(
            "POST",
            product_status_path,
            bearer=owner_access,
            body={"status": "active", "expectedRevision": retired_product["revision"]},
        )
        require_status(response, 200)
        assert response.json()["product"]["status"] == "active"

        response = client.request(
            "POST",
            "/api/v1/auth/refresh",
            body={"refreshToken": owner["refreshToken"]},
        )
        require_status(response, 200)
        rotated_refresh = response.json()["refreshToken"]
        response = client.request(
            "POST",
            "/api/v1/auth/refresh",
            body={"refreshToken": owner["refreshToken"]},
        )
        require_status(response, 401)
        response = client.request(
            "POST",
            "/api/v1/auth/refresh",
            body={"refreshToken": rotated_refresh},
        )
        require_status(response, 401)
    finally:
        client.close()
