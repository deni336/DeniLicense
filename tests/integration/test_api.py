"""Live-container integration coverage for the complete licensing lifecycle."""

from __future__ import annotations

import base64
import os
import time
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
            body={"email": customer_email, "password": customer_password},
        )
        require_status(response, 202)
        verification_token = response.json().get("developmentVerificationToken", "")
        assert verification_token, "development verification token missing"

        response = client.request(
            "POST",
            "/api/v1/auth/verify-email",
            body={"token": verification_token},
        )
        require_status(response, 200)
        customer = login(client, customer_email, customer_password)
        customer_access = customer["accessToken"]

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

        managed_password = "managed admin correct horse password"  # noqa: S105 - test fixture
        response = client.request(
            "POST",
            "/api/v1/auth/password-reset/confirm",
            body={"token": managed_setup_token, "newPassword": managed_password},
        )
        require_status(response, 204)
        managed_session = login(client, managed_email, managed_password)
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
            body={"role": "platform_owner", "status": "disabled"},
        )
        require_status(response, 409)

        response = client.request(
            "POST",
            f"/api/v1/admin/users/{managed_id}/access",
            bearer=owner_access,
            body={"role": "auditor", "status": "active"},
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

        # The intentionally small login bucket needs time to refill before the
        # refresh-family checks so rate limiting cannot mask token reuse behavior.
        time.sleep(7)
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
