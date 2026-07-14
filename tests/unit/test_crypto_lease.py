from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from denilicense.crypto.common import b64url_encode
from denilicense.crypto.keys import ACTIVATION_RECEIPT_SIGNER, SigningKey
from denilicense.crypto.lease import (
    JWK,
    JWKS,
    InvalidLeaseSignature,
    LeaseClaims,
    VerifyOptions,
    device_key_thumbprint,
    sign_lease,
    verify_lease,
    verify_lease_jwk,
)
from denilicense.crypto.renewal import RenewalChallenge, sign_renewal_challenge, verify_renewal_signature

_GO_DLLEASE1 = (
    "dllease1.eyJ2ZXIiOjEsInR5cCI6ImFjdGl2YXRpb24tbGVhc2UiLCJpc3MiOiJodHRwczovL2lzc3Vlci5leGFt"
    "cGxlIiwia2lkIjoiVmtkYXAxUmpSMHdDaGQ5ZHZ5dkt0ejJtVVRXSU9lbTNkSUd5NnJFSGNJdyIsImp0aSI6IjIy"
    "MjIyMjIyLTIyMjItNDIyMi04MjIyLTIyMjIyMjIyMjIyMiIsImxpY2Vuc2VfaWQiOiIzMzMzMzMzMy0zMzMzLTQz"
    "MzMtODMzMy0zMzMzMzMzMzMzMzMiLCJhY3RpdmF0aW9uX2lkIjoiNDQ0NDQ0NDQtNDQ0NC00NDQ0LTg0NDQtNDQ0"
    "NDQ0NDQ0NDQ0IiwiYXVkIjoiUFJPRFVDVCIsImxpY2Vuc2VfcmV2aXNpb24iOjMsImRldmljZV9rZXlfc2hhMjU2"
    "IjoiMlRUTWtoY0dleDVodXRDc1FzVnVBSGRDMEQ2cHVSd2hUQlZoY2xlbkJTZyIsImVudGl0bGVtZW50cyI6eyJm"
    "ZWF0dXJlcyI6MywicHJvIjp0cnVlfSwiaWF0IjoiMjAyNi0wMS0wMlQwMzowNDowNS4xMjM0NTZaIiwibmJmIjoi"
    "MjAyNi0wMS0wMlQwMzowNDowNS4xMjM0NTZaIiwiZXhwIjoiMjAyNi0wMS0wM1QwMzowNDowNS4xMjM0NTZaIn0."
    "83OTNhArokLS88wEZsAWTIyFLgoLqp32GC9DNJxUf0XvD3Pp9o4p4vaSDNTscBDoMl2zK3xe9n9PT8aXOwH4Dg"
)


def _fixture() -> tuple[SigningKey, bytes, LeaseClaims, VerifyOptions]:
    issuer = SigningKey.from_seed(bytes(range(32)), ACTIVATION_RECEIPT_SIGNER)
    device = (
        Ed25519PrivateKey.from_private_bytes(b"abcdefghijklmnopqrstuvwxyzABCDEF")
        .public_key()
        .public_bytes_raw()
    )
    issued = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
    claims = LeaseClaims(
        issuer="https://issuer.example",
        key_id=issuer.key_id,
        jwt_id="22222222-2222-4222-8222-222222222222",
        license_id="33333333-3333-4333-8333-333333333333",
        activation_id="44444444-4444-4444-8444-444444444444",
        audience="PRODUCT",
        license_revision=3,
        device_key_thumbprint=device_key_thumbprint(device),
        entitlements={"features": 3, "pro": True},
        issued_at=issued,
        not_before=issued,
        expires_at=issued + timedelta(days=1),
    )
    options = VerifyOptions(
        "https://issuer.example",
        "PRODUCT",
        claims.device_key_thumbprint,
        datetime(2026, 1, 2, 4, tzinfo=UTC),
    )
    return issuer, device, claims, options


def test_python_dllease1_exactly_matches_go_wire_contract() -> None:
    issuer, _, claims, options = _fixture()
    assert sign_lease(claims, issuer) == _GO_DLLEASE1
    assert verify_lease(_GO_DLLEASE1, issuer.public_bytes, options).license_revision == 3


def test_jwk_and_jwks_validate_binding_and_verify() -> None:
    issuer, _, claims, options = _fixture()
    token = sign_lease(claims, issuer)
    jwk = JWK.from_public_key(issuer.public_bytes)
    assert JWKS((jwk,)).lookup(issuer.key_id) == jwk
    assert verify_lease_jwk(token, jwk, options).activation_id == claims.activation_id
    with pytest.raises(ValueError):
        JWKS((jwk, jwk)).lookup(issuer.key_id)


def test_lease_tamper_and_device_mismatch_fail_closed() -> None:
    issuer, _, claims, options = _fixture()
    token = sign_lease(claims, issuer)
    with pytest.raises(InvalidLeaseSignature):
        verify_lease(token[:-1] + ("A" if token[-1] != "A" else "B"), issuer.public_bytes, options)
    with pytest.raises(ValueError):
        verify_lease(
            token,
            issuer.public_bytes,
            VerifyOptions(
                options.expected_issuer, options.expected_audience, b64url_encode(bytes(32)), options.now
            ),
        )


def test_structured_renewal_transcript_is_reconstructed_before_signing() -> None:
    device = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    challenge_id = "55555555-5555-4555-8555-555555555555"
    activation_id = "44444444-4444-4444-8444-444444444444"
    nonce = b64url_encode(bytes(range(32)))
    transcript = (
        b"DeniLicense\x00activation-renewal\x00v1\x00"
        + challenge_id.encode()
        + b"\x00"
        + activation_id.encode()
        + b"\x00"
        + nonce.encode()
    )
    challenge = RenewalChallenge(challenge_id, activation_id, nonce, "Ed25519", b64url_encode(transcript))
    signature = sign_renewal_challenge(device, challenge, activation_id)
    verify_renewal_signature(device.public_key().public_bytes_raw(), challenge, signature)
    altered = RenewalChallenge(
        challenge_id, activation_id, nonce, "Ed25519", b64url_encode(transcript + b"!")
    )
    with pytest.raises(ValueError):
        sign_renewal_challenge(device, altered, activation_id)
