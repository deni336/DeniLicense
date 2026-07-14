from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from denilicense.crypto.claim_code import digest, from_entropy, parse
from denilicense.crypto.common import (
    InvalidPublicKey,
    b64url_encode,
    format_rfc3339_preserving,
    parse_rfc3339,
    validate_ed25519_public_key,
)
from denilicense.crypto.keys import (
    ACTIVATION_RECEIPT_SIGNER,
    OFFLINE_LICENSE_ISSUER,
    InvalidKeyFile,
    KeyDecryptionFailed,
    ScryptParams,
    SigningKey,
    decrypt_signing_key,
    encrypt_signing_key,
    marshal_public_key,
    parse_public_key,
)
from denilicense.crypto.license import (
    InvalidSignature,
    LicenseClaims,
    VerificationOptions,
    encode_claim_code_digest,
    sign_token,
    verify_token,
    verify_token_for_use,
)

_GO_DLIC1 = (
    "dlic1.eyJpc3MiOiJpc3N1ZXIuZXhhbXBsZSIsImtpZCI6IlZrZGFwMVJqUjB3Q2hkOWR2eXZLdHoybVVUV0lP"
    "ZW0zZElHeTZyRUhjSXciLCJhdWQiOiJQUk9EVUNUIiwianRpIjoiMTExMTExMTEtMTExMS00MTExLTgxMTEtMTEx"
    "MTExMTExMTExIiwic3ViIjoiY3VzdG9tZXIiLCJjbGFpbV9jb2RlX3NoYTI1NiI6Ik10aGlNNFV5UFdUeWkxY3dr"
    "UDRKSzNTTG5sNURldUhwMlYwbjhjWnpCQzAiLCJjbGFpbV9jb2RlX3N1ZmZpeCI6IkVFMVMiLCJpYXQiOiIyMDI2"
    "LTAxLTAyVDAzOjA0OjA1LjEyMzQ1NloiLCJuYmYiOiIyMDI2LTAxLTAyVDAzOjA0OjA1LjEyMzQ1NloiLCJleHAi"
    "OiIyMDI2LTAxLTAzVDAzOjA0OjA1LjEyMzQ1NloiLCJtYXhfYWN0aXZhdGlvbnMiOjIsImVudGl0bGVtZW50cyI6"
    "eyJmZWF0dXJlcyI6MywicHJvIjp0cnVlfX0.VJ-XYnhg_MDRN6r_Q8zubf3h8CiaLGPVWKfcWBlY7EkairE1Rown"
    "ZWH1RWBn7vRxtk04a_ySNjnWAOW8i57jDw"
)


def _claims(key: SigningKey) -> LicenseClaims:
    issued = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
    code = from_entropy(b"01234567890123456789")
    return LicenseClaims(
        issuer="issuer.example",
        key_id=key.key_id,
        audience="PRODUCT",
        serial="11111111-1111-4111-8111-111111111111",
        subject="customer",
        claim_code_sha256=encode_claim_code_digest(code.digest),
        claim_code_suffix=code.suffix,
        issued_at=issued,
        not_before=issued,
        expires_at=issued + timedelta(days=1),
        max_activations=2,
        entitlements={"features": 3, "pro": True},
    )


def test_claim_code_is_160_bit_checksummed_and_domain_separated() -> None:
    code = from_entropy(bytes(20))
    assert code.display == "DNL1-00000-00000-00000-00000-00000-00000-009B"
    assert parse(code.display.lower()) == bytes(20)
    assert digest(code.display) == code.digest
    with pytest.raises(ValueError):
        parse(code.display[:-1] + "N")


def test_python_dlic1_exactly_matches_go_wire_contract() -> None:
    key = SigningKey.from_seed(bytes(range(32)), OFFLINE_LICENSE_ISSUER)
    token = sign_token(_claims(key), key)
    assert token == _GO_DLIC1
    assert verify_token(_GO_DLIC1, key.verification_key).serial == "11111111-1111-4111-8111-111111111111"
    assert (
        verify_token_for_use(
            token,
            key.verification_key,
            VerificationOptions("issuer.example", "PRODUCT", datetime(2026, 1, 2, 4, tzinfo=UTC)),
        ).entitlements["pro"]
        is True
    )


def test_go_map_order_and_nanosecond_times_remain_canonical() -> None:
    key = SigningKey.from_seed(bytes(range(32)), OFFLINE_LICENSE_ISSUER)
    claims = _claims(key)
    claims.entitlements = {"z-last": True, "a-first": 1}
    assert b'"entitlements":{"a-first":1,"z-last":true}' in claims.canonical_json()
    raw = "2026-01-02T03:04:05.123456789Z"
    assert format_rfc3339_preserving(parse_rfc3339(raw), raw) == raw


def test_license_rejects_noncanonical_and_tampered_tokens() -> None:
    key = SigningKey.from_seed(bytes(range(32)), OFFLINE_LICENSE_ISSUER)
    token = sign_token(_claims(key), key)
    parts = token.split(".")
    payload = json.loads(__import__("base64").urlsafe_b64decode(parts[1] + "=="))
    noncanonical = json.dumps(payload, indent=1).encode()
    forged = f"dlic1.{b64url_encode(noncanonical)}.{parts[2]}"
    with pytest.raises(InvalidSignature):
        verify_token(forged, key.verification_key)
    with pytest.raises(ValueError):
        sign_token(_claims(key), SigningKey.from_seed(bytes(range(32)), ACTIVATION_RECEIPT_SIGNER))


def test_encrypted_key_and_public_file_round_trip_and_authenticate_metadata() -> None:
    key = SigningKey.from_seed(bytes(range(32)), OFFLINE_LICENSE_ISSUER)
    encrypted = encrypt_signing_key(key, "this is a strong passphrase", ScryptParams(n=1 << 14))
    assert decrypt_signing_key(encrypted, "this is a strong passphrase").key_id == key.key_id
    with pytest.raises(KeyDecryptionFailed):
        decrypt_signing_key(encrypted, "this is the wrong passphrase")

    document = json.loads(encrypted)
    document["purpose"] = ACTIVATION_RECEIPT_SIGNER
    with pytest.raises(KeyDecryptionFailed):
        decrypt_signing_key(
            json.dumps(document, separators=(",", ":")).encode(), "this is a strong passphrase"
        )

    public = marshal_public_key(key.verification_key)
    assert parse_public_key(public).public_bytes == key.public_bytes
    duplicate = public[:-1] + b',"kid":"bad"}'
    with pytest.raises(InvalidKeyFile):
        parse_public_key(duplicate)


def test_unsafe_ed25519_identity_point_is_rejected() -> None:
    with pytest.raises(InvalidPublicKey):
        validate_ed25519_public_key(b"\x01" + bytes(31))
