# Python client integration

The supported product-side surface is `denilicense.client`. It exposes activation-lease verification, JWK parsing, installation-key thumbprints, and renewal proof signing. It deliberately does not expose offline or activation signing keys.

## Installation identity

Generate a distinct Ed25519 keypair on first launch. Store the private key in the strongest facility available on the target OS: a TPM or non-exportable key, Keychain, DPAPI/CNG, Android Keystore, or Secure Enclave. Do not derive it from mutable hardware fingerprints.

```python
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

device_private_key = Ed25519PrivateKey.generate()
device_public_key = device_private_key.public_key().public_bytes_raw()
device_public_key_wire = base64.urlsafe_b64encode(device_public_key).rstrip(b"=").decode("ascii")
```

Persist `device_private_key` through the OS keystore rather than a plaintext file. Send only `device_public_key_wire`, the canonical raw 32-byte public key in unpadded base64url form, when the authenticated customer approves an activation.

## Lease verification

Treat the product machine and every received lease as attacker-controlled. A `dllease1` lease is useful only after all of these checks succeed:

1. Enforce the three-component format, byte limits, canonical unpadded base64url, canonical claims, and Ed25519 signature.
2. Resolve `kid` only against a pinned key or the JWK set retrieved from the configured DeniLicense HTTPS origin. Never accept a token-supplied URL or embedded key.
3. Bind the configured activation issuer, product audience, and SHA-256 thumbprint of this installation public key.
4. Enforce `iat`, `nbf`, and exclusive `exp`, allowing only the small clock leeway your deployment requires.
5. Apply only the signed entitlement snapshot. Unsigned local settings must never add entitlements.

The SDK performs these checks. The following helper parses the untrusted `kid` only to select a candidate from the already trusted JWK set; `verify_lease_jwk` then authenticates the complete lease before any claim is used.

```python
import base64
import json
from datetime import timedelta

import httpx

from denilicense.client import (
    JWKS,
    VerifyOptions,
    device_key_thumbprint,
    verify_lease_jwk,
)


def untrusted_key_id(lease: str) -> str:
    parts = lease.split(".")
    if len(parts) != 3 or parts[0] != "dllease1":
        raise ValueError("malformed activation lease")
    encoded = parts[1]
    payload = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    value = json.loads(payload)
    if not isinstance(value, dict) or not isinstance(value.get("kid"), str):
        raise ValueError("malformed activation lease")
    return value["kid"]


origin = "https://licenses.example.com"
jwk_response = httpx.get(
    f"{origin}/.well-known/denilicense-activation-keys.json",
    timeout=5.0,
    follow_redirects=False,
)
jwk_response.raise_for_status()
jwks = JWKS.from_dict(jwk_response.json())

# `lease` is the string returned by activation or renewal.
candidate = jwks.lookup(untrusted_key_id(lease))
claims = verify_lease_jwk(
    lease,
    candidate,
    VerifyOptions(
        expected_issuer=origin,
        expected_audience="MYAPP",
        expected_device_key_thumbprint=device_key_thumbprint(device_public_key),
        clock_leeway=timedelta(minutes=1),
    ),
)

if claims.entitlements.get("feature.reporting") is True:
    enable_reporting()
```

Entitlements are a typed, flat, signed snapshot. Missing or incorrectly typed
values must fail closed, and unsigned configuration must never widen them. See
[License entitlements](ENTITLEMENTS.md) for the exact name, type, and payload
limits; UI, API, and offline issuance examples; safe boolean, integer, and enum
consumption; revision handling; and schema-evolution guidance.

Pin the service origin in application configuration. Retrieve the JWK set over authenticated HTTPS, apply normal response-size and timeout limits, and cache it according to policy. For installations that must verify while disconnected, ship or persist the expected public keys through a signed software update. Key-set retrieval is not a substitute for a trust anchor.

## Proof-of-possession renewal

Request a challenge with the activation UUID:

```http
POST /api/v1/activation-challenges
Content-Type: application/json

{"activationId":"00000000-0000-4000-8000-000000000000"}
```

Construct `RenewalChallenge` from the response and let the SDK validate the algorithm, canonical identifiers, nonce, expected activation, and server-provided transcript before signing. This prevents a compromised server response from turning the installation key into a generic signing oracle.

```python
from denilicense.client import RenewalChallenge, sign_renewal_challenge

challenge = RenewalChallenge.from_dict(challenge_response.json())
signature = sign_renewal_challenge(
    device_private_key,
    challenge,
    expected_activation_id=activation_id,
)

completion = {
    "challengeId": challenge.challenge_id,
    "nonce": challenge.nonce,
    "signature": signature,
}
```

Send `completion` to `POST /api/v1/activation-challenges/complete`. Challenges expire after five minutes and are consumed exactly once. Altered nonces, another installation key, inactive or expired licenses, and replayed challenges fail.

## Revocation and offline behavior

Online renewal observes suspension and revocation immediately. A lease already issued to a disconnected installation remains valid until its signed expiry. Choose the activation lease TTL and per-license offline grace for the business risk, and make that behavior explicit to customers.

A user who controls the device can patch local enforcement. Protect server-authoritative operations independently and use offline lease checks as one layer, not the sole control for high-value actions.
