"""Safe public SDK surface for product-side activation verification.

This module intentionally exposes verification and device proof operations only;
it never loads or accepts DeniLicense issuer signing keys.
"""

from .crypto.lease import (
    JWK,
    JWKS,
    VerifyOptions,
    device_key_thumbprint,
    verify_lease,
    verify_lease_jwk,
)
from .crypto.lease import (
    LeaseClaims as ActivationClaims,
)
from .crypto.renewal import RenewalChallenge, sign_renewal_challenge

__all__ = [
    "JWK",
    "JWKS",
    "ActivationClaims",
    "RenewalChallenge",
    "VerifyOptions",
    "device_key_thumbprint",
    "sign_renewal_challenge",
    "verify_lease",
    "verify_lease_jwk",
]
