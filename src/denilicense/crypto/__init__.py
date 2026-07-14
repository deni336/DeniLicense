"""Public cryptographic API for DeniLicense issuers and product clients."""

from .claim_code import (
    ClaimCode,
)
from .claim_code import (
    digest as claim_code_digest,
)
from .claim_code import (
    generate as generate_claim_code,
)
from .claim_code import (
    parse as parse_claim_code,
)
from .common import DeniLicenseError, InvalidClaims, InvalidPublicKey, NonCanonicalPayload
from .keys import (
    ACTIVATION_RECEIPT_SIGNER,
    OFFLINE_LICENSE_ISSUER,
    InvalidKeyFile,
    KeyDecryptionFailed,
    ScryptParams,
    SigningKey,
    VerificationKey,
    WrongKeyPurpose,
    decrypt_signing_key,
    encrypt_signing_key,
    marshal_public_key,
    parse_public_key,
)
from .lease import (
    JWK,
    JWKS,
    LeaseClaims,
    device_key_thumbprint,
    key_id,
    new_jwt_id,
    sign_lease,
    verify_lease,
    verify_lease_jwk,
)
from .lease import (
    VerifyOptions as LeaseVerifyOptions,
)
from .license import (
    LicenseClaims,
    generate_serial,
    inspect_unverified,
    sign_token,
    verify_token,
    verify_token_for_use,
)
from .license import (
    VerificationOptions as LicenseVerificationOptions,
)
from .renewal import (
    RenewalChallenge,
    sign_renewal_challenge,
    validate_renewal_challenge,
    verify_renewal_signature,
)

__all__ = [
    "ACTIVATION_RECEIPT_SIGNER",
    "JWK",
    "JWKS",
    "OFFLINE_LICENSE_ISSUER",
    "ClaimCode",
    "DeniLicenseError",
    "InvalidClaims",
    "InvalidKeyFile",
    "InvalidPublicKey",
    "KeyDecryptionFailed",
    "LeaseClaims",
    "LeaseVerifyOptions",
    "LicenseClaims",
    "LicenseVerificationOptions",
    "NonCanonicalPayload",
    "RenewalChallenge",
    "ScryptParams",
    "SigningKey",
    "VerificationKey",
    "WrongKeyPurpose",
    "claim_code_digest",
    "decrypt_signing_key",
    "device_key_thumbprint",
    "encrypt_signing_key",
    "generate_claim_code",
    "generate_serial",
    "inspect_unverified",
    "key_id",
    "marshal_public_key",
    "new_jwt_id",
    "parse_claim_code",
    "parse_public_key",
    "sign_lease",
    "sign_renewal_challenge",
    "sign_token",
    "validate_renewal_challenge",
    "verify_lease",
    "verify_lease_jwk",
    "verify_renewal_signature",
    "verify_token",
    "verify_token_for_use",
]
