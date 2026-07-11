# Client integration

## Installation identity

Generate a distinct Ed25519 keypair on first launch. Store the private key in the strongest OS facility available (TPM/non-exportable key, Keychain, DPAPI/CNG, Android Keystore, or Secure Enclave). Do not derive it from mutable hardware fingerprints. Send only the canonical raw 32-byte public key as unpadded base64url when the customer approves an activation.

## Lease verification

Treat the product machine as attacker-controlled and fail closed. For each `dllease1` lease:

1. Enforce the exact three-component format, size limits, canonical unpadded base64url, and Ed25519 only.
2. Select `kid` only from a pinned or securely retrieved DeniLicense JWK set. Never accept a token-supplied URL or embedded public key.
3. Verify the domain-separated Ed25519 signature over the exact received payload bytes.
4. Strictly parse the canonical claims and reject unknown/duplicate fields.
5. Compare the configured issuer, product audience, and SHA-256 thumbprint of the installation public key.
6. Check `iat`, `nbf`, and exclusive `exp` with no more than the small allowed clock leeway.
7. Apply only the signed entitlement snapshot. Never let unsigned local configuration add entitlements.

Go products can import `github.com/deni336/DeniLicense/client` for lease verification, JWK types, device thumbprints, and renewal-transcript signing. Port the repository's positive and adversarial vectors when building SDKs for other languages.

## Proof-of-possession renewal

Call `POST /api/v1/activation-challenges` with the activation UUID. Treat the response as structured data: require the expected activation UUID, a canonical challenge UUID, the `Ed25519` algorithm, and a canonical 32-byte nonce. Reconstruct `DeniLicense\0activation-renewal\0v1\0<challenge UUID>\0<activation UUID>\0<nonce base64url>`, then require the returned base64url `transcript` to match before signing. Never pass an arbitrary server-supplied byte string to a long-lived device signing key. Go clients should use `client.SignRenewalChallenge`, which performs these checks and validates private-key consistency.

Send the canonical base64url signature, original nonce, and challenge ID to `/api/v1/activation-challenges/complete`. Challenges expire after five minutes and are consumed once. A replay, altered nonce, other installation key, inactive license, or expired license fails.

## Revocation semantics

Online introspection or renewal sees suspension/revocation immediately. An already issued offline lease remains valid until its signed expiry. Keep lease TTLs short enough for the business risk and make the user-visible offline grace policy explicit.
