# Security model

## Separate credentials and keys

DeniLicense deliberately separates:

- account passwords and opaque web/API sessions;
- one-time customer claim codes;
- offline license issuer keys;
- online activation lease keys;
- per-installation device keys.

None is accepted in place of another. License possession does not authenticate a human administrator, and a web session cannot forge a signed license or device proof.

## Protected assets

- Offline issuer private keys: encrypted at rest and never copied to the online server.
- Online signer: currently loaded from an encrypted file; a production adapter should use non-exportable KMS/HSM signing.
- Claim codes, session tokens, email tokens, password reset tokens, and challenge nonces: random; only a digest/HMAC is persisted.
- Passwords: Argon2id with per-password salt, bounded PHC parsing, and optional separately managed pepper.
- Public keys: strict canonical on-curve prime-subgroup Ed25519 validation prevents low-order/identity-key attacks.

## Important invariants

- Offline grant signature and exact canonical bytes are verified before claims become trusted.
- Issuer status and validity are checked at import; revoked keys cannot be restored through the API.
- Claiming is one-time and transactionally binds a license to one account.
- A locked license row serializes seat count and activation creation.
- License revocation is terminal and deactivates existing activation rows.
- Renewal requires a fresh, single-use server nonce plus proof of the bound device private key.
- Leases bind issuer, product, license revision, activation, entitlements, device thumbprint, and a finite validity interval.
- Refresh token rotation retains consumed hashes; reuse revokes the entire session family.
- Online issuance binds the administrator, idempotency key, and canonical request. Its issuance pepper is a backed-up, non-rotating recovery secret for the current key version.

## Residual risks

Client-side enforcement can be patched by the owner of the machine. VM snapshots can clone local state, local clocks can be manipulated, and permanently disconnected clients cannot receive immediate revocation. Database or application-server compromise may alter authoritative state; KMS/HSM prevents direct key extraction but cannot stop an authorized compromised service from requesting policy-compliant signatures until contained.

Before production, threat-model the actual product, tenant model, recovery path, administrators, deployment platform, and economic value. Run independent review against OWASP ASVS Level 2 or stronger.
