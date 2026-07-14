# Security model

## Intended use

DeniLicense combines first-party user accounts with software-entitlement issuance and installation proof. It is not a delegated authorization protocol, external identity federation service, or replacement for third-party single sign-on.

The online service and PostgreSQL database are authoritative for accounts, claims, activation seats, renewal, and revocation. Signed grants permit an isolated issuer to authorize license creation without exposing that issuer's private key to the service. Signed leases permit a product to verify a bounded entitlement snapshot while temporarily disconnected.

## Separate credentials and keys

DeniLicense deliberately separates:

- account passwords and opaque API sessions;
- one-time customer claim codes;
- offline license issuer keys;
- online activation lease keys;
- per-installation device keys;
- server-side HMAC peppers for tokens, request-source identifiers, device state, and deterministic issuance recovery.

None is accepted in place of another. Possessing a license does not authenticate a human administrator. A valid account session cannot forge a signed offline grant or a device proof. An offline issuer cannot sign activation leases because key purpose is enforced in both encrypted and public key documents and again at signing boundaries.

## Protected assets

- **Offline issuer private keys:** encrypted with AES-256-GCM under a bounded scrypt-derived key, stored only on the isolated issuer workstation, and never copied to the online service.
- **Online activation signer:** currently loaded from an encrypted file. High-value deployments should adapt signing to non-exportable KMS/HSM keys.
- **Installation private keys:** generated per installation and retained in an OS keystore or hardware-backed facility where possible.
- **Passwords:** Argon2id with a per-password salt, bounded PHC parsing, and an optional separately managed pepper.
- **Access, refresh, email, and reset tokens:** random opaque values; only domain-separated HMACs are persisted.
- **Claim codes and challenge nonces:** random; only digests are persisted. Claim-code plaintext is not stored.
- **Issuance pepper:** recovery-critical secret used to reproduce retry-safe online issuance responses. It must be backed up and versioned rather than rotated in place.
- **Secret separation:** production startup rejects reuse across token, device, issuance, and optional password peppers so compromise of one purpose does not silently collapse every keyed boundary.
- **Public keys:** canonical 32-byte Ed25519 keys with explicit purpose and key ID. Unsafe identity and low-order points are rejected.

## Cryptographic formats

Offline grants use the `dlic1` format and activation leases use `dllease1`. Both use domain-separated Ed25519 signatures over exact canonical payload bytes. Parsers bound token and payload sizes, require canonical unpadded base64url, reject duplicate or unknown fields, and validate identifiers, times, entitlements, and key purpose.

Encrypted private-key documents authenticate their metadata as additional data, including algorithm, purpose, key ID, public key, KDF parameters, and nonce. This prevents metadata substitution from changing how a key is interpreted.

Cryptographic verification does not make an untrusted claim true outside its context. The caller must also provide the expected issuer, product, installation-key thumbprint, and verification time.

## Important invariants

- An offline grant's signature and exact canonical bytes are verified before any embedded claim becomes trusted.
- The issuer key must be active and valid at the grant's issue time. A revoked issuer cannot be reactivated through the API.
- Exact offline re-import is idempotent. Reusing a serial with different signed bytes is a conflict.
- Online issuance binds the administrator, idempotency key, and canonical request. A reused key with a different request is rejected.
- Claiming is one-time and transactionally binds a license to one account.
- A locked license row serializes seat counting, activation, state changes, and challenge completion.
- License revocation is terminal and deactivates existing activation rows. Suspension can be reversed by authorized policy.
- Renewal requires a fresh, short-lived, single-use server nonce and a signature from the private key bound to the activation.
- Renewal signing uses a locally reconstructed, domain-separated transcript. The product SDK does not sign arbitrary bytes supplied by a server.
- Leases bind issuer, product, license revision, activation, entitlements, device-key thumbprint, and a finite validity interval.
- Lease expiry is capped by server policy, per-license offline grace, and license expiry.
- Refresh-token rotation retains consumed hashes. Reuse revokes the entire session family.
- Authenticated users can inspect active sessions and revoke one or all other sessions. Password changes revoke every other session and outstanding reset link while preserving only the session that proved the current password.
- Public registration is email-first: pending records contain no usable caller-selected password, and the single-use verification-token holder installs the first password in the same transaction that verifies the email.
- Owner-created accounts use a single-use password-setup token; the owner never selects or receives the invitee's password.
- User role or status changes are atomic and revoke that user's sessions. The transaction rechecks the acting owner's current authority, rejects self-demotion or self-disablement, and prevents removal of the final active platform owner.
- Product retirement and reactivation use optimistic revisions and transactional administrator rechecks. Retirement blocks new requests, imports, and online issuance while preserving already-issued license verification and renewal behavior.
- Audit records are written in the same transaction as security-sensitive state changes where the store operation supports them.

## Account and API protections

Email normalization is strict, request objects reject unknown fields and type coercion, and authentication errors avoid revealing whether an account exists. Password verification uses bounded Argon2 concurrency to limit attacker-controlled resource consumption.

Browser origins are allowlisted. Wildcards and insecure production origins are rejected. The service adds restrictive content, frame, referrer, permissions, and cross-origin headers, plus HSTS in production. Access tokens are bearer credentials and must be protected from script injection, logs, crash reports, and insecure client storage.

The operations console identifies a machine by the domain-separated SHA-256
thumbprint of its installation public key and its user-supplied label. That ID
is stable and pseudonymous, not proof of a particular physical device. The
service deliberately does not collect IP addresses, hostnames, or hardware
fingerprints for inventory; deployments should define retention and label-data
policies appropriate to their privacy requirements.

Rate limiting reduces straightforward source-based abuse but is in-memory and per process. It is not a distributed denial-of-service control. Trusted proxy configuration must match only infrastructure that overwrites forwarding headers.

## Revocation semantics

The server observes account disablement, session revocation, issuer status, license suspension or revocation, and activation deactivation immediately for online operations. A previously issued lease is a self-contained offline credential and remains valid until its signed exclusive expiry.

Short lease lifetimes reduce revocation delay at the cost of more frequent online renewal. Permanently disconnected products cannot have immediate revocation or authoritative concurrent-seat enforcement.

## Residual risks

A customer controlling a product machine can patch local verification, inspect process memory, clone software state, manipulate the clock, or restore VM snapshots. Hardware-backed non-exportable installation keys reduce export risk but cannot make a hostile host trustworthy.

Application-server compromise can authorize policy-valid signatures while the service remains compromised, even if KMS/HSM prevents private-key extraction. Database compromise can alter authoritative account and entitlement state. Offline-issuer compromise permits forged grants under that issuer until the public key is revoked and administrators respond.

The current release does not include WebAuthn, passkeys, MFA ceremonies, organization tenancy, row-level tenant isolation, a durable email outbox, a shared rate limiter, immutable external audit storage, or a KMS/HSM adapter. These are explicit deployment boundaries, not hidden assurances.

Before production, threat-model the actual product, administrators, tenant model, recovery path, deployment platform, and economic value. Commission independent cryptographic review and penetration testing, and assess the deployment against OWASP ASVS Level 2 or a stronger standard appropriate to its risk.
