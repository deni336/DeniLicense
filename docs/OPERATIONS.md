# Operations guide

## Required production configuration

- `DENILICENSE_ENV=production`
- PostgreSQL URL with `sslmode=verify-full` and a least-privilege application role
- independent 32-byte-or-longer base64url token, device, and issuance peppers
- activation issuer plus encrypted activation key, with passphrase delivered through a root-readable secret file
- explicit CORS origins
- HTTPS public-app and authenticated HTTPS email-webhook URLs for verification and password recovery

Configuration parsing is fail-closed: malformed booleans/durations, short secrets, wildcard production CORS, HTTP production email URLs, and exposed development tokens stop startup.

Run `denilicense migrate` as a deployment job with a TLS-verified PostgreSQL URL and a role allowed to change the schema. Production defaults `DENILICENSE_AUTO_MIGRATE` to false; the serving role then verifies the exact migration ledger at startup without issuing DDL. Grant the runtime role only the table/sequence operations it needs.

Configure `DENILICENSE_TRUSTED_PROXY_CIDRS` only for reverse proxies that overwrite client forwarding headers. Forwarded addresses from all other peers are ignored.

## Key lifecycle

Use unrelated offline and online keys. The service publishes the current signing key plus every public document in `DENILICENSE_ACTIVATION_VERIFICATION_KEY_FILES`. Before rotation, add the successor public key there and allow clients to fetch the expanded JWK set. Then switch the signer while retaining the prior public key until every lease it signed has expired. Move private signing behind a KMS/HSM adapter for high-value deployments. A revoked offline issuer is terminal; retroactively revoking all licenses from that issuer is intentionally a separate policy decision.

Back up public trust metadata, the database, and the online key configuration independently. Test restoration. Do not back up the offline issuer into the online environment.

Treat `DENILICENSE_ISSUANCE_PEPPER` as recovery-critical key material. Online issuance uses it to reproduce the same serial and one-time claim code for an idempotent retry without storing the plaintext code. Losing or rotating it in place prevents exact recovery of those responses and can turn a replay into a conflicting or duplicate business operation. Store it in a versioned secret manager, include it in encrypted recovery tests, and introduce an explicit versioned migration before any future rotation.

## Monitoring

Alert on repeated authentication/redeem failures, refresh-token reuse, conflicting offline serial imports, issuer changes, owner/role changes, unusual issuance volume or term, license revocation, and signer/readiness failure. Export structured logs and `audit_events` to storage that database administrators cannot rewrite.

Email webhook jobs are held in a bounded in-memory queue, retried three times, and drained on graceful shutdown so auth responses remain non-enumerating and independent of provider latency. Alert on delivery failures and queue saturation. This queue is not durable across a process/host crash; users can request a fresh token, but deployments requiring guaranteed delivery should replace it with an encrypted transactional outbox or a durable provider queue before launch.

Platform owners and auditors can read the bounded audit API at
`GET /api/v1/admin/audit-events`; use `beforeId` for descending pagination.
User role and status changes revoke that user's sessions and cannot remove the
final active platform owner. Maintain at least two independently controlled
owner accounts for recovery.

## Multi-instance deployments

PostgreSQL remains authoritative and transactional invariants work across replicas. The built-in token-bucket limiter is per-process; enforce account and source limits at a shared edge/Redis layer. Keep server clocks synchronized. Run schema migration once under the included PostgreSQL advisory lock before rolling out new binaries.
