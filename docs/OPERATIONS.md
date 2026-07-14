# Operations guide

## Development containers

The included Compose stack builds the Python 3.14 image, starts PostgreSQL 17, creates a development activation key in a named volume, applies migrations on API startup, and binds both services to loopback ports.

```powershell
docker compose up --build -d --wait
docker compose ps
Invoke-RestMethod http://127.0.0.1:8080/ready
docker compose logs api
```

Create the first owner after the stack is healthy:

```powershell
docker compose run --rm api bootstrap-owner --email owner@example.com
```

Stop the containers with `docker compose down`. Add `--volumes` only when you intentionally want to destroy the development database and generated activation key.

## Container-to-container access

The development Compose stack publishes the browser UI on host loopback and
also attaches the API to a stable Docker bridge named `denilicense-network`.
The API has the network alias `denilicense-api`. PostgreSQL remains on a
separate backend bridge and is not exposed to application containers attached
only to the integration bridge. Its development port is published only on host
loopback so the repository-level `python main.py` launcher can use the same
database without opening it to the LAN.

Start DeniLicense first so Docker creates the bridge. In the other project's
Compose file, attach only the service that needs licensing:

```yaml
services:
  your-app:
    environment:
      DENILICENSE_URL: http://denilicense-api:8080
    networks:
      - default
      - denilicense

networks:
  denilicense:
    external: true
    name: denilicense-network
```

Use `http://denilicense-api:8080`, not `localhost`, from that container.
Neither Docker Desktop's host-networking option nor `network_mode: host` is
required. Networks are a runtime Compose concern, so no Dockerfile network tag
exists or is needed.

`DENILICENSE_ACTIVATION_ISSUER` is the logical issuer embedded in signed leases.
Product code must validate the configured issuer exactly even when it fetches
the API or JWK set through the `denilicense-api` network alias. In production,
set the issuer to the stable public HTTPS identity shared by every client.

The Compose credentials, peppers, key passphrase, HTTP listener, and database TLS setting are intentionally unsafe outside local development.

## Required production configuration

At minimum, set:

- `DENILICENSE_ENV=production`.
- `DENILICENSE_DATABASE_URL` with exactly one `sslmode=verify-full` query parameter and a least-privilege role.
- Independent unpadded base64url values of at least 32 decoded bytes for `DENILICENSE_TOKEN_PEPPER`, `DENILICENSE_DEVICE_PEPPER`, and `DENILICENSE_ISSUANCE_PEPPER`.
- `DENILICENSE_ACTIVATION_ISSUER`, `DENILICENSE_ACTIVATION_KEY_FILE`, and a root-readable `DENILICENSE_ACTIVATION_KEY_PASSPHRASE_FILE`.
- Explicit HTTPS origins in `DENILICENSE_ALLOWED_ORIGINS` for browser clients,
  including the exact origin that serves the embedded `/ui/` console.
- HTTPS `DENILICENSE_PUBLIC_APP_URL` and `DENILICENSE_EMAIL_WEBHOOK_URL`, plus a webhook bearer value of at least 32 characters.
- `DENILICENSE_AUTO_MIGRATE=false` for a serving role that should not issue DDL.

The configuration parser fails closed. Malformed booleans or durations, short or reused production peppers, wildcard or HTTP production origins, an HTTP production webhook, missing recovery email delivery, and unverified production database TLS stop startup. The token, device, issuance, and optional password peppers must all be independently generated in production.

`DENILICENSE_PASSWORD_PEPPER` is optional but, when set, must also be unpadded base64url encoding at least 32 bytes. Rotating it requires a deliberate password-rehash strategy.

Set `DENILICENSE_REGISTRATION_MODE` to `open` or `closed`. Open registration requires a working email webhook, except when development token exposure is explicitly enabled outside production. Public registration records only an email and a short-lived token; the token holder proves email ownership and chooses the first password atomically. In either mode, a platform owner can invite an account from the embedded console without assigning a shared temporary password. The invitee chooses their own password with a short-lived, single-use setup token.

## Schema migration

Run migration as a separate deployment job with a PostgreSQL role permitted to modify the schema:

```powershell
$env:DENILICENSE_ENV = 'production'
$env:DENILICENSE_DATABASE_URL = 'postgresql://migration-role@db.example/denilicense?sslmode=verify-full'
denilicense migrate
```

Migrations are embedded in the Python package, serialized with a PostgreSQL advisory lock, and recorded with filenames and SHA-256 checksums. The server verifies the exact migration ledger when automatic migration is disabled and refuses to start on missing, unknown, or modified migrations.

Grant the runtime role only the table and sequence operations it needs. Run one migration job before rolling out new service instances.

## Network and proxy configuration

Serve DeniLicense behind an HTTPS reverse proxy or load balancer. The Python process listens at `DENILICENSE_HTTP_ADDRESS`; it does not terminate production TLS itself.

Configure `DENILICENSE_TRUSTED_PROXY_CIDRS` only with networks belonging to reverse proxies that overwrite `X-Forwarded-For`. Forwarded addresses from untrusted peers are ignored. A bad forwarded chain from a trusted peer falls back to the direct peer rather than trusting arbitrary input.

The application adds request IDs, restrictive browser security headers, and HSTS in production. Preserve `X-Request-ID` in log aggregation and return it to support staff with problem responses.

Use `/live` only for process liveness. `/ready` checks the database and is the appropriate readiness probe. The public JWK set and generated OpenAPI document are available at:

- `/.well-known/denilicense-activation-keys.json`
- `/openapi.yaml`

## Key lifecycle

Use unrelated keys for offline license issuance and online activation signing.

Generate an online key in a protected administrative environment:

```powershell
denilic keygen --purpose activation `
  --private secrets/activation.key.json `
  --public secrets/activation.public.json
```

In production, pass the encrypted private document through `DENILICENSE_ACTIVATION_KEY_FILE` and deliver its passphrase through a separately mounted, root-readable file. The current file-backed signer should be replaced by a KMS/HSM adapter for high-value deployments.

For rotation, add successor or retained public documents to the comma-separated `DENILICENSE_ACTIVATION_VERIFICATION_KEY_FILES`. Publish the expanded JWK set before switching signers. Keep the previous public key available until every lease it signed has expired. At most 32 additional verification keys are accepted.

An offline issuer can move from active to retired or revoked. Revocation is terminal for that key; it prevents future imports but does not silently rewrite the state of licenses already imported. Make retroactive license policy explicit.

Back up public trust metadata, the database, the online key configuration, and recovery instructions independently. Never copy the offline issuer private key into the online environment.

## Recovery-critical issuance pepper

Online issuance derives its deterministic serial and one-time claim-code response from `DENILICENSE_ISSUANCE_PEPPER`, the administrator identity, and the idempotency key. This supports exact retry recovery without storing the plaintext code.

Treat that pepper as non-rotating recovery key material for the current derivation version. Losing or changing it in place prevents exact recovery of previous idempotent responses and can turn a retry into a duplicate or conflicting business operation. Store it in a versioned secret manager, include it in encrypted recovery tests, and design an explicit versioned migration before rotation.

## Email delivery

Verification, password-reset, and owner-created account-setup jobs enter a bounded in-memory queue with 256 slots and two worker threads. Delivery uses a ten-second HTTP timeout, rejects redirects, retries three times with short backoff, and drains until `DENILICENSE_SHUTDOWN_TIMEOUT` during graceful shutdown.

Expired token/session rows are pruned hourly. Abandoned, unverified customer registrations with no license or request references are deleted after 30 days without a fresh registration or verification request; registering the address again restarts that retention window and the email-ownership ceremony.

This keeps authentication responses non-enumerating and independent of provider latency, but it is not durable across process or host failure. Users can request fresh tokens. Deployments requiring guaranteed delivery should use an encrypted transactional outbox or durable provider queue before launch. Alert on queue saturation and final delivery failures without logging raw tokens.

## Monitoring and audit

Alert on repeated authentication and claim failures, refresh-token reuse, conflicting offline serial imports, issuer changes, owner or role changes, unusual issuance volume or terms, license revocation, email delivery failure, migration mismatch, database readiness failure, and signer failure.

Export application logs and `audit_events` to storage that application and database administrators cannot rewrite. Platform owners and auditors can page backward through `GET /api/v1/admin/audit-events` with the descending `beforeId` cursor and filters. User creation and access changes are audited. Role or status changes revoke that user's sessions, cannot modify the acting owner's own access, and cannot remove the final active platform owner. Maintain at least two independently controlled owner accounts.

The maintenance thread removes expired session, refresh-token, email-token, password-reset-token, and activation-challenge rows in bounded batches each hour. PostgreSQL remains the authoritative security state.

## Multiple service instances

Database locks and transactions preserve claim, seat, renewal, final-owner, and idempotency invariants across replicas. Server clocks must remain synchronized.

The built-in token-bucket limiter is process-local. Enforce account and source limits at a shared edge or shared data store before scaling horizontally. Coordinate activation-key configuration across instances, publish all valid verification keys, and perform migration once before the rollout.

## Backup and incident preparation

Test encrypted database restoration, issuance-pepper recovery, activation-key recovery and rotation, owner-account recovery, and offline public-key inventory. Define RPO/RTO and rehearse response to database compromise, activation-signer compromise, offline-issuer loss, and refresh-token reuse alerts.

A database restore and an activation-key restore are separate concerns. Preserve previous activation public keys long enough to verify outstanding leases, while never restoring a compromised private key into service.
