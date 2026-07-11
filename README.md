# DeniLicense

DeniLicense is a first-party account and software-entitlement service with an air-gapped issuance workflow. It lets an offline administrator generate a high-entropy claim code plus a signed grant, transfer only the public key and grant to the online service, and then let a registered customer claim and activate the license.

It does **not** reimplement OAuth. OAuth/OIDC is still the right tool for third-party delegated access or external SSO. DeniLicense replaces that dependency only when your actual requirement is first-party accounts plus proof that an account or installation owns a software entitlement.

## What is implemented

- Go service and network-free offline issuer CLI, both shipped as standalone binaries.
- PostgreSQL migrations and transactional license, claim, activation, and audit state.
- Argon2id passwords; opaque HMAC-indexed access tokens; rotating refresh tokens with reuse-family revocation.
- Non-enumerating registration, email verification, and password-reset flows through a private email webhook.
- Five server-enforced roles, with offline issuer registration restricted to the platform owner.
- 160-bit Crockford Base32 one-time claim codes. The database stores only a domain-separated digest and four-character support suffix.
- Passphrase-encrypted Ed25519 issuer keys using bounded scrypt and AES-256-GCM.
- Strict, canonical, bounded `dlic1` offline grants with issuer, product, validity, entitlement, and activation-limit checks.
- Exact offline re-import idempotency and conflicting-serial detection.
- Retry-safe online issuance using required idempotency keys without storing plaintext claim codes.
- Transactional activation-seat enforcement under a license row lock.
- Strict, short-lived, device-bound `dllease1` activation leases signed by a separate online key.
- Ed25519 device proof-of-possession renewal challenges with replay protection.
- Public JWK set, OpenAPI document, RFC-style errors, CORS allowlist, security headers, rate limits, request IDs, and audit records.
- Unit, fuzz-seed, race, cryptographic regression, and live PostgreSQL end-to-end tests.

## Trust model

```text
Air-gapped issuer                Online DeniLicense                 Product installation
-----------------               ------------------                 --------------------
offline private key             issuer public key only             device private key
       |                                  |                                  |
claim code + signed grant ---> admin imports grant                          |
       |                                  |                                  |
customer receives code ------> account claims license                       |
                                          | <--- customer approves device public key
                                          | ---- signed, device-bound lease ->
                                          | <--- signed one-time renewal proof
                                          | ---- fresh short-lived lease ---->
```

The offline license private key never belongs on the server. The online activation signer is a separate key and should be moved behind a KMS/HSM before a high-value production deployment. Distributed product code contains public verification keys only.

## Quick start

Requirements: Go 1.26.5+ and Docker with Compose. Patch-level upgrades matter because Go binaries include the standard library.

```powershell
docker compose up --build -d --wait
docker compose run --rm api bootstrap-owner --email owner@example.com
```

The bootstrap command prompts for the owner password without putting it in shell history or process arguments.

The development API listens on `http://127.0.0.1:8080`. Its machine-readable API document is at `http://127.0.0.1:8080/openapi.yaml`.

Log in and create a product:

```powershell
$login = Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/auth/login `
  -ContentType application/json `
  -Body (@{ email='owner@example.com'; password='use a password manager value' } | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.accessToken)" }

Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/admin/products `
  -Headers $headers -ContentType application/json `
  -Body (@{ code='MYAPP'; name='My Application'; description='Desktop edition' } | ConvertTo-Json)
```

The Compose secrets and database password are intentionally predictable development values. Never deploy them.

## Offline issuance

Build or copy only `denilic` to the offline workstation:

```powershell
go build -trimpath -o bin/denilic.exe ./cmd/denilic
bin/denilic.exe secret # run separately for each server pepper
New-Item -ItemType Directory -Force secrets | Out-Null
bin/denilic.exe keygen --purpose license `
  --private secrets/offline-issuer.key.json `
  --public secrets/offline-issuer.public.json
```

Keep the encrypted private file and its passphrase offline. Transfer the public JSON to the server and register it once:

```powershell
$publicDocument = Get-Content -Raw secrets/offline-issuer.public.json
Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/admin/issuers `
  -Headers $headers -ContentType application/json `
  -Body (@{
    issuer='com.example.offline-issuer'
    publicKeyDocument=$publicDocument
  } | ConvertTo-Json)
```

Back on the offline workstation, issue a grant. `--expires`, `--valid-for`, or the explicit `--perpetual` override is required:

```powershell
bin/denilic.exe issue `
  --key secrets/offline-issuer.key.json `
  --issuer com.example.offline-issuer `
  --product MYAPP `
  --subject customer-1042 `
  --valid-for 8760h `
  --max-activations 3 `
  --entitlement feature.reporting=true `
  --entitlement projects.max=100 `
  --out customer-1042.dlicense
```

The command displays the claim code exactly once and writes the signed grant. Transfer the grant to an administrator; send the claim code to the customer through a separate secure channel.

```powershell
$artifact = (Get-Content -Raw customer-1042.dlicense).Trim()
Invoke-RestMethod -Method Post http://127.0.0.1:8080/api/v1/admin/licenses/import `
  -Headers $headers -ContentType application/json `
  -Body (@{ artifact=$artifact } | ConvertTo-Json)
```

An exact re-import returns the original license. The same serial with different signed bytes is a conflict and security event.

## Customer and installation flow

1. Register with `POST /api/v1/auth/register`, then consume the emailed token at `/api/v1/auth/verify-email`. Development Compose returns that token in the response because no email webhook is configured.
2. Log in and send the one-time code to `POST /api/v1/licenses/claim`.
3. The installation generates an Ed25519 keypair and keeps the private key in the OS keystore/TPM where available.
4. The authenticated customer approves its raw public key through `POST /api/v1/licenses/{licenseID}/activations`.
5. The product verifies the returned lease using the key set at `/.well-known/denilicense-activation-keys.json`, binding the expected issuer, product, and device-key thumbprint.
6. Before expiry, the product requests `/api/v1/activation-challenges`, validates and reconstructs the structured renewal transcript (the public Go client does this), signs it with the device key, and exchanges it at `/api/v1/activation-challenges/complete`.

See [client integration](docs/CLIENT_INTEGRATION.md) for the exact verification and renewal rules.

## Administration and seat recovery

Customers can list every installation for an owned license with
`GET /api/v1/licenses/{licenseID}/activations`, then safely retry
`DELETE /api/v1/activations/{activationID}` to free an abandoned seat.

Privileged read APIs are available under `/api/v1/admin`:

- platform owners, license administrators, support, and auditors can search
  licenses by serial, owner email, four-character claim-code suffix, product,
  or state, and can list a license's activations;
- platform owners, license administrators, and support can administratively
  deactivate an installation;
- platform owners can look up users and change role or status. Every actual
  role/status change revokes all sessions for that user, and the service
  transactionally refuses to demote or disable the final active owner;
- platform owners and auditors can page through `audit_events` using the
  descending `beforeId` cursor and filter by action, actor, or target.

Role administration applies to accounts that already exist. Closed
registration mode intentionally has no invitation or administrator-created
password workflow; provision customer accounts through open verified
registration before closing it, or add an application-specific invitation
ceremony rather than distributing shared temporary passwords.

## Local commands

```powershell
# Compile both binaries
go build -o bin/denilicense.exe ./cmd/denilicense
go build -o bin/denilic.exe ./cmd/denilic

# Unit and parser regression tests
go test ./...
go test -race ./...
go vet ./...

# Live end-to-end test against the Compose service
$env:DENILICENSE_INTEGRATION_URL='http://127.0.0.1:8080'
$env:DENILICENSE_INTEGRATION_OWNER_EMAIL='owner@example.com'
$env:DENILICENSE_INTEGRATION_OWNER_PASSWORD='use a password manager value'
go test -v ./integration
```

## Production boundary

This is a security-focused foundation, not a claim of a finished audited identity provider. Before exposing it to customers:

- Put the service behind TLS and use TLS to PostgreSQL; replace every development secret.
- Put the activation signer in KMS/HSM and keep the offline issuer on an isolated workstation or hardware token.
- Add WebAuthn/passkeys and mandatory step-up MFA for privileged roles. The current release has strong password/session handling but no MFA UI or WebAuthn ceremony.
- Replace the bounded, retrying in-memory email queue with an encrypted transactional outbox or durable provider queue if verification/reset delivery must survive a host crash.
- Use a distributed edge rate limiter when running multiple service replicas.
- Export audit events to independent immutable storage and alert on issuer, role, revocation, and issuance changes.
- Test encrypted backups and signing-key recovery, define RPO/RTO, run secret/dependency/SBOM scans, and commission an independent cryptographic review and penetration test.
- Back up the issuance pepper as non-rotating recovery key material; changing it requires a deliberate versioned migration because retry-safe online responses are derived from it.
- Add organization tenancy and database row-level security before using one deployment for mutually untrusted business tenants.

Permanently offline software cannot have instant revocation or authoritative concurrent-seat enforcement, and a customer controlling a machine can patch a local verifier. Finite signed leases and server-authoritative high-value operations reduce that risk; they cannot eliminate it.

More detail: [security model](docs/SECURITY_MODEL.md), [operations guide](docs/OPERATIONS.md), and [OpenAPI source](internal/httpapi/openapi.yaml).
