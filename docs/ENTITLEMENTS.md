# License entitlements

Entitlements are the product-specific capabilities and limits attached to a
license. DeniLicense stores them as a flat JSON object and copies the complete
object into every signed activation lease for that license. Your product must
verify the lease before it reads any entitlement.

For example:

```json
{
  "entitlements.schema": 1,
  "feature.reporting": true,
  "feature.export.pdf": true,
  "limits.projects": 100,
  "plan": "professional"
}
```

DeniLicense authenticates this data and controls how long the snapshot is
valid. It does not know what `feature.reporting` means, count projects, or turn
features on itself. The product defines and enforces that contract.

## What entitlements are—and are not

Entitlements are license-wide. Every active installation of one license
receives the same entitlement object. They are not per-user or per-machine
overrides.

Keep these separate concepts separate:

| License field | Purpose |
| --- | --- |
| `entitlements` | Product-specific feature switches, editions, and usage limits |
| `maxActivations` | Number of installation keys that may hold active seats |
| `offlineGraceSeconds` | Upper bound on how long a newly issued lease can remain usable without renewal |
| `notBefore` / `expiresAt` | License validity window |
| license state | Administrative active, suspended, or revoked state |

An integer entitlement such as `limits.projects: 100` is only a signed limit.
Your software must count projects and refuse the 101st. It is not a usage meter
maintained by DeniLicense. Likewise, `feature.reporting: true` has no effect
until product code checks it.

Entitlements are signed, not encrypted. Administrators, the customer-facing
API, and anyone able to read an activation lease can see their names and
values. Do not put secrets, credentials, private customer data, or security
answers in them.

## Names, types, and limits

The common contract accepted by online issuance, offline grants, and activation
leases is:

- The entitlement set is a JSON object with at most 128 entries.
- A name is 1–128 lowercase ASCII characters. It must start with `a`–`z` or
  `0`–`9`; remaining characters may also contain `.`, `_`, or `-`. The exact
  pattern is `^[a-z0-9][a-z0-9._-]{0,127}$`.
- A value is exactly one of a JSON boolean, signed 64-bit integer, or string.
- Integers range from `-9223372036854775808` through
  `9223372036854775807`.
- Keep strings at or below 4,096 UTF-8 bytes and use printable Unicode. Control,
  formatting, surrogate, private-use, and unassigned characters are rejected by
  the signed artifact format.
- Floating-point numbers, `null`, arrays, nested objects, and binary values are
  not supported.
- The canonical entitlement object may encode to at most 12 KiB. This leaves
  bounded room for the license, product, device, revision, and time fields in
  the signed 16 KiB payload.

The complete canonical payload of an offline grant or activation lease is
limited to 16 KiB, including fields outside `entitlements`; the complete token
is limited to 24 KiB. The separate 12 KiB entitlement-object limit is enforced
by online issuance, offline grants, and activation leases. Therefore, 128
maximum-length strings cannot fit in one license. Keep names and values compact
and test a real activation as part of release qualification.

JSON types are meaningful. These values are different contracts:

```json
{
  "feature.reporting": true,
  "incorrect.boolean": "true",
  "limits.projects": 100,
  "incorrect.limit": "100"
}
```

The second and fourth values are strings, not a boolean and integer. Product
code should never coerce them.

## Designing a stable entitlement contract

Define entitlement names and semantics in the product repository as a public
compatibility contract. A useful convention is:

- `feature.<name>` for exact boolean switches, such as
  `feature.reporting`;
- `limits.<resource>` for integer ceilings, such as `limits.projects`;
- `plan` or `edition` for a small, explicitly allowlisted string enum;
- `entitlements.schema` for an integer version of your product's entitlement
  vocabulary.

The convention is optional; the stability rules are not:

1. Never change the type or meaning of a released key. Add a new key instead.
2. Treat names and string values as case-sensitive.
3. Give each product its own documented vocabulary even if several products
   use the same DeniLicense service.
4. Use one boolean per independently controlled capability. Because arrays are
   unsupported, model multiple export formats as `feature.export.pdf` and
   `feature.export.csv`, not a comma-separated value that every client must
   parse.
5. Use integers for limits only when the product has a clear unit and a hard
   implementation ceiling. Document whether zero means disabled or unlimited;
   the safer convention is that zero means disabled and no signed value means
   no allowance.
6. Do not infer access from an unknown plan name. Allowlist known values and
   deny on anything else.

When evolving the schema, deploy product support for new keys first, then issue
licenses that contain them. Older product versions will safely ignore a new key
only if their missing-key behavior is fail-closed. Do not repurpose a key after
deployment. If an unknown `entitlements.schema` version changes the meaning of
a security-sensitive decision, disable that capability and require an update.

## Issuing entitlements in the UI

1. Open **Licenses** and choose **Issue license**.
2. Select the product and fill in the license validity, machine-seat, and
   offline-grace fields.
3. In **Entitlements (JSON object)**, enter one JSON object. JSON requires quoted
   names and string values, lowercase `true`/`false`, and no trailing commas.
4. Issue the license and preserve the one-time claim code through the intended
   secure channel.
5. Open the new license's detail view and review the rendered entitlement names
   and values before delivering the code.

A practical desktop-license example is:

```json
{
  "entitlements.schema": 1,
  "feature.analytics": true,
  "feature.cloud.sync": false,
  "feature.export.pdf": true,
  "limits.projects": 25,
  "limits.team_members": 5,
  "plan": "business"
}
```

Use `{}` for a license that grants no product-specific capabilities. The UI
currently creates an online license; it does not edit the entitlement snapshot
of an existing license.

## Issuing through the API

Send the JSON object in `entitlements` when creating the license. The
`Idempotency-Key` must be unique for the intended request. Reusing it with the
exact request recovers the same license and claim code; reusing it with changed
entitlements is a conflict.

```http
POST /api/v1/admin/licenses HTTP/1.1
Authorization: Bearer <administrator-access-token>
Content-Type: application/json
Idempotency-Key: contract-1042-2026-07

{
  "productCode": "MYAPP",
  "subject": "contract-1042",
  "expiresAt": "2027-07-13T00:00:00Z",
  "maxActivations": 3,
  "offlineGraceSeconds": 86400,
  "perpetual": false,
  "entitlements": {
    "entitlements.schema": 1,
    "feature.reporting": true,
    "feature.export.pdf": true,
    "limits.projects": 100,
    "plan": "professional"
  }
}
```

Only a platform owner or license administrator can issue a license. The claim
code returned by a successful request assigns ownership; it is not the runtime
entitlement credential. The product consumes a signed activation lease after
the customer claims and activates the license.

## Issuing from an offline workstation

Repeat `--entitlement KEY=VALUE` for each entry:

```powershell
denilic issue `
  --key secrets/offline-issuer.key.json `
  --issuer com.example.offline-issuer `
  --product MYAPP `
  --subject contract-1042 `
  --valid-for 8760h `
  --max-activations 3 `
  --entitlement entitlements.schema=1 `
  --entitlement feature.reporting=true `
  --entitlement feature.export.pdf=true `
  --entitlement limits.projects=100 `
  --entitlement plan=professional `
  --out contract-1042.dlicense
```

The offline CLI parses exact lowercase `true` and `false` as booleans and a
canonical base-10 whole number as an integer. Other text is a string. For
example, `True`, `01`, `1.5`, and `professional` are strings. Run `denilic
verify` and inspect its JSON output if a value could be ambiguous.

The `dlic1` file freezes the entitlement object into the issuer-signed grant.
After an administrator imports it, DeniLicense copies those values into the
online license record. An exact re-import is idempotent; altering the artifact
invalidates its signature, and issuing different data under the same serial is
rejected.

The offline grant is an administrator-to-server issuance artifact. Product
code should not use it as the runtime feature token. Claim and activate the
imported license, then verify the server-issued, device-bound `dllease1` lease.

## Consuming entitlements safely in Python

Follow the complete key selection, signature, issuer, product, device, and time
checks in [Python client integration](CLIENT_INTEGRATION.md). Read
`claims.entitlements` only after `verify_lease_jwk` returns successfully.

Use exact type checks and conservative defaults:

```python
from collections.abc import Mapping
from typing import Any


def enabled(values: Mapping[str, Any], name: str) -> bool:
    # Missing, false, 1, and "true" are all disabled.
    return values.get(name) is True


def bounded_limit(
    values: Mapping[str, Any],
    name: str,
    *,
    implementation_maximum: int,
) -> int:
    value = values.get(name)
    # `bool` is a subclass of `int` in Python, so use an exact type check.
    if type(value) is not int or value < 0:
        return 0
    return min(value, implementation_maximum)


def allowed_plan(values: Mapping[str, Any]) -> str | None:
    value = values.get("plan")
    return value if value in {"starter", "professional", "business"} else None


# `claims` came from a successful `verify_lease_jwk(...)` call.
entitlements = claims.entitlements

if enabled(entitlements, "feature.reporting"):
    enable_reporting()
else:
    disable_reporting()

project_limit = bounded_limit(
    entitlements,
    "limits.projects",
    implementation_maximum=10_000,
)
plan = allowed_plan(entitlements)
```

The implementation maximum protects the product from an accidentally enormous
but correctly signed limit. Apply the same pattern in other languages: exact
type, known key, expected range or allowlist, conservative fallback.

Recommended failure behavior is:

- failed signature or context check: grant nothing;
- lease not yet valid or expired: grant nothing and attempt renewal when
  connectivity permits;
- missing entitlement: disabled or zero allowance;
- wrong value type: disabled or zero allowance;
- unknown key: ignore it;
- unknown enum value or schema version: deny the affected capability.

Do not merge unsigned local configuration in a way that adds capabilities. A
local administrator may narrow a signed entitlement, such as reducing a limit,
but must not widen it. Do not keep using a cached entitlement object after its
lease fails verification or expires.

## Lease snapshots, renewal, and offline behavior

An activation or successful proof-of-possession renewal produces a signed
`dllease1` token containing:

- the complete entitlement snapshot;
- the license and activation IDs;
- the product audience and installation-key thumbprint;
- a positive `license_revision`;
- the issue, not-before, and exclusive expiration times.

The lease expires at the earliest of the configured activation lease TTL, the
license's offline grace, and the license expiration. The service-wide lease TTL
defaults to 24 hours and may be configured from one hour through seven days.
Online-issued licenses accept an offline grace from one hour through 30 days,
although the service-wide seven-day maximum can make a longer value ineffective.
Offline-imported licenses currently receive a fixed 24-hour grace.

Once the lease is verified and still inside that window, the product can use
its signed snapshot without contacting DeniLicense. Renewal returns a fresh
snapshot and observes the current server-side license and activation state.
Suspending or revoking a license stops new activations and renewals, but a lease
already held by a disconnected installation remains cryptographically valid
until its signed expiration. Choose the TTL for the maximum revocation delay
your business can tolerate.

The license revision begins at 1. It is included in the signed lease, but the
verification SDK does not contact the server to discover a newer revision and
does not persist anti-rollback state. If the product persists a highest-seen
revision, scope it to the same license ID and reject a lower revision; this can
prevent replay of an older snapshot after that installation has seen a newer
one. It cannot reveal a server-side change while the installation is offline.
Do not use `license_revision` as your entitlement-schema version—use an explicit
entitlement such as `entitlements.schema`.

In the current release, entitlements are immutable after issuance. License
state transitions advance the license revision, but there is no entitlement
editing endpoint. To change a customer's feature set, issue and claim a
replacement license, transition the old license according to your revocation
policy, and let each installation activate the replacement. Plan for the old
lease's remaining validity window during that migration.

## Hostile-client limitations

A valid signature proves that DeniLicense issued this snapshot for the selected
product and installation key. It does not make a customer-controlled computer a
trusted enforcement environment.

An administrator of that computer can potentially patch feature checks, alter
the system clock, instrument the process, copy an exportable installation key,
or replay an older lease that is still valid. Hardware-backed keys, secure
storage, code signing, clock-rollback detection, and obfuscation can raise the
cost but cannot eliminate this boundary.

For high-value or server-hosted operations, enforce authorization on a system
the customer does not control. Do not trust a client-supplied statement such as
`reporting=true`; verify an appropriate signed credential and, where applicable,
device proof, or consult your server-authoritative account state. Treat local
entitlement enforcement as one layer of a larger abuse and authorization model.

## Release checklist

Before shipping a new entitlement or changing a license template:

1. Document the key, exact type, unit, allowed range, default, and first product
   version that understands it.
2. Add tests for enabled, disabled, missing, wrong-type, out-of-range, unknown,
   expired-lease, and invalid-signature cases.
3. Confirm the product binds verification to the expected issuer, product, and
   installation key.
4. Activate a representative license and verify the resulting lease rather
   than testing only the JSON form or offline grant.
5. Test disconnected use through expiration and confirm the product fails
   closed afterward.
6. Test suspension or revocation and account for already issued leases.
7. Keep sensitive data out of names and values, and review audit and support
   procedures for replacement licenses.
