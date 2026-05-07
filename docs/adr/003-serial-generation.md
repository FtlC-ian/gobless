# ADR 003: Certificate serial generation and audit correlation

Status: ACCEPTED

Issue: #20

## Context

OpenSSH certificates include a uint64 serial field. GoBless needs serials for certificate construction and operator investigation, but Lambda should remain stateless and highly available. A monotonic serial allocator would require durable state and contention handling. BLESS compatibility does not require a specific serial sequence.

## Decision

GoBless will generate a random 64-bit certificate serial using `crypto/rand`.

Collision probability is negligible for expected certificate issuance volumes. Audit correlation must use certificate KeyID as the stable identifier, not serial alone. KeyID will contain an issuance timestamp plus a random suffix and enough context to distinguish GoBless-issued certificates without embedding secrets.

## Rationale

Random serials keep certificate issuance stateless and avoid a DynamoDB-backed allocator in the signing path. This preserves Lambda availability and reduces operational complexity. A 64-bit random value provides acceptable collision resistance for v0.1 when combined with KeyID-based audit correlation.

## Consequences

Positive consequences:
- No serial allocation database is required.
- Parallel Lambda invocations do not contend on shared state.
- Certificate issuance remains available during audit backend or database allocator degradation, subject to audit policy.
- Tests can assert format and non-deterministic generation without depending on sequence state.

Negative consequences:
- Serial is not human-meaningful or ordered.
- Serial alone is insufficient as an audit lookup key.
- Collision detection is not performed in the signing path.

Residual risks:
- A serial collision is possible in theory. Investigation tooling must use KeyID, public-key fingerprint, caller identity, and issuance time in addition to serial.
- If a future deployment issues certificates at volumes where birthday-bound collision risk becomes material, the project should revisit this ADR with measured issuance numbers.

## Test requirements

- Certificate builder tests must verify serials are non-zero uint64 values generated from a cryptographic random source.
- Golden tests must not require deterministic serial values; they should normalize serial fields or inject a test random source.
- Audit tests must verify KeyID is present and used as the primary correlation field.
