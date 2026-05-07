# GoBless BLESS Compatibility

GoBless targets near drop-in compatibility with Netflix BLESS for direct AWS Lambda invocation and OpenSSH certificate output. Compatibility means existing BLESS operators should be able to determine whether a migration requires no change, config-only change, or client/code change.

## Feature matrix

| Feature | v0.1 support | Notes |
| --- | --- | --- |
| User certificates | ✓ | Primary path. IAM caller identity binds to requested username principal by default. |
| Host certificates | ✓ | Separate host authorization policy required. |
| RSA CA | ✓ | Supported for BLESS/OpenSSH compatibility. KMS RSA asymmetric keys are the production-preferred custody mode. RSA keys below 2048 bits are rejected. |
| Ed25519 CA | Future | Requires separate signer compatibility work and KMS/provider decision. |
| `source-address` critical option | ✓ | Derived from request payload, not Lambda network metadata; policy-approved only; caller-provided value is untrusted. |
| `force-command` critical option | ✓ | Policy-approved only. |
| KMS key | ✓ | Preferred production mode. Private key never leaves KMS. |
| Encrypted PEM | ✓ with warning | Explicit fallback only. Not recommended for production because plaintext key material exists in memory. |
| `kmsauth` | ✗ | Out of scope for v0.1. |
| IAM Lambda invoke | ✓ | Direct Lambda invocation is the v0.1 authentication boundary. |
| API Gateway / OIDC | Later | Out of scope for v0.1. |

## Compatibility contract

### Invocation

GoBless v0.1 supports direct AWS Lambda invocation by IAM-authenticated callers. The Lambda handler should accept BLESS-style request shapes for:

- user certificate signing;
- host certificate signing;
- CA public key export;
- legacy handler names where compatibility can be preserved without weakening authorization.

Request-body identity claims are not trusted. IAM caller identity is the authentication source; GoBless policy decides certificate contents.

### Response behavior

Successful certificate responses return OpenSSH certificate material suitable for writing to `*-cert.pub` files or piping to an SSH client flow.

Error responses must be stable and non-secret. They should identify request class and reason code, not dump raw request bodies, credentials, PEM data, KMS internals, or stack traces.

### Certificate fields

| Field | GoBless behavior |
| --- | --- |
| Certificate type | User or host, selected by validated request type. |
| Key ID | Timestamp plus random suffix; primary audit correlation identifier. |
| Serial | Random 64-bit value from `crypto/rand`; not the primary audit identifier. |
| Principals | Policy-approved canonical principals only. |
| Valid after | Issuance time by default. Any compatibility mode for request-supplied/backdated `valid-after` must be named, bounded by policy clock skew, and threat-modeled before enablement. |
| Valid before | Valid after plus policy-approved TTL. |
| Critical options | Only policy-approved options; supports `source-address` and `force-command`. |
| Extensions | Only policy-approved extensions. |
| Signature key | Configured CA public key. |

## Config mapping

Exact parser names may be refined during #5, but the mapping below is the compatibility target.

| BLESS config key / concept | GoBless equivalent | Notes |
| --- | --- | --- |
| Lambda function name / region | `lambda.function_name`, `aws.region` | Used by CLI and deployment docs. |
| CA private key path or blob | `signer.pem.encrypted_key` | Explicit fallback only; production warning required. |
| CA private key passphrase source | `signer.pem.passphrase_secret` | Must resolve from protected secret source, not logs or source code. |
| KMS key ID / alias | `signer.kms.key_id` | Preferred production mode. |
| CA public key export path | `ca.public_key_output` or export operation | Public key only; never private key. |
| Allowed IAM users/roles | `policy.callers` | Trusted invocation identities eligible for policy evaluation. |
| Username to AWS identity mapping | `policy.user_principal_bindings` | Required when AWS username/ARN differs from Unix username. |
| Remote user / requested principal | `request.principals` after policy approval | Body value is untrusted until validated. |
| Bastion or source address rules | `policy.source_addresses` | Request value is caller-supplied and must be validated against policy; Lambda does not network-enforce it. |
| Force command rules | `policy.force_commands` | Disabled unless explicitly allowed. |
| Certificate lifetime / TTL | `policy.max_ttl` and request `ttl` | Request cannot exceed policy maximum. |
| User certificate toggle | `policy.user_certs.enabled` | Enabled for v0.1. |
| Host certificate toggle | `policy.host_certs.enabled` | Enabled only with separate host policy. |
| Audit table / sink | `audit.backend`, `audit.table` | DynamoDB or configured backend in later implementation. |
| Logging verbosity | `log.level` | Standard-library logging conventions; no logging framework. |

## Intentional behavior differences

These differences are deliberate security decisions, not accidental incompatibilities.

1. **KMS is preferred over PEM for production.** Classic BLESS-style encrypted key material is supported only as an explicit fallback with warnings.
2. **Request-body principals are never trusted.** IAM invocation success only authenticates the caller. Policy still validates all requested certificate contents.
3. **Caller-to-username binding is default behavior.** A caller cannot request another user's SSH principal unless an explicit override policy says so.
4. **Random serials are used.** GoBless does not provide monotonic serial allocation in v0.1. KeyID is the audit correlation key.
5. **Unicode-confusable principals are rejected.** Conservative canonical principal parsing is preferred over accepting visually ambiguous names.
6. **Audit failure is production-fail-closed by default.** Operators may configure a narrow emergency mode only if documented and reviewed.
7. **No `kmsauth` in v0.1.** Direct IAM Lambda invoke is the supported authentication path.
8. **RSA below 2048 bits is rejected.** This is a deliberate BLESS compatibility difference to avoid silently accepting weak legacy keys.
9. **No silent backdated certificates.** `valid-after` defaults to issuance time; any compatibility clock-skew/backdating mode must be explicit, bounded, and tested.
10. **No framework compatibility layer.** GoBless uses small internal interfaces and standard library code instead of web/config/logging frameworks.

## Known gaps

- Fixture files under `testdata/bless/` still need to be created by implementation/test issues using public BLESS examples or reconstructed equivalents.
- Exact legacy Lambda event aliases must be confirmed during handler implementation (#7).
- Exact BLESS config key spelling must be validated during config implementation (#5).
- API Gateway and OIDC flows are not part of v0.1.
- Ed25519 CA support is deferred.
- `kmsauth` is out of scope for v0.1.
