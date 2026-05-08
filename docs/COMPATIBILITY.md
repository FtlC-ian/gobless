# GoBless BLESS Compatibility

GoBless targets BLESS-compatible behavior for API Gateway-backed AWS Lambda signing flows and OpenSSH certificate output. Compatibility means existing BLESS operators should be able to determine whether a migration requires no change, config-only change, or client/code change.

## Feature matrix

| Feature | v0.1 support | Notes |
| --- | --- | --- |
| User certificates | ✓ | Primary path. IAM caller identity binds to requested username principal by default. |
| Host certificates | ✓ | Separate host authorization policy required. |
| RSA CA | ✓ | Supported for BLESS/OpenSSH compatibility. KMS RSA asymmetric keys are the production-preferred custody mode. RSA keys below 2048 bits are rejected. |
| Ed25519 CA | ✗ | Not supported by the current KMS-backed CA signer. |
| `source-address` critical option | ✓ | Derived from request payload, not Lambda network metadata; policy-approved only; caller-provided value is untrusted. |
| `force-command` critical option | ✓ | Policy-approved only. |
| KMS key | ✓ | Preferred production mode. Private key never leaves KMS. |
| Encrypted PEM | ✓ with warning | Explicit fallback only. Not recommended for production because plaintext key material exists in memory. |
| `kmsauth` | ✗ | Not supported. |
| API Gateway AWS_IAM | ✓ | Current production entrypoint expects API Gateway proxy events and trusted IAM identity in request context. |
| Direct IAM Lambda invoke | ✗ for end users | Direct invoke payloads cannot safely provide caller identity to this handler. Operator smoke tests only. |
| OIDC | ✗ | Not supported by the current production handler. |

## Compatibility contract

### Invocation

GoBless v0.1 supports API Gateway proxy integration with AWS_IAM authorization. The Lambda handler accepts API Gateway-shaped events whose `body` contains the signing request. Trusted caller identity comes from API Gateway request context, not from request-body fields.

Implemented request bodies cover:

- user certificate signing;
- host certificate signing.

CA public key export is currently provided by the local `ca-pubkey` CLI path, not by the production Lambda handler. Direct Lambda invocation is not a secure end-user boundary for this handler because callers can control the event payload, including any spoofed `requestContext`.

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

The mapping below shows the current GoBless configuration surfaces. INI-style keys are loaded from config files; `GOBLESS_*` environment variables override them in Lambda deployments.

| BLESS config key / concept | GoBless equivalent | Notes |
| --- | --- | --- |
| Lambda function region | `[Lambda] region` / `GOBLESS_LAMBDA_REGION` or `AWS_REGION` | Used by production Lambda/KMS wiring. |
| CA private key path or blob | `[CA] private_key_file` / `[CA] private_key_b64` | Local/dev or explicit PEM fallback only; production should use KMS. |
| CA private key passphrase | `[CA] encrypted_password` | Must come from protected config, not source code or logs. |
| KMS key ID / alias | `[CA] kms_key_id` / `GOBLESS_CA_KMS_KEY_ID` | Preferred production signer. |
| Signer backend | `[CA] signer_type` / `GOBLESS_CA_SIGNER_TYPE` | `kms` for production, `rsa`/PEM paths for local development. |
| Remote user / requested principal | request `principals` after policy approval | Body value is untrusted until validated. |
| Allowed principals | `[Principal] allowed` / `GOBLESS_PRINCIPAL_ALLOWED` | Comma-separated policy-approved SSH principals. |
| IAM account binding | `[Principal] expected_account_id`, `[Principal] enforce_iam_binding` | Binds caller identity to requested user principals. |
| Source-address rules | request `source_address` plus policy validation | Caller supplied; Lambda does not network-enforce it. |
| Certificate lifetime / TTL | `[CA] max_ttl`, `[CA] default_ttl`; request `ttl_seconds` | Request cannot exceed policy maximum. |
| User/host certificate toggle | `[Principal] allowed_cert_types` | Restricts certificate classes when needed. |
| Audit table | `[CA] dynamodb_table` / `GOBLESS_CA_DYNAMODB_TABLE` | Used when audit logging is enabled. |
| Audit behavior | `[Logging] audit_enabled`, `[Logging] audit_fail_open` | Fail-closed by default; fail-open is an emergency mode. |

## Intentional behavior differences

These differences are deliberate security decisions, not accidental incompatibilities.

1. **KMS is preferred over PEM for production.** Classic BLESS-style encrypted key material is supported only as an explicit fallback with warnings.
2. **Request-body principals are never trusted.** IAM invocation success only authenticates the caller. Policy still validates all requested certificate contents.
3. **Caller-to-username binding is default behavior.** A caller cannot request another user's SSH principal unless an explicit override policy says so.
4. **Random serials are used.** GoBless does not provide monotonic serial allocation in v0.1. KeyID is the audit correlation key.
5. **Unicode-confusable principals are rejected.** Conservative canonical principal parsing is preferred over accepting visually ambiguous names.
6. **Audit failure is production-fail-closed by default.** Operators may configure a narrow emergency mode only if documented and reviewed.
7. **No `kmsauth` in v0.1.** API Gateway AWS_IAM is the supported authentication path for the production handler.
8. **RSA below 2048 bits is rejected.** This is a deliberate BLESS compatibility difference to avoid silently accepting weak legacy keys.
9. **No silent backdated certificates.** `valid-after` defaults to issuance time; any compatibility clock-skew/backdating mode must be explicit, bounded, and tested.
10. **No framework compatibility layer.** GoBless uses small internal interfaces and standard library code instead of web/config/logging frameworks.

## Unsupported compatibility surfaces

- Legacy Lambda event aliases are not part of the current handler contract.
- API Gateway AWS_IAM is the production invocation boundary; OIDC is not implemented.
- Ed25519 CA signing is not implemented.
- `kmsauth` is not implemented.
