# GoBless Threat Model

## Scope

This model covers GoBless v0.1: API Gateway-backed AWS Lambda invocation with AWS_IAM caller identity, BLESS-compatible user and host SSH certificate issuance, KMS-backed CA signing by default, encrypted PEM fallback, policy evaluation, and audit logging.

## Assets

| Asset | Protection |
| --- | --- |
| CA private key | Prefer AWS KMS asymmetric signing so the private key never leaves KMS; restrict KMS IAM permissions; never log key data. |
| Encrypted PEM fallback key | Require explicit config opt-in; decrypt only in memory; restrict Lambda environment/config storage; warn against production use. |
| Authorization policy | Validate config at startup; require code review for policy changes; fail closed on missing or ambiguous rules. |
| AWS caller identity | Trust IAM/STS invocation context, not request-body identity claims; log normalized caller ARN/user ID. |
| SSH certificate contents | Build only from policy-approved principals, TTL, extensions, and critical options. |
| Audit trail | Emit structured decision events; restrict write permissions; redact secrets; fail closed by default on audit write failure. |
| Lambda configuration and environment | Least-privilege IAM, encrypted environment variables, no plaintext private keys in environment variables. |
| Returned certificates | Short TTL, source-address/force-command constraints where policy requires them, auditable KeyID. |

## Attacker profiles

| Attacker | Capabilities |
| --- | --- |
| Unauthenticated external actor | Cannot invoke Lambda unless IAM or network perimeter is misconfigured; may obtain public docs or CA public key. |
| AWS principal with invoke permission | Can submit arbitrary request bodies to Lambda under their IAM identity. |
| Compromised developer workstation | Can invoke as the victim while AWS credentials are valid; can submit arbitrary public keys and principals. |
| Malicious internal user | Has legitimate access for their own principal and attempts privilege escalation to other principals or hosts. |
| Compromised Lambda runtime | Can read process memory, environment, temporary files, and outbound responses for that invocation. |
| Misconfigured AWS operator | May grant broad Lambda/KMS/DynamoDB permissions or expose invocation through unintended paths. |
| Audit reader | Can inspect audit data and may look for secrets or sensitive operational metadata. |

## Threats, mitigations, and residual risks

### Principal spoofing

Threat: A caller edits the request body to request `root`, `ec2-user`, another employee's username, a service account, or a host principal.

Mitigations:
- IAM caller identity is the authentication source for invocation.
- Request-body principals are untrusted.
- User certificate policy requires caller AWS username/ARN mapping to match the requested username principal unless policy explicitly overrides it.
- Host certificate issuance uses separate host policy, not user principal matching.
- Policy rejects principals outside allowlists.

Residual risk:
- Incorrect username/ARN mapping config can authorize the wrong principal.
- Overbroad override policies can intentionally bypass default BLESS behavior.

### Key exfiltration

Threat: The CA private key is stolen from Lambda memory, environment, logs, artifacts, or a dependency exploit.

Mitigations:
- Default signer uses KMS asymmetric signing; private key never leaves KMS.
- Lambda role gets only required `kms:Sign` and public-key permissions for the configured key.
- Encrypted PEM mode requires explicit opt-in and production warning.
- Logs and errors must not include private key bytes, decrypted PEM, or signing inputs beyond non-secret fingerprints.

Residual risk:
- KMS misuse remains possible if IAM grants signing to unintended principals.
- Encrypted PEM mode leaves plaintext key material in process memory during signing and is unsuitable for high-assurance production deployments.

### Audit bypass

Threat: Certificates are issued without audit records, or audit records omit fields needed for investigation.

Mitigations:
- Handler emits audit events for successful and rejected decisions.
- Audit event includes caller identity, public-key fingerprint, requested/approved principals, TTL, KeyID, serial, decision, and reason code.
- Production default fails closed when audit write fails.
- Audit writer role is separate from signer permissions where practical.

Residual risk:
- Fail-open emergency mode, if configured, can create audit gaps.
- Backend IAM misconfiguration can allow audit deletion or tampering outside GoBless.

### Certificate replay

Threat: A valid certificate is copied and reused by another party before expiration.

Mitigations:
- Certificates are short-lived.
- Source-address critical option is supported and should be required where caller source ranges are stable.
- Force-command is supported for constrained automation.
- Audit records KeyID, serial, public-key fingerprint, and principals for replay investigation.

Residual risk:
- OpenSSH certificates are bearer credentials when paired with the corresponding private key. If the private key is stolen, replay is possible until expiry or server-side revocation controls take effect.

### TTL abuse

Threat: A caller requests a long-lived certificate to extend access beyond intended session length.

Mitigations:
- Policy enforces maximum TTL by certificate type and principal class.
- Request TTL above maximum is rejected or capped according to explicit compatibility config; default is reject.
- Audit records requested and issued TTL.

Residual risk:
- Overly generous TTL policy weakens the security model.

### Homoglyph principal injection

Threat: A caller submits Unicode confusables such as Cyrillic characters resembling ASCII usernames, invisible controls, mixed normalization forms, or duplicate principals that render similarly.

Mitigations:
- Principal parser rejects non-canonical principals.
- User and host principals should be restricted to a conservative ASCII allowlist unless a future issue deliberately expands support.
- Normalization and duplicate detection run before policy matching.
- Golden and negative tests cover homoglyphs, controls, whitespace, and mixed case behavior.

Residual risk:
- Existing deployments with non-ASCII principals will need explicit future design before support.

### IAM misconfiguration

Threat: Broad IAM permissions allow unintended principals to invoke Lambda, sign with KMS, alter config, or write misleading audit records.

Mitigations:
- Deployment docs must require least-privilege roles for invoke, Lambda execution, KMS signing, and audit writes.
- KMS key policy should restrict signing to the GoBless Lambda execution role.
- Lambda resource policy should restrict direct invocation to authorized AWS principals.
- GoBless policy still validates requested certificate contents after IAM invocation succeeds.

Residual risk:
- GoBless cannot fully compensate for an AWS account where administrators grant wildcard invoke or KMS signing permissions.

### Timing side-channels

Threat: Certificate signing time can vary by signer backend, KMS network latency, CA key type, key size, and local cryptographic operation cost. An attacker with reliable timing visibility across many requests might try to fingerprint the configured CA key type or infer operational details from signing latency. KMS signing is especially variable because it is a remote service call, while local comparisons and validation paths must avoid data-dependent comparisons for secrets where applicable.

Mitigations:
- Lambda cold-start and AWS service latency noise dominates normal end-to-end signing time, making CA key fingerprinting by timing not practically exploitable for the v0.1 direct-invocation model.
- Do not expose detailed per-stage timing metrics to callers.
- Keep secret comparisons and token/fingerprint equality checks constant-time where the compared value is secret or authorization-sensitive.
- Treat timing metrics in logs and traces as operational metadata and restrict access accordingly.

Residual risk:
- Operators with high-fidelity internal telemetry may still infer signer backend or key class from aggregate latency.
- Future low-latency front doors or colocated attackers should revisit whether additional timing normalization is needed.

### Lambda cold-start surface

Threat: During a new Lambda container cold start, GoBless loads configuration, initializes dependencies, and may fetch or decrypt CA-related material before serving the first request. A compromised runtime, extension, or environment-inspection path during initialization could observe configuration, secret references, decrypted PEM material in fallback mode, or first-request state. A race between key fetch and first request would be dangerous if requests could reach a partially initialized handler.

Mitigations:
- Configuration is loaded and validated before the handler is registered with the Lambda runtime, so malformed or incomplete configuration fails closed before request handling begins.
- KMS mode keeps CA private key material outside the Lambda process during cold start; the function receives signatures, not key bytes.
- PEM fallback must fetch/decrypt key material only through the configured signer path and must not log secret material during initialization.
- Init failures return generic startup/invocation errors rather than partially serving signing requests.

Residual risk:
- Any Lambda runtime compromise during cold start can inspect process memory and environment available to the function.
- PEM fallback has materially higher cold-start exposure because decrypted key material can exist in memory.

### Secret-leak paths

Threat: CA key material, passphrases, signing inputs, request bodies, or sensitive policy/config values leak through observability or error paths.

Concrete paths and mitigations:
- Logs: application logs, dependency logs, panic output, or debug statements could include PEM bytes, passphrases, request bodies, or KMS errors. Mitigation: structured logging with secret redaction, no raw request-body logging, and review of new log fields.
- Error messages: propagated errors could include filesystem paths, KMS internals, PEM parse details, or secret-source values. Mitigation: sanitize errors before returning them to callers and keep internal detail only in restricted logs after redaction.
- Lambda response body: malformed requests or signing failures could reflect attacker-controlled input or internal errors. Mitigation: stable generic error responses with reason codes; never return stack traces, PEM data, KMS payloads, or config values.
- CloudWatch and log forwarding: retained or forwarded logs can replicate leaked secrets into external SIEM systems. Mitigation: enforce the log redaction policy before emission, restrict CloudWatch/log-forwarder access, and use retention policies appropriate for audit data.
- X-Ray or tracing: tracing integrations can capture request/response bodies or annotations containing sensitive fields. Mitigation: disable body capture for signing requests and treat trace annotations as non-secret, low-cardinality operational metadata only.
- DynamoDB audit records: overbroad audit events could persist request bodies, critical options, or user-controlled strings that contain secrets. Mitigation: audit only the approved schema, store fingerprints and reason codes instead of raw key material or full request bodies, and redact sensitive-looking values before write.

Residual risk:
- Third-party extensions or account-level log subscriptions can copy data outside GoBless controls.
- Redaction bugs are possible; tests should assert that representative secrets do not appear in logs, audit records, or caller-visible errors.

### Emergency audit fail-open

Threat: Operators configure audit failure to fail open, allowing certificates to be issued without durable audit records.

Mitigations:
- Production default is fail closed on audit write failure.
- Fail-open is an emergency-only operational mode that must be enabled by an authorized operator, documented in change control, and time-bounded to the shortest practical outage window.
- Enabling fail-open must emit alerts and prominent logs; operators must monitor certificate issuance counts, signer/KMS activity, and audit backend recovery until fail-closed is restored.
- After recovery, operators must reconcile CloudTrail/KMS/Lambda logs with any missing GoBless audit records.

Residual risk:
- During fail-open windows, investigation quality is reduced and some issuance details may be unrecoverable.

### Plaintext key material in memory

Threat: Encrypted PEM fallback decrypts the CA key into Lambda memory, where a runtime compromise, crash dump, extension, or unsafe logging could expose it.

Mitigations:
- KMS is the production-preferred custody mode.
- Encrypted PEM mode requires explicit configuration and prominent warning.
- PEM passphrases must come from a protected secret source, not source code or logs.
- Code must avoid copying key bytes unnecessarily and must not include key material in errors.

Residual risk:
- Go cannot guarantee immediate zeroization of all copies of decrypted key material.
- Any memory disclosure in PEM mode can become CA compromise.

## Out of scope

- Protection of SSH private keys on caller workstations beyond documenting that they must remain private.
- SSH server-side configuration, CA trust distribution, and revocation runbooks beyond compatibility notes.
- API Gateway, OIDC, or non-IAM authentication for v0.1.
- `kmsauth` compatibility for v0.1.
- Detection of compromised AWS administrator accounts.
- Non-AWS serverless deployments.
