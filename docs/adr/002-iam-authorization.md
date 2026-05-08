# ADR 002: IAM authorization and principal binding

Status: ACCEPTED

Issue: #17

## Context

GoBless is invoked as an AWS Lambda function. IAM controls who can invoke the function, but the Lambda request body can contain arbitrary user-controlled fields, including requested SSH principals. BLESS compatibility expects the AWS caller identity to bind to the requested username principal unless policy deliberately allows an override.

## Decision

IAM caller identity is trusted for invocation authentication. Requested principals in the request body are untrusted and must be validated against allowlist policy.

For API Gateway proxy invocations using AWS IAM authorization, the handler extracts the trusted identity from `requestContext.identity.userArn` and `requestContext.accountId`. It records the full caller ARN and derives the default short username by splitting the ARN path on `/` and using the final segment:

- `arn:aws:iam::123456789012:user/alice` derives username `alice`.
- `arn:aws:sts::123456789012:assumed-role/Admin/alice` derives username `alice`.

For user certificates, the caller AWS username/ARN mapping must match the requested username principal by default, following BLESS behavior. Policy config may explicitly override this binding for service accounts, break-glass roles, or migration cases. Overrides must be narrow, auditable, and covered by tests.

Assumed-role session names are currently used only as the derived default username; they are not separately enforced beyond normal caller ARN and principal policy checks. In effect, if policy allows an assumed-role ARN or role mapping broadly, any STS session that can assume that allowed role can request certificates permitted for that role/session-derived username. If a deployment needs to restrict which session names may invoke GoBless, enforce that in IAM rather than in request-body policy: add Lambda resource-policy or identity-policy conditions using AWS condition keys such as `aws:userid`, `aws:PrincipalArn`, principal tags, or organization-specific STS session controls.

`sts:RoleSessionName` restrictions belong in the role trust policy and are enforced by IAM during `sts:AssumeRole`, before GoBless is ever invoked. GoBless uses the caller identity already authenticated by Lambda and does not re-validate `sts:RoleSessionName` in request-body policy or Lambda invoke policy. This is intentional defense in depth: STS is the authoritative enforcement point for session-name constraints, while GoBless authorizes certificate contents from the authenticated caller identity.

Host certificate authorization is separate from user certificate authorization. A user allowed to request a user certificate is not automatically allowed to request host certificates.

## Rationale

API Gateway AWS_IAM context answers "who invoked GoBless?" It does not answer "what SSH identity should this certificate contain?" Treating request-body principals as trusted would let any caller request privileged principals by editing JSON. Binding IAM identity to requested principals preserves the core BLESS security property while still allowing explicit policy exceptions.

## Rules

- Lambda invocation requires AWS IAM authorization.
- GoBless policy is the authorization decision point for certificate contents.
- Request-body identity fields are claims, not evidence.
- User principals must match the configured mapping from caller AWS username/ARN unless an explicit override rule applies.
- Principal allowlists are always enforced, including for overrides.
- TTL, source-address, force-command, extensions, and critical options are untrusted request fields and must be policy-validated.
- Rejected decisions must be audited with a stable reason code.

## Edge cases

- Assumed roles: default username derivation uses the final ARN path segment, which is the STS session name for `assumed-role` ARNs. Session-name enforcement is otherwise ignored by GoBless policy; use IAM condition keys in the Lambda resource policy if the session name itself must be constrained.
- AWS usernames that differ from Unix usernames: require explicit mapping config.
- Service accounts: require explicit policy override listing allowed requester identities and target principals.
- `root` and shared privileged users: denied unless explicitly allowlisted and override-approved.
- Host principals: evaluated by host policy, such as instance identity, deployment role, or configured hostname allowlist.
- Source address: request-body source-address is untrusted. Policy must derive or validate it against configured allowed ranges; it must not blindly trust caller-provided IP strings.
- Bastion identity: if used, it must come from a trusted integration or policy mapping, not an arbitrary request-body field.
- Unicode or ambiguous principals: reject before allowlist matching.

## Test requirements

Implementation issues #6 and #7 must include negative tests proving:
- Caller cannot request another human user's principal.
- Caller cannot request `root`, `ec2-user`, or a service account without explicit override.
- Request-body caller identity fields do not affect authorization.
- Allowed override succeeds only for configured caller and configured target principal.
- Host certificate requests use host policy and fail under user-only authorization.
- Malformed, duplicate, Unicode-confusable, or whitespace-padded principals are rejected.
- TTL, source-address, force-command, extensions, and critical options cannot exceed policy by request-body edits.

## Consequences

- Existing BLESS deployments with implicit username mappings may need config mapping in GoBless.
- Policy code must be testable without Lambda or AWS SDK clients.
- Audit events must include both trusted caller identity and requested principals to support investigation.
