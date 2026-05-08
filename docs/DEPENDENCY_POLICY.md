# GoBless Dependency Policy

GoBless is security-sensitive certificate authority software. Dependency choices must optimize for auditability, stable maintenance, and small attack surface.

## Rule

Standard library first.

A dependency is allowed only when it provides a concrete capability that would be unsafe, wasteful, or incompatible to reimplement. Convenience alone is not enough.

## Approved dependencies

| Dependency | Allowed use | Rationale | Boundary |
| --- | --- | --- | --- |
| `golang.org/x/crypto/ssh` | SSH public key parsing, OpenSSH certificate primitives, certificate marshaling and verification helpers. | OpenSSH certificate wire format is security-sensitive and compatibility-sensitive. The Go SSH package is the appropriate maintained primitive. | May be used by certificate, signer, CLI, and tests. |
| `github.com/aws/aws-sdk-go-v2` service clients | AWS Lambda invocation, KMS signing/public-key export, DynamoDB audit backend, STS/IAM identity integrations as required. | GoBless is an AWS Lambda CA; AWS integration is required. SDK v2 is the maintained AWS Go SDK. | Concrete clients must stay behind internal interfaces so core policy/cert code is testable without AWS. Import only required service modules. |

Approved does not mean unrestricted. Each import must still be necessary for the package using it.

## New dependency review gate

Any dependency not listed above requires explicit pull request justification containing:

1. Package name and exact module path.
2. Feature requiring it.
3. Why the standard library or an approved dependency is insufficient.
4. Runtime vs test-only classification.
5. Transitive dependency count and notable transitive modules.
6. Security history and maintenance signal.
7. Maintainer stability assessment: release cadence, ownership, bus factor, and compatibility practices.
8. Removal plan if the dependency becomes unmaintained or security-problematic.

Security-adjacent dependencies require reviewer approval and security review before merge.

## Banned without explicit approval

The following are banned unless a future ADR or PR security review grants a narrow exception:

- Web frameworks.
- Config frameworks.
- Logging frameworks.
- Assertion libraries such as `stretchr/testify`.
- CLI frameworks.
- Reflection-heavy validation/mapping libraries.
- Serialization packages when `encoding/json`, `encoding/pem`, `encoding/base64`, or other standard-library packages suffice.
- Global dependency injection containers.
- Packages that execute subprocesses for core signing, policy, or parsing paths.

## Test dependencies

Test dependencies follow the same rule. Prefer Go's built-in `testing`, `httptest`, `cmp` patterns implemented locally, table-driven tests, and small fakes.

A test-only dependency may be approved only if it materially improves security coverage or compatibility validation and cannot be replaced with a small local helper.

## AWS SDK containment

AWS SDK imports must be isolated to adapter packages. Core packages must depend on small interfaces such as:

- signer interface;
- audit sink interface;
- identity provider interface;
- AWS_IAM-signed API Gateway client interface for CLI code.

Core policy and certificate-builder tests must run without AWS credentials and without network access.

## Inventory and enforcement

Every PR that adds or changes Go modules must include reviewer-visible dependency justification. Run:

```sh
make deps
```

`make deps` runs `go mod verify`, `go mod tidy`, and fails if `go.mod` or `go.sum` would change. The GitHub CI `deps` job runs the same target, so dependency drift should be fixed before review.

For manual inventory review, use:

```sh
go list -m all
```

## Reviewer checklist item

Every PR reviewer must answer:

> Does this PR add or expand non-standard-library dependencies? If yes, is each dependency approved in `docs/DEPENDENCY_POLICY.md` or justified with security and maintainer review?

If the answer is unclear, the PR must not merge.
