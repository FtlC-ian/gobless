# GoBless Test Strategy

GoBless is a security-sensitive SSH certificate authority. Tests must prove correctness, compatibility with BLESS-style callers, policy-deny behavior, and the absence of secret leakage in failure paths.

## Test Categories and CI Gates

| Category | Description | CI gate |
| --- | --- | --- |
| Unit | Fast package-level tests for cert construction, policy evaluation, signer interfaces, config parsing, audit fields, and Lambda request routing. | `make test` / `go test ./...` on every MR and main branch push. |
| Golden/compatibility | Deterministic SSH certificate vectors compared against normalized `ssh-keygen -L` fields, including key type, certificate type, principals, critical options, extensions, validity windows, and serial/key IDs. | `make test` / `go test ./...` on every MR and main branch push. Fixtures live under `testdata/golden/`. |
| Negative/policy | Deny-case fixtures for unauthorized principals, privileged users, malformed TTLs, IAM mismatches, malformed source-address options, and host/user certificate boundary violations. | `make test` / `go test ./...` on every MR and main branch push. Fixtures live under `testdata/policy/negative/`. |
| Lambda fixture | API Gateway/Lambda event fixtures and expected sanitized error responses for BLESS-compatible request handling. | `make test` / `go test ./...` on every MR and main branch push. Fixtures live under `testdata/lambda/`. |
| Race/concurrency | Race detector coverage for all packages, with emphasis on signer/key cache behavior, policy loading, audit emission, and Lambda handler reuse across invocations. | Required CI gate: `go test -race ./...` via `make test-race` / `make ci` on every MR and main branch push. |
| Fuzz/adversarial | Fuzz and adversarial inputs for public key parsing, JSON request decoding, principal normalization, source-address parsing, TTL boundaries, and redaction paths. | Scheduled/nightly CI and optional manual CI gate; crashes or minimized reproducers become regression tests before merge. |
| OpenSSH interoperability | End-to-end checks with `ssh-keygen -L` and, where practical, `sshd`/`ssh` acceptance behavior for generated user and host certificates. | Nightly CI and release candidate gate; lightweight golden normalization runs in `go test ./...`. |
| Redaction/secret-leak | Assertions that errors, Lambda responses, audit logs, and test output do not include private keys, AWS secrets, request credentials, stack traces, or raw sensitive payloads. | `make test` / `go test ./...` on every MR and main branch push; additional grep/audit checks in release gate. |
| End-to-end smoke | Minimal CLI/Lambda-style signing smoke using generated test-only keys and representative policy/config fixtures. | Release candidate gate and optional manual CI gate; may run in MR CI once deterministic and fast. |

## Race Detection Policy

`go test -race ./...` is required in CI for all packages. A merge request is not considered green unless the race detector passes without exclusions. If a package cannot run under the race detector, the MR must document the reason, create a follow-up issue, and receive explicit maintainer approval before merge.

## Fixture and Traceability Expectations

- Every implemented security or compatibility requirement must map to at least one row in `docs/TEST_MATRIX.md`.
- Test fixture directories include a README describing the local format.
- Fixtures must not contain real private keys, AWS credentials, user secrets, or production identifiers.
- Golden vectors must be reproducible from documented generators and normalized before comparison to avoid wall-clock and host-specific noise.
- Negative authorization fixtures should assert both denial and sanitized error behavior.
