# GoBless — Agent & Contributor Guide

## What is GoBless?

GoBless is a Go-based, BLESS-compatible SSH certificate authority for standard serverless signing flows. It signs short-lived SSH certificates on behalf of authenticated users, enforcing policy before signing.

## Package Layout

```
cmd/gobless/          CLI entry point
internal/cert/        SSH certificate building and signing helpers
internal/config/      Configuration loading
internal/policy/      Request validation and policy enforcement
internal/signer/      CA signer interface + local and KMS implementations
internal/audit/       Audit event model
internal/lambda/      AWS Lambda handler
testdata/             Keys, golden files, policy fixtures, lambda events, regression cases
docs/                 Additional documentation
```

## Build, Test, and Run

```bash
make vet          # go vet
make test         # go test ./...
make test-race    # go test -race ./...
make ci           # vet + test + test-race (full CI check)
make build        # build the binary
```

All three checks (vet, test, test-race) must pass cleanly before pushing.

## Security-Sensitive Packages

The following packages require careful review before any changes:

- **`internal/cert`** — SSH certificate construction and signing helpers
- **`internal/policy`** — request validation and policy enforcement
- **`internal/signer`** — CA signer interface, local and KMS implementations

Changes to these packages touch the core security boundary of the system. Treat them with extra scrutiny: review the threat model in `docs/` before making modifications, and ensure all tests pass with `-race`.

## Additional Documentation

- `docs/` — architecture overview, threat model, ADRs, test matrix, dependency policy, roadmap
- `testdata/regression/` — regression cases and the process for adding new ones

## Dependency Policy

- `golang.org/x/crypto` — allowed (SSH primitives)
- `AWS SDK v2` — allowed only in narrow adapter/wiring packages (`cmd/gobless`, `internal/signer`, `internal/audit`, `internal/lambda`) and behind small internal interfaces
- All other dependencies require explicit justification in the PR description

See `docs/DEPENDENCY_POLICY.md` for full details.

## Contribution Guidelines

- Match existing code style and conventions
- Add or update tests for any changed behaviour
- Keep PRs focused — one logical change per PR
- Security-sensitive changes (anything touching `internal/signer`, `internal/cert`, `internal/policy`) should include a reviewer with security expertise before merge
- No self-merges
- All keys in `testdata/keys/` are for testing only — never commit real secrets
