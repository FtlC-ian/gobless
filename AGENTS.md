# GoBless — Agent Documentation

## Project Overview

GoBless is a Go-based, near drop-in replacement for Netflix BLESS — a serverless SSH certificate authority. It signs short-lived SSH certificates on behalf of authenticated users, enforcing policy before signing.

## Repo Layout

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

## Safety Rules Summary

- **Standard library first.** Only reach for `golang.org/x/crypto/ssh` when the stdlib doesn't cover it.
- **AWS SDK v2 only, behind small interfaces.** Keep concrete SDK usage in runtime wiring or AWS adapter packages; keep core policy/cert logic AWS-free.
- **No other deps** unless explicitly justified and approved in a PR.
- **No secrets in code or test fixtures.** All keys in `testdata/keys/` must be generated for testing only.
- **Security-sensitive changes** (signing logic, policy evaluation, key handling) require Hawk's review before merge.

## Test Commands

```bash
make vet          # go vet
make test         # go test ./...
make test-race    # go test -race ./...
make ci           # vet + test + test-race
```

All three must pass cleanly before pushing.

## Review Protocol

- Every PR needs a builder and a reviewer from different agent families.
- Security-sensitive changes (anything touching `internal/signer`, `internal/cert`, `internal/policy`) require Hawk's review.
- No self-merges.

## Dependency Policy

- `golang.org/x/crypto` — allowed (SSH primitives)
- `AWS SDK v2` — allowed in AWS adapter/runtime packages such as `cmd/gobless`, `internal/signer`, and `internal/audit`; core policy and certificate construction must stay AWS-free
- All other dependencies require explicit justification in the PR description

## What NOT To Do

- Don't add dependencies without approval
- Don't put signing or policy logic in the Lambda handler
- Don't skip tests for "quick fixes"
- Don't merge security-sensitive code without Hawk's sign-off
- Don't commit real private keys or credentials anywhere
