# GoBless — Contributor Notes

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
testdata/             Keys, golden files, policy fixtures, lambda events
docs/                 Additional documentation
```

## Safety Rules Summary

- Prefer the Go standard library. Use `golang.org/x/crypto/ssh` for SSH primitives not covered by the standard library.
- Use AWS SDK v2 only behind small interfaces or in runtime wiring. Keep core policy and certificate logic AWS-free.
- Do not add dependencies unless they are narrowly justified and reviewed.
- Do not commit real credentials, private keys, account data, or production identifiers. Keys in `testdata/keys/` must be generated for testing only.
- Treat signing, policy, key custody, audit, and Lambda handler changes as security-sensitive.

## Test Commands

```bash
make vet          # go vet
make test         # go test ./...
make test-race    # go test -race ./...
make ci           # vet + test + test-race
```

All checks should pass before submitting changes.

## Design Boundaries

- Keep signing and policy logic out of the Lambda adapter.
- Keep AWS clients out of core policy and certificate construction.
- Prefer small interfaces for KMS, audit storage, and runtime wiring.
- Errors and logs must not include private key material, AWS secrets, raw credentials, or stack traces.
