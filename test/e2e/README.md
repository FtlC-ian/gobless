# E2E Smoke Tests

These tests exercise the full GoBless trust chain using the local signer (non-production path).

## Requirements

- Go 1.24+
- `ssh-keygen` must be in `PATH` (standard on macOS/Linux; part of OpenSSH)
- No AWS account or KMS key required — uses the local RSA signer only

## Running

```bash
GOTOOLCHAIN=local go test -v -tags e2e ./test/e2e/
```

Or via the Makefile target:

```bash
make e2e
```

## What the tests cover

| Test | Description |
|------|-------------|
| `TestSignAndVerify_UserCert` | Signs a user cert, validates type/principals/extensions, verifies with `ssh-keygen -L` |
| `TestSignAndVerify_HostCert` | Signs a host cert, validates type/principals, verifies with `ssh-keygen -L` |
| `TestExpiredCert_Rejected` | Signs with TTL=1s, waits 2s, asserts cert is expired (structural validity confirmed via `ssh-keygen -L`) |
| `TestInvalidPrincipal_Denied` | Asserts that `root` is denied without explicit allowlist entry |
| `TestCAPublicKey_Roundtrip` | Calls `RunCAPubKey` and verifies the output matches the CA key generated in setup |

## Notes

- The `e2e` build tag keeps these tests out of normal `go test ./...` runs. CI will not run them unless explicitly invoked.
- These tests use the local signer only (`!production` build tag). The production KMS path is not exercised.
- A fresh RSA 4096 CA key and RSA 2048 user key are generated in a temporary directory per test run.
