# Test Keys — NOT FOR PRODUCTION USE

> ⚠️ **WARNING**: The key material in this directory is for testing and development purposes ONLY.
>
> - These keys are **not secret** and are **committed to version control**.
> - **Never use these keys in any production, staging, or sensitive environment.**
> - These keys exist solely for running tests and generating test fixtures.

## Files

| File | Description |
|------|-------------|
| `test_rsa` | RSA 2048-bit private key, no passphrase — TEST ONLY |
| `test_rsa.pub` | Corresponding SSH public key — TEST ONLY |

## Regenerating

```bash
ssh-keygen -t rsa -b 2048 -f testdata/keys/test_rsa -N "" -C "gobless-test-key-DO-NOT-USE-IN-PRODUCTION"
```

Or generate in-memory during tests using `rsa.GenerateKey` (see `internal/signer/local_test.go`).
