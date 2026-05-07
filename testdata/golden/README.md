# SSH Certificate Golden Vectors

Golden fixtures describe expected OpenSSH certificate properties in a normalized JSON format. They are designed for tests that generate a certificate from fixture inputs, inspect it with Go's `golang.org/x/crypto/ssh` parser and/or `ssh-keygen -L`, normalize host/time-specific fields, and compare the result to `expected_fields`.

## Fixture Format

Each `*.json` fixture contains:

- `description`: human-readable scenario.
- `cert_type`: `user` or `host`.
- `key_type`: public key algorithm for the subject key, e.g. `rsa`.
- `principals`: certificate valid principals.
- `ttl_seconds`: requested certificate lifetime.
- `extensions`: map of SSH certificate extension names to values. Empty string values represent OpenSSH boolean extensions.
- `critical_options`: map of critical option names to values.
- `expected_fields`: map of normalized `ssh-keygen -L` field names to exact expected strings or regex-style patterns.

The generator stub in `gen/main.go` is for deterministic test-only material. It must never be used for production key material.
