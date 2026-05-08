# GoBless

GoBless is a Go-based, BLESS-compatible SSH certificate authority for standard serverless signing flows. It signs short-lived SSH certificates on behalf of authenticated users and enforces configurable policy before each signing operation.

> **Status:** Local signing, certificate operations, and Lambda/KMS deployment paths are implemented and tested. Operators must still provide AWS credentials, Terraform variables, KMS configuration, and principal policy for their environment; see [docs/DEPLOY_AWS.md](docs/DEPLOY_AWS.md) and [docs/RUNBOOKS.md](docs/RUNBOOKS.md).

## Architecture

GoBless runs as an AWS Lambda function. A client submits a signing request containing a public key and principal metadata. The Lambda handler authenticates the request, evaluates policy, signs the certificate using a CA key (local or AWS KMS), emits an audit event, and returns the signed certificate. Core logic lives in focused internal packages (`cert`, `config`, `policy`, `signer`, `audit`) with a thin Lambda adapter in `internal/lambda`.

## Quickstart (Local Dev)

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full local development flow.

```bash
git clone https://github.com/FtlC-ian/gobless.git
cd gobless
make ci   # vet + test + test-race
```

## BLESS Compatibility

GoBless targets functional compatibility with Netflix BLESS for standard SSH certificate signing flows. It is not a line-for-line port; configuration format and internal structure differ.

## Contributing

## Documentation

See [docs/INDEX.md](docs/INDEX.md) for all documentation.

For Lambda deployments, `GOBLESS_*` environment variables override configuration-file values at runtime. Treat `lambda:UpdateFunctionConfiguration` as privileged deployment access, not general developer access; see [docs/DEPLOY_AWS.md](docs/DEPLOY_AWS.md#environment-variable-overrides).
