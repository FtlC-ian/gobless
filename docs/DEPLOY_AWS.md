# GoBless — AWS Deployment Guide

GoBless runs as an AWS Lambda function that acts as an SSH certificate authority. It reads configuration from Lambda environment variables, uses AWS KMS for CA signing, and optionally records audit events to DynamoDB.

For detailed step-by-step runbooks (initial deployment, CA key rotation, incident response), see **[docs/RUNBOOKS.md](RUNBOOKS.md)**.

## Deployment Steps

1. **Provision infrastructure** — run `terraform apply` in `deploy/terraform/` to create the Lambda function, IAM roles, KMS key, and (optionally) a DynamoDB audit table.
2. **Package and upload the binary** — `make build` produces a `bootstrap` binary for `provided.al2023`. Zip it and upload via Terraform or `aws lambda update-function-code`.
3. **Configure environment variables** — see the table below. At minimum you need `GOBLESS_CA_KMS_KEY_ID` and `GOBLESS_PRINCIPAL_ALLOWED`.
4. **Verify certificate issuance** — invoke the Lambda with a test signing request and confirm a valid SSH certificate is returned (`ssh-keygen -L` passes).

## Required Environment Variables

| Variable | Description | Example |
|---|---|---|
| `GOBLESS_CA_KMS_KEY_ID` | KMS key ID or ARN used for CA signing | `alias/gobless-ca` |
| `GOBLESS_CA_MAX_TTL` | Maximum certificate lifetime in seconds | `3600` |
| `GOBLESS_CA_DEFAULT_TTL` | Default certificate lifetime in seconds when the request omits TTL | `3600` |
| `GOBLESS_CA_SIGNER_TYPE` | Signer backend: `kms` (production) or `rsa` (local PEM dev only) | `kms` |
| `GOBLESS_PRINCIPAL_ALLOWED` | Comma-separated list of allowed SSH principals | `ec2-user,ubuntu` |
| `GOBLESS_CA_DYNAMODB_TABLE` | DynamoDB table name for audit events (optional) | `gobless-audit` |
| `GOBLESS_LOGGING_AUDIT_ENABLED` | Enable audit logging (`true`/`false`) | `true` |
| `GOBLESS_LOGGING_AUDIT_FAIL_OPEN` | Allow signing when audit write fails (`true`/`false`; default `false`) | `false` |

The Terraform module in `deploy/terraform/` provisions all of the above automatically from Terraform variables. Review `deploy/terraform/variables.tf` for defaults.

## Environment Variable Overrides

GoBless reads `GOBLESS_*` environment variables at runtime in Lambda deployments. These environment variables override values from the configuration file, including security-sensitive CA, policy, and audit settings.

Treat Lambda environment variables as a privileged control surface. Partial access to `lambda:UpdateFunctionConfiguration` is effectively a privilege-escalation path because an attacker who can update environment variables can change GoBless behavior without changing code or Terraform. For example, they could set `GOBLESS_LOGGING_AUDIT_FAIL_OPEN=true` to disable audit enforcement when DynamoDB writes fail, or change `GOBLESS_CA_KMS_KEY_ID` to redirect signing to a different KMS key.

Operators should restrict `lambda:UpdateFunctionConfiguration` to a tightly scoped IAM principal, such as a dedicated deployment role used only by CI/CD or approved infrastructure operators. Do not grant this permission to general developer roles, even if those developers are allowed to invoke GoBless or read logs.

The Terraform IAM module in `deploy/terraform` does not grant `lambda:UpdateFunctionConfiguration` by default. It creates a caller invoker policy for `lambda:InvokeFunction` only, and a Lambda execution role with the KMS, DynamoDB, and CloudWatch Logs permissions needed by the function. Keep configuration update permissions outside that invoker policy and bind them only to your deployment workflow.
