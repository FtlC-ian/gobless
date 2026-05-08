# GoBless — AWS Deployment Guide

GoBless runs as an AWS Lambda function that acts as an SSH certificate authority. The current Lambda entrypoint expects an API Gateway proxy-style event and derives caller identity from API Gateway request context populated by AWS_IAM authorization. It reads configuration from Lambda environment variables, uses AWS KMS for CA signing, and optionally records audit events to DynamoDB.

For detailed step-by-step runbooks (initial deployment, CA key rotation, incident response), see **[docs/RUNBOOKS.md](RUNBOOKS.md)**.

## Deployment Steps

1. **Provision backend infrastructure** — run `terraform apply` in `deploy/terraform/` to create the Lambda function, execution role, KMS key, DynamoDB audit table, and logs. This module does **not** create the public caller endpoint.
2. **Package and upload the binary** — build `./cmd/gobless` with `-tags production` as a Lambda `bootstrap`, zip it, and upload via Terraform or `aws lambda update-function-code`. See the runbook or Terraform README for copy/paste commands.
3. **Configure environment variables** — see the table below. At minimum you need `GOBLESS_CA_KMS_KEY_ID` and `GOBLESS_PRINCIPAL_ALLOWED`.
4. **Expose a trusted caller boundary** — configure API Gateway proxy integration with AWS_IAM authorization, or another adapter that supplies trusted caller identity outside the request body. Do not grant end users direct `lambda:InvokeFunction` access to this handler.
5. **Verify certificate issuance** — invoke through the trusted integration and confirm a valid SSH certificate is returned (`ssh-keygen -L` passes).

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

The Terraform module in `deploy/terraform/` provisions the Lambda/KMS/DynamoDB backend environment variables from Terraform variables. It intentionally does not provision an API Gateway endpoint yet. Review `deploy/terraform/variables.tf` for defaults.

## Environment Variable Overrides

GoBless reads `GOBLESS_*` environment variables at runtime in Lambda deployments. These environment variables override values from the configuration file, including security-sensitive CA, policy, and audit settings.

Treat Lambda environment variables as a privileged control surface. Partial access to `lambda:UpdateFunctionConfiguration` is effectively a privilege-escalation path because an attacker who can update environment variables can change GoBless behavior without changing code or Terraform. For example, they could set `GOBLESS_LOGGING_AUDIT_FAIL_OPEN=true` to disable audit enforcement when DynamoDB writes fail, or change `GOBLESS_CA_KMS_KEY_ID` to redirect signing to a different KMS key.

Operators should restrict `lambda:UpdateFunctionConfiguration` to a tightly scoped IAM principal, such as a dedicated deployment role used only by CI/CD or approved infrastructure operators. Do not grant this permission to general developer roles, even if those developers are allowed to invoke GoBless or read logs.

The Terraform IAM module in `deploy/terraform` does not grant `lambda:UpdateFunctionConfiguration` by default. It creates only the Lambda execution role with the KMS, DynamoDB, and CloudWatch Logs permissions needed by the function. Keep configuration update permissions outside caller roles and bind them only to your deployment workflow.

## Invocation boundary

The production Lambda handler consumes API Gateway proxy-style events. The trusted identity comes from `requestContext.identity.userArn` and `requestContext.accountId`, which API Gateway populates when the method uses AWS_IAM authorization. Request-body identity fields are never trusted.

Do not attach direct `lambda:InvokeFunction` permissions to normal certificate requesters for this handler. A direct Lambda invocation payload is caller-controlled and can spoof `requestContext`; it is suitable only for tightly controlled operator smoke tests where the payload is not treated as an authorization boundary. Public/user certificate issuance should go through API Gateway AWS_IAM or an equivalent trusted adapter.
