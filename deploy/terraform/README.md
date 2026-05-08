# GoBless Terraform deployment

This Terraform module deploys GoBless on AWS with the production-oriented architecture described in `docs/ARCHITECTURE.md` and the accepted key-custody and IAM authorization ADRs:

- AWS Lambda runs the GoBless handler.
- AWS KMS holds the asymmetric RSA-4096 CA signing key; private key material never leaves KMS.
- DynamoDB stores audit events with point-in-time recovery and TTL enabled.
- IAM grants the Lambda execution role only the KMS, DynamoDB, and log permissions needed by the backend.

## Prerequisites

- Terraform 1.5 or newer.
- AWS credentials with permission to create Lambda, IAM, KMS, DynamoDB, and CloudWatch Logs resources.
- A packaged GoBless Lambda zip file available at `var.lambda_zip_path` (default: `build/gobless.zip`).

## Package the Lambda

From the repository root, build a Linux Lambda binary named `bootstrap` and zip it:

```bash
mkdir -p build
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags production -o build/bootstrap ./cmd/gobless
(cd build && zip gobless.zip bootstrap)
```

For arm64 Lambda deployments, build with `GOARCH=arm64` and add an `architectures` argument to the Lambda resource if desired.

## Configure

Create a `terraform.tfvars` file or pass variables on the command line. `kms_key_alias` is required and should not include the `alias/` prefix:

```hcl
kms_key_alias      = "gobless-ca"
allowed_principals = ["alice", "bob"]
tags = {
  Project = "gobless"
}
```

Useful defaults:

- `aws_region`: `us-east-1`
- `function_name`: `gobless`
- `dynamodb_table_name`: `gobless-audit`
- `audit_fail_open`: `false`
- `max_ttl_seconds`: `3600`
- `reserved_concurrent_executions`: `10`
- `log_retention_days`: `30`

## Deploy

```bash
cd deploy/terraform
terraform init
terraform plan -out tfplan
terraform apply tfplan
```

After apply, Terraform prints the Lambda ARN, KMS key ARN/ID, audit table ARN, and Lambda execution role ARN.

## Caller authorization

This module intentionally does not create a caller invoker policy or public endpoint. The current GoBless Lambda entrypoint expects an API Gateway proxy event and derives trusted caller identity from API Gateway request context populated by AWS_IAM authorization.

Do not attach direct `lambda:InvokeFunction` permissions to normal certificate requesters for this handler. Direct Lambda invoke payloads are caller-controlled and can spoof API Gateway `requestContext`. Put the function behind API Gateway AWS_IAM, or add a separate trusted direct-invoke adapter before granting end-user invocation permissions.
