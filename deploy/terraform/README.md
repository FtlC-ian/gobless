# GoBless Terraform deployment

This Terraform module deploys GoBless on AWS with the production-oriented architecture described in `docs/ARCHITECTURE.md` and the accepted key-custody and IAM authorization ADRs:

- AWS Lambda runs the GoBless handler.
- AWS KMS holds the asymmetric RSA-4096 CA signing key; private key material never leaves KMS.
- DynamoDB stores audit events with point-in-time recovery and TTL enabled.
- IAM separates the Lambda execution role from the caller invoker policy.

## Prerequisites

- Terraform 1.5 or newer.
- AWS credentials with permission to create Lambda, IAM, KMS, DynamoDB, and CloudWatch Logs resources.
- A packaged GoBless Lambda zip file available at `var.lambda_zip_path` (default: `build/gobless.zip`).

## Package the Lambda

From the repository root, build a Linux Lambda binary named `bootstrap` and zip it:

```bash
mkdir -p build
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/bootstrap ./cmd/gobless
(cd build && zip gobless.zip bootstrap)
```

For arm64 Lambda deployments, build with `GOARCH=arm64` and add an `architectures` argument to the Lambda resource if desired.

## Configure

Create a `terraform.tfvars` file or pass variables on the command line. `kms_key_alias` is required and should not include the `alias/` prefix:

```hcl
kms_key_alias      = "gobless-ca"
allowed_principals = ["alice", "bob"]
kms_admin_principal_arns = [
  "arn:aws:iam::123456789012:role/gobless-deploy",
]
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
- `allowed_cert_types`: `["user"]`
- `enforce_iam_binding`: `false`
- `expected_account_id`: `""`
- `kms_admin_principal_arns`: `[]`
- `reserved_concurrent_executions`: `10`
- `log_retention_days`: `30`

## Remote state

For shared deployments, configure a remote backend before running `apply`. Copy `backend.tf.example` to `backend.tf` and edit the bucket and region for your AWS account, or pass backend settings through your deployment workflow. The backend file is intentionally ignored so account-specific state locations are not committed.

Use an S3 bucket with versioning, server-side encryption, public access blocking, and native S3 lockfile locking (`use_lockfile = true`). Do not commit local `terraform.tfstate` or `terraform.tfvars` files.

## Deploy

```bash
cd deploy/terraform
terraform init
terraform plan -out tfplan
terraform apply tfplan
```

After apply, Terraform prints the Lambda ARN, KMS key ARN/ID, audit table ARN, and Lambda execution role ARN.

## Caller authorization

Terraform creates an invoker IAM policy named `${function_name}-invoker` that allows `lambda:InvokeFunction` on only the GoBless Lambda ARN. Attach that policy to the IAM roles or users that are authorized to request certificates. GoBless still validates requested certificate principals against `allowed_principals`, `allowed_cert_types`, optional `expected_account_id`, and optional IAM principal-binding policy.

## Operational hardening notes

- Use `kms_admin_principal_arns` for short-lived deploy/operator roles that administer the KMS key. Avoid broad standing KMS admin grants on long-lived access-key users.
- Lambda log retention is managed by Terraform. The deploy principal needs scoped CloudWatch Logs permissions for `/aws/lambda/${function_name}`.
- Keep `backend.tf` and `terraform.tfvars` account-local and out of version control.

## Invoke with the AWS CLI

Example direct invocation payload:

```bash
aws lambda invoke \
  --function-name gobless \
  --payload fileb://request.json \
  response.json
cat response.json
```

The exact request JSON shape depends on the GoBless client/compatibility mode in use. Request-body principals are untrusted; IAM authorizes invocation and GoBless policy authorizes certificate contents.
