# GoBless — AWS Deployment Guide

GoBless can run as an AWS Lambda SSH certificate authority with AWS KMS holding the asymmetric CA signing key and DynamoDB storing audit events.

## Prerequisites

- Terraform 1.5 or newer.
- AWS credentials for a deployment role or user that can manage Lambda, IAM, KMS, DynamoDB, CloudWatch Logs, and the Terraform state backend.
- A Terraform S3 backend bucket with versioning, encryption, public access blocking, and native S3 lockfile support enabled via `use_lockfile = true`.

Do not commit real `terraform.tfvars`, Terraform state, AWS credentials, packaged Lambda zips, or generated `bootstrap` binaries.

## Package the Lambda

From the repository root:

```bash
mkdir -p build
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -tags production -o build/bootstrap ./cmd/gobless
(cd build && zip gobless.zip bootstrap)
```

## Configure Terraform

Copy the example backend and edit it for your account, or pass backend settings through your deployment workflow:

```bash
cp deploy/terraform/backend.tf.example deploy/terraform/backend.tf
```

Example `terraform.tfvars`:

```hcl
aws_region          = "us-east-1"
function_name       = "gobless"
kms_key_alias       = "gobless-ca"
dynamodb_table_name = "gobless-audit"
lambda_zip_path     = "../../build/gobless.zip"
kms_admin_principal_arns = [
  "arn:aws:iam::123456789012:role/gobless-deploy",
]

max_ttl_seconds  = 3600
audit_fail_open  = false
allowed_principals = ["alice", "bob"]

# Recommended production hardening.
allowed_cert_types     = ["user"]
expected_account_id    = "123456789012"
enforce_iam_binding    = true
log_retention_days     = 30

tags = {
  Project   = "gobless"
  ManagedBy = "terraform"
}
```

Use `enforce_iam_binding = true` only when your AWS caller identity names intentionally match SSH principals. If you invoke through assumed roles or federated sessions, validate the mapping before enabling it.

Use `kms_admin_principal_arns` for short-lived deploy or operator roles that administer the CA key. Avoid long-lived access-key users as KMS administrators.

## Deploy

```bash
terraform -chdir=deploy/terraform init
terraform -chdir=deploy/terraform plan -out tfplan
terraform -chdir=deploy/terraform apply tfplan
```

Terraform creates:

- Lambda function.
- KMS RSA-4096 asymmetric signing key and alias.
- DynamoDB audit table with TTL and point-in-time recovery.
- CloudWatch log group with configured retention.
- Lambda execution role.
- Invoker IAM policy scoped to the Lambda function.

## Caller authorization

Attach the generated invoker policy only to principals that may request SSH certificates. Invocation permission alone is not enough to get a certificate: GoBless also validates certificate type, requested principals, TTL, source address, expected AWS account, and optional IAM identity binding.

## Environment Variable Overrides

GoBless reads `GOBLESS_*` environment variables at runtime in Lambda deployments. These environment variables override values from the configuration file, including security-sensitive CA, policy, and audit settings.

Treat Lambda environment variables as a privileged control surface. Partial access to `lambda:UpdateFunctionConfiguration` is effectively a privilege-escalation path because an attacker who can update environment variables can change GoBless behavior without changing code or Terraform. For example, they could set `GOBLESS_LOGGING_AUDIT_FAIL_OPEN=true` to disable audit enforcement when DynamoDB writes fail, or change `GOBLESS_CA_KMS_KEY_ID` to redirect signing to a different KMS key.

Operators should restrict `lambda:UpdateFunctionConfiguration` to a tightly scoped IAM principal, such as a dedicated deployment role used only by CI/CD or approved infrastructure operators. Do not grant this permission to general developer roles, even if those developers are allowed to invoke GoBless or read logs.

The Terraform module in `deploy/terraform` does not grant `lambda:UpdateFunctionConfiguration` to callers. It creates a caller invoker policy for `lambda:InvokeFunction` only, and a Lambda execution role with the KMS, DynamoDB, and CloudWatch Logs permissions needed by the function. Keep configuration update permissions outside that invoker policy and bind them only to your deployment workflow.

## Tear down

If this was only a test deployment:

```bash
terraform -chdir=deploy/terraform destroy
```

After destroy, disable or delete any deployment access keys that were created only for this stack. Keep state backups only as long as they are operationally useful.
