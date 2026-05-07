variable "aws_region" {
  description = "AWS region for GoBless resources."
  type        = string
  default     = "us-east-1"
}

variable "function_name" {
  description = "Name of the GoBless Lambda function."
  type        = string
  default     = "gobless"
}

variable "kms_key_alias" {
  description = "KMS alias name for the CA signing key, without the alias/ prefix."
  type        = string
}

variable "kms_admin_principal_arns" {
  description = "Additional IAM principal ARNs allowed to administer the GoBless KMS key. Prefer short-lived operator or CI deploy roles, not long-lived access-key users. Account root remains in the policy to avoid key lockout."
  type        = list(string)
  default     = []
}

variable "dynamodb_table_name" {
  description = "DynamoDB table name for audit events."
  type        = string
  default     = "gobless-audit"
}

variable "audit_fail_open" {
  description = "If true, signing proceeds when audit writes fail. Dangerous; keep false for production."
  type        = bool
  default     = false
}

variable "max_ttl_seconds" {
  description = "Maximum certificate TTL accepted by GoBless, in seconds."
  type        = number
  default     = 3600
}

variable "allowed_principals" {
  description = "Principal allowlist enforced by GoBless policy. Set this explicitly for production. When empty, GoBless still denies well-known privileged principals but otherwise behaves like a permissive demo configuration."
  type        = list(string)
  default     = []
}

variable "enforce_iam_binding" {
  description = "If true, requested principals must match the invoking IAM identity. Recommended for production when caller identities map directly to SSH principals."
  type        = bool
  default     = false
}

variable "expected_account_id" {
  description = "Expected AWS account ID for invocations. Leave empty to disable account pinning."
  type        = string
  default     = ""
}

variable "allowed_cert_types" {
  description = "Certificate types GoBless may issue. Production defaults to user certs only."
  type        = list(string)
  default     = ["user"]
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the Lambda log group."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags applied to provisioned resources."
  type        = map(string)
  default     = {}
}

variable "lambda_zip_path" {
  description = "Path to the packaged GoBless Lambda zip file."
  type        = string
  default     = "build/gobless.zip"
}

variable "reserved_concurrent_executions" {
  description = "Reserved concurrency for the GoBless Lambda function."
  type        = number
  default     = 10
}
