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

variable "default_ttl_seconds" {
  description = "Default certificate TTL when the signing request does not specify one, in seconds."
  type        = number
  default     = 3600
}

variable "allowed_principals" {
  description = "Principal allowlist enforced by GoBless policy."
  type        = list(string)
  default     = []
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
