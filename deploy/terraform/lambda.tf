resource "aws_cloudwatch_log_group" "gobless" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_lambda_function" "gobless" {
  function_name                  = var.function_name
  role                           = aws_iam_role.lambda_execution.arn
  runtime                        = "provided.al2023"
  handler                        = "bootstrap"
  filename                       = var.lambda_zip_path
  source_code_hash               = filebase64sha256(var.lambda_zip_path)
  reserved_concurrent_executions = var.reserved_concurrent_executions

  environment {
    variables = {
      GOBLESS_CA_DYNAMODB_TABLE       = var.dynamodb_table_name
      GOBLESS_CA_KMS_KEY_ID           = aws_kms_key.gobless_ca.key_id
      GOBLESS_CA_MAX_TTL              = tostring(var.max_ttl_seconds)
      GOBLESS_CA_DEFAULT_TTL          = tostring(var.default_ttl_seconds)
      GOBLESS_CA_SIGNER_TYPE          = "kms"
      GOBLESS_LAMBDA_FUNCTION_NAME    = var.function_name
      GOBLESS_LAMBDA_REGION           = var.aws_region
      GOBLESS_LOGGING_AUDIT_ENABLED   = "true"
      GOBLESS_LOGGING_AUDIT_FAIL_OPEN = tostring(var.audit_fail_open)
      GOBLESS_PRINCIPAL_ALLOWED       = join(",", var.allowed_principals)
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.gobless,
    aws_iam_role_policy.lambda_execution,
  ]

  tags = var.tags
}
