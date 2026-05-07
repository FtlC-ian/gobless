output "lambda_arn" {
  description = "ARN of the GoBless Lambda function."
  value       = aws_lambda_function.gobless.arn
}

output "kms_key_arn" {
  description = "ARN of the GoBless KMS CA signing key."
  value       = aws_kms_key.gobless_ca.arn
}

output "kms_key_id" {
  description = "ID of the GoBless KMS CA signing key."
  value       = aws_kms_key.gobless_ca.key_id
}

output "dynamodb_table_arn" {
  description = "ARN of the GoBless audit DynamoDB table."
  value       = aws_dynamodb_table.gobless_audit.arn
}

output "lambda_execution_role_arn" {
  description = "ARN of the GoBless Lambda execution role."
  value       = aws_iam_role.lambda_execution.arn
}
