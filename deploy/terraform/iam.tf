data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "lambda_execution" {
  name               = "${var.function_name}-execution"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.tags
}

data "aws_iam_policy_document" "lambda_execution" {
  statement {
    sid    = "AllowKmsSigningOnly"
    effect = "Allow"

    actions = [
      "kms:GetPublicKey",
      "kms:Sign",
    ]

    resources = [aws_kms_key.gobless_ca.arn]
  }

  statement {
    sid    = "AllowAuditWrites"
    effect = "Allow"

    actions = ["dynamodb:PutItem"]

    resources = [aws_dynamodb_table.gobless_audit.arn]
  }

  statement {
    sid    = "AllowLambdaLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.function_name}",
      "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.function_name}:*",
    ]
  }
}

resource "aws_iam_role_policy" "lambda_execution" {
  name   = "${var.function_name}-execution"
  role   = aws_iam_role.lambda_execution.id
  policy = data.aws_iam_policy_document.lambda_execution.json
}
