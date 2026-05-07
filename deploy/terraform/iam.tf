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
      "arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.function_name}",
      "arn:aws:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.function_name}:*",
    ]
  }
}

resource "aws_iam_role_policy" "lambda_execution" {
  name   = "${var.function_name}-execution"
  role   = aws_iam_role.lambda_execution.id
  policy = data.aws_iam_policy_document.lambda_execution.json
}

data "aws_iam_policy_document" "invoker" {
  statement {
    sid    = "AllowInvokeGoBless"
    effect = "Allow"

    actions = ["lambda:InvokeFunction"]

    resources = [aws_lambda_function.gobless.arn]
  }
}

resource "aws_iam_policy" "invoker" {
  name        = "${var.function_name}-invoker"
  description = "Allows callers to invoke the GoBless Lambda function. Attach to authorized caller roles or users."
  policy      = data.aws_iam_policy_document.invoker.json
  tags        = var.tags
}
