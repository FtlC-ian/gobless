data "aws_iam_policy_document" "kms_key" {
  statement {
    sid    = "AllowAccountRootAdministration"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    actions = ["kms:*"]

    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(var.kms_admin_principal_arns) > 0 ? [1] : []

    content {
      sid    = "AllowConfiguredKeyAdministrators"
      effect = "Allow"

      principals {
        type        = "AWS"
        identifiers = var.kms_admin_principal_arns
      }

      actions = ["kms:*"]

      resources = ["*"]
    }
  }

  statement {
    sid    = "AllowLambdaSigningOnly"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda_execution.arn]
    }

    actions = [
      "kms:GetPublicKey",
      "kms:Sign",
    ]

    resources = ["*"]
  }
}

resource "aws_kms_key" "gobless_ca" {
  description              = "GoBless SSH CA asymmetric signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_4096"
  deletion_window_in_days  = 30

  # AWS KMS does not support automatic rotation for asymmetric signing keys.
  enable_key_rotation = false
  policy              = data.aws_iam_policy_document.kms_key.json
  tags                = var.tags
}

resource "aws_kms_alias" "gobless_ca" {
  name          = "alias/${var.kms_key_alias}"
  target_key_id = aws_kms_key.gobless_ca.key_id
}
