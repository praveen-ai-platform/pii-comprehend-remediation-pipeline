terraform {
  required_version = ">= 1.6, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "pii-comprehend-remediation", ManagedBy = "Terraform" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_s3_bucket" "sanitized" {
  bucket_prefix = "${var.name}-"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "sanitized" {
  bucket                  = aws_s3_bucket.sanitized.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sanitized" {
  bucket = aws_s3_bucket.sanitized.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "tls" {
  bucket = aws_s3_bucket.sanitized.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport", Effect = "Deny", Principal = "*", Action = "s3:*"
      Resource  = [aws_s3_bucket.sanitized.arn, "${aws_s3_bucket.sanitized.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "retention" {
  bucket = aws_s3_bucket.sanitized.id
  rule {
    id     = "expire-sanitized-records"
    status = "Enabled"
    filter { prefix = "sanitized/" }
    expiration { days = var.retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
}

resource "aws_cloudwatch_log_group" "function" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = 14
}

resource "aws_iam_role" "function" {
  name_prefix = "${var.name}-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "function" {
  role = aws_iam_role.function.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.function.arn}:*" },
      # DetectPiiEntities does not support resource-level IAM restrictions.
      { Effect = "Allow", Action = ["comprehend:DetectPiiEntities"], Resource = "*" },
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${aws_s3_bucket.sanitized.arn}/sanitized/*" }
    ]
  })
}

resource "aws_lambda_function" "pipeline" {
  function_name                  = var.name
  role                           = aws_iam_role.function.arn
  filename                       = var.lambda_zip
  source_code_hash               = filebase64sha256(var.lambda_zip)
  handler                        = "src.lambda_handler.lambda_handler"
  runtime                        = "python3.13"
  architectures                  = ["x86_64"]
  timeout                        = 120
  memory_size                    = 256
  reserved_concurrent_executions = 2
  environment {
    variables = {
      ENVIRONMENT      = "production"
      PII_BACKEND      = "comprehend"
      PII_LANGUAGE     = var.language
      SANITIZED_BUCKET = aws_s3_bucket.sanitized.id
    }
  }
  logging_config {
    log_format            = "JSON"
    application_log_level = "INFO"
    system_log_level      = "WARN"
  }
  depends_on = [aws_iam_role_policy.function, aws_s3_bucket_public_access_block.sanitized, aws_s3_bucket_server_side_encryption_configuration.sanitized]
}

resource "aws_lambda_permission" "cloudwatch" {
  count          = var.source_log_group_name == null ? 0 : 1
  statement_id   = "AllowCloudWatchLogs"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.pipeline.function_name
  principal      = "logs.${var.region}.amazonaws.com"
  source_account = data.aws_caller_identity.current.account_id
  source_arn     = "arn:${data.aws_partition.current.partition}:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${var.source_log_group_name}:*"
}

resource "aws_cloudwatch_log_subscription_filter" "source" {
  count           = var.source_log_group_name == null ? 0 : 1
  name            = "${var.name}-sanitize"
  log_group_name  = var.source_log_group_name
  filter_pattern  = ""
  destination_arn = aws_lambda_function.pipeline.arn
  depends_on      = [aws_lambda_permission.cloudwatch]
  lifecycle {
    precondition {
      condition     = var.source_log_group_name != "/aws/lambda/${var.name}"
      error_message = "Source log group must differ from the Lambda log group to prevent recursion."
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${var.name}-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { FunctionName = aws_lambda_function.pipeline.function_name }
  alarm_actions       = var.alarm_actions
}

output "function_name" { value = aws_lambda_function.pipeline.function_name }
output "sanitized_bucket" { value = aws_s3_bucket.sanitized.id }
