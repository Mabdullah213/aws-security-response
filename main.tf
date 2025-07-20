# --- Provider & Backend Configuration ---
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.2"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "us-east-1"
}

# --- 1. Package the Lambda Function ---
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "lambda_function.py"
  output_path = "lambda_function_payload.zip"
}

# --- 2. Create the IAM Role and Policy for Lambda ---
data "aws_iam_policy_document" "security_waf_update_policy_doc" {
  # Allows listing all IP sets to find the correct one by name
  statement {
    sid       = "ListWAFIPSets"
    effect    = "Allow"
    actions   = ["wafv2:ListIPSets"]
    resources = ["*"] # List action requires a broader resource scope
  }

  # Allows getting and updating only the specific IP set
  statement {
    sid    = "GetAndUpdateSpecificWAFIPSet"
    effect = "Allow"
    actions = [
      "wafv2:GetIPSet",
      "wafv2:UpdateIPSet"
    ]
    resources = [aws_wafv2_ip_set.security_malicious_ips.arn]
  }
}

resource "aws_iam_policy" "security_waf_update_policy" {
  name   = "security-waf-update-policy"
  policy = data.aws_iam_policy_document.security_waf_update_policy_doc.json
}

resource "aws_iam_role" "security_waf_update_role" {
  name = "security-waf-update-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "custom_waf_policy_attach" {
  role       = aws_iam_role.security_waf_update_role.name
  policy_arn = aws_iam_policy.security_waf_update_policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_logging_attach" {
  role       = aws_iam_role.security_waf_update_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# --- 3. Create SQS Dead-Letter Queue for Resilience ---
resource "aws_sqs_queue" "security_lambda_dlq" {
  name = "security-lambda-dlq"
}

# --- 4. Create the Lambda Function ---
resource "aws_lambda_function" "security_block_malicious_ip" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "security-block-malicious-ip"
  role             = aws_iam_role.security_waf_update_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      IP_SET_NAME = aws_wafv2_ip_set.security_malicious_ips.name
      WAF_SCOPE   = aws_wafv2_ip_set.security_malicious_ips.scope
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.security_lambda_dlq.arn
  }

  depends_on = [aws_iam_role_policy_attachment.dlq_policy_attach]
}

# --- 5. IAM Policy for Lambda to send to DLQ ---
data "aws_iam_policy_document" "security_lambda_dlq_policy_doc" {
  statement {
    effect = "Allow"
    actions = [
      "sqs:SendMessage"
    ]
    resources = [
      aws_sqs_queue.security_lambda_dlq.arn
    ]
  }
}

resource "aws_iam_policy" "security_lambda_dlq_policy" {
  name   = "security-lambda-dlq-send-policy"
  policy = data.aws_iam_policy_document.security_lambda_dlq_policy_doc.json
}

resource "aws_iam_role_policy_attachment" "dlq_policy_attach" {
  role       = aws_iam_role.security_waf_update_role.name
  policy_arn = aws_iam_policy.security_lambda_dlq_policy.arn
}

# --- 6. Create the WAF Resources ---
resource "aws_wafv2_ip_set" "security_malicious_ips" {
  name               = "security-malicious-ips"
  scope              = "CLOUDFRONT"
  ip_address_version = "IPV4"
  addresses          = []
}

# --- 7. Enable GuardDuty ---
data "aws_guardduty_detector" "default" {}

# --- 8. Create the EventBridge Rule & Target ---
resource "aws_cloudwatch_event_rule" "security_guardduty_finding_rule" {
  name        = "security-guardduty-finding-rule"
  description = "Trigger on GuardDuty Recon:EC2/Portscan findings"

  event_pattern = jsonencode({
    "source" : ["aws.guardduty", "com.my-test-source"],
    "detail-type" : ["GuardDuty Finding"],
    "detail" : {
      "type" : ["Recon:EC2/Portscan"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.security_guardduty_finding_rule.name
  target_id = "SecurityBlockMaliciousIPLambda"
  arn       = aws_lambda_function.security_block_malicious_ip.arn
}

# --- 9. Grant EventBridge Permission to Invoke Lambda ---
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_block_malicious_ip.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_guardduty_finding_rule.arn
}