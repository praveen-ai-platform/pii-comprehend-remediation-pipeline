# Terraform skeleton (edit as per your AWS account/region)
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# TODO: Create IAM role + policy for Lambda
# TODO: Create Lambda function packaging src/ as zip
# TODO: Wire CloudWatch Logs subscription or Kinesis as source
