variable "region" {
  type    = string
  default = "us-east-1"
}
variable "name" {
  type    = string
  default = "pii-remediation"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,29}$", var.name))
    error_message = "Use 3 to 30 lowercase letters, digits, or hyphens, starting with a letter."
  }
}
variable "lambda_zip" {
  type    = string
  default = "../dist/lambda.zip"
}
variable "language" {
  type    = string
  default = "en"
  validation {
    condition     = contains(["en", "es"], var.language)
    error_message = "Comprehend PII supports en or es."
  }
}
variable "retention_days" {
  type    = number
  default = 30
  validation {
    condition     = var.retention_days >= 1 && var.retention_days <= 365 && floor(var.retention_days) == var.retention_days
    error_message = "Retention must be an integer from 1 to 365 days."
  }
}
variable "source_log_group_name" {
  type        = string
  default     = null
  description = "Existing source log group. Never use this Lambda's own log group."
}
variable "alarm_actions" {
  type        = list(string)
  default     = []
  description = "Optional existing SNS topic ARNs for error notifications."
}
