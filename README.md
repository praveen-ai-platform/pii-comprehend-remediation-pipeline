# PII Detection & Remediation Pipeline (Comprehend-style)
A simple project showing how to detect and remediate PII in logs before sending to observability tools.

✅ What it demonstrates
- A Lambda-style handler (`lambda_handler`) that:
  - receives log events
  - detects PII entities (local regex demo)
  - masks/redacts sensitive values
  - returns sanitized output

> In production, swap the regex detector with **Amazon Comprehend DetectPiiEntities**.

## Run locally
```bash
python -m venv .venv
pip install -r requirements.txt
python src/local_run.py
```

## Terraform (skeleton)
Terraform files included as a blueprint for wiring:
- Lambda
- IAM
- CloudWatch Logs subscription filter / Kinesis input
- (Optional) SNS alerts for PII found
