from typing import Dict, Any
from .pii_detector import detect_pii, mask_pii

def lambda_handler(event: Dict[str, Any], context=None) -> Dict[str, Any]:
    # Example expected input
    # { "records": [{"message":"user email abc@x.com failed login"}] }
    records = event.get("records", [])
    sanitized = []
    pii_count = 0

    for r in records:
        msg = r.get("message", "")
        findings = detect_pii(msg)
        if findings:
            pii_count += len(findings)
        sanitized.append({
            "original": msg,
            "sanitized": mask_pii(msg),
            "pii_findings": findings
        })

    return {
        "status": "ok",
        "pii_found": pii_count,
        "sanitized_records": sanitized
    }
