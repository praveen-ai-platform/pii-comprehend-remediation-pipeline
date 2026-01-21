import re
from typing import Dict, List, Tuple

# Simple patterns (demo). Replace with Amazon Comprehend DetectPiiEntities in production.
PATTERNS: List[Tuple[str, str]] = [
    ("EMAIL", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ("PHONE", r"\b(?:\+?\d{1,3}[- ]?)?(?:\d{10})\b"),
    ("CREDIT_CARD", r"\b(?:\d[ -]*?){13,16}\b"),
]

def detect_pii(text: str) -> List[Dict]:
    findings = []
    for label, pat in PATTERNS:
        for m in re.finditer(pat, text):
            findings.append({"type": label, "start": m.start(), "end": m.end(), "value": m.group(0)})
    return sorted(findings, key=lambda x: x["start"])

def mask_pii(text: str, mask_char: str="*") -> str:
    findings = detect_pii(text)
    if not findings:
        return text
    out = []
    last = 0
    for f in findings:
        out.append(text[last:f["start"]])
        out.append(mask_char * (f["end"] - f["start"]))
        last = f["end"]
    out.append(text[last:])
    return "".join(out)
