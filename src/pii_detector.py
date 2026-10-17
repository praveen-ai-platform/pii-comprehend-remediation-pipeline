"""PII detection without raw-value findings; detection errors fail closed."""
from dataclasses import dataclass
import re

MAX_TEXT_BYTES = 100000

@dataclass(frozen=True)
class Finding:
    type: str
    start: int
    end: int
    score: float = 1.0

PATTERNS = [
    ('EMAIL', r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'),
    ('PHONE', r'(?<!\w)\+?\d(?:[ -]?\d){9,14}(?!\w)'),
    ('CREDIT_DEBIT_NUMBER', r'(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)'),
]

class RegexDetector:
    """Offline demonstration only; not a substitute for Comprehend detection."""
    def detect(self, text):
        validate_text(text)
        return sorted([Finding(label, m.start(), m.end()) for label, pattern in PATTERNS
                       for m in re.finditer(pattern, text)], key=lambda f: (f.start, f.end))

class ComprehendDetector:
    def __init__(self, client=None, language='en'):
        if language not in {'en', 'es'}:
            raise ValueError('PII detection supports English and Spanish')
        if client is None:
            import boto3
            from botocore.config import Config
            client = boto3.client('comprehend', config=Config(connect_timeout=3, read_timeout=10,
                retries={'mode': 'standard', 'total_max_attempts': 3}))
        self.client, self.language = client, language

    def detect(self, text):
        validate_text(text)
        if not text:
            return []
        result = self.client.detect_pii_entities(Text=text, LanguageCode=self.language)
        if 'Entities' not in result:
            raise ValueError('Invalid Comprehend response')
        findings = []
        for entity in result['Entities']:
            start, end = entity['BeginOffset'], entity['EndOffset']
            score = entity['Score']
            if not 0 <= start < end <= len(text) or not 0 <= score <= 1:
                raise ValueError('Invalid Comprehend entity boundaries or confidence')
            # Redact every returned entity, including low-confidence detections.
            findings.append(Finding(entity['Type'], start, end, score))
        return findings

def validate_text(text):
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_TEXT_BYTES:
        raise ValueError('Text must be a string of at most 100000 UTF-8 bytes')

def mask_pii(text, findings):
    validate_text(text)
    spans = []
    for finding in sorted(findings, key=lambda f: (f.start, f.end)):
        if not 0 <= finding.start < finding.end <= len(text):
            raise ValueError('Invalid PII span')
        if spans and finding.start <= spans[-1][1]:
            spans[-1][1] = max(spans[-1][1], finding.end)
        else:
            spans.append([finding.start, finding.end])
    output, cursor = [], 0
    for start, end in spans:
        output.extend([text[cursor:start], '[REDACTED]'])
        cursor = end
    return ''.join(output) + text[cursor:]
