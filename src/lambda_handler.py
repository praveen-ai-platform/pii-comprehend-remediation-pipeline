"""CloudWatch/direct-record ingestion; only sanitized content may leave the handler."""
import base64
from dataclasses import asdict
from datetime import datetime, timezone
import gzip
import io
import json
import os
import uuid
from pydantic import BaseModel, ConfigDict, Field
from .pii_detector import ComprehendDetector, RegexDetector, mask_pii

class Record(BaseModel):
    model_config = ConfigDict(extra='ignore', str_strip_whitespace=False)
    message: str = Field(max_length=100000)

class Batch(BaseModel):
    model_config = ConfigDict(extra='forbid')
    records: list[Record] = Field(max_length=1000)

def records_from_event(event):
    if 'awslogs' not in event:
        return Batch.model_validate(event).records
    encoded = event['awslogs']['data']
    if len(encoded) > 2_000_000:
        raise ValueError('CloudWatch payload exceeds limit')
    raw = base64.b64decode(encoded, validate=True)
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        decoded = stream.read(4_000_001)
    if len(decoded) > 4_000_000:
        raise ValueError('Decompressed CloudWatch payload exceeds limit')
    payload = json.loads(decoded)
    if payload.get('messageType') == 'CONTROL_MESSAGE':
        return []
    if payload.get('messageType') != 'DATA_MESSAGE':
        raise ValueError('Unknown CloudWatch message type')
    return Batch.model_validate({'records': [{'message': r['message']} for r in payload['logEvents']]}).records

def process_event(event, detector):
    try:
        records = records_from_event(event)
        sanitized, count = [], 0
        for record in records:
            findings = detector.detect(record.message)
            count += len(findings)
            sanitized.append({'sanitized': mask_pii(record.message, findings),
                              'pii_findings': [asdict(f) for f in findings]})
        return {'status': 'ok', 'pii_found': count, 'sanitized_records': sanitized}
    except Exception:
        # Neither validation errors nor upstream errors may expose original input.
        raise RuntimeError('PII processing failed; no unsanitized output was emitted') from None

def lambda_handler(event, context=None):
    backend = os.getenv('PII_BACKEND', 'comprehend')
    if backend not in {'comprehend', 'regex'}:
        raise RuntimeError('Unknown PII_BACKEND')
    if backend == 'regex' and os.getenv('ENVIRONMENT', 'production') == 'production':
        raise RuntimeError('Regex backend is restricted to local development')
    detector = RegexDetector() if backend == 'regex' else ComprehendDetector(language=os.getenv('PII_LANGUAGE', 'en'))
    result = process_event(event, detector)
    bucket = os.getenv('SANITIZED_BUCKET')
    if bucket and result['sanitized_records']:
        import boto3
        key = f"sanitized/{datetime.now(timezone.utc):%Y/%m/%d}/{uuid.uuid4().hex}.json"
        boto3.client('s3').put_object(Bucket=bucket, Key=key, Body=json.dumps(result).encode('utf-8'),
                                    ContentType='application/json', ServerSideEncryption='AES256')
        return {'status': 'ok', 'pii_found': result['pii_found'], 'records_written': len(result['sanitized_records']), 'object_key': key}
    return result
