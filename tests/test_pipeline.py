import base64
from dataclasses import asdict
import gzip
import json
import os
import unittest
from unittest.mock import Mock, patch
from botocore.stub import Stubber
import boto3
from src.pii_detector import Finding, RegexDetector, ComprehendDetector, mask_pii
from src.lambda_handler import process_event, lambda_handler

class PipelineTests(unittest.TestCase):
    def test_output_does_not_contain_original_values(self):
        result=process_event({'records':[{'message':'Email synthetic@example.com phone +12025550123'}]},RegexDetector())
        serialized=json.dumps(result)
        self.assertNotIn('synthetic@example.com',serialized)
        self.assertNotIn('12025550123',serialized)
        self.assertNotIn('original',serialized)
        self.assertGreater(result['pii_found'],0)

    def test_overlapping_and_adjacent_spans(self):
        self.assertEqual(mask_pii('abcdefghij',[Finding('A',1,5),Finding('B',3,7),Finding('C',7,9)]),'a[REDACTED]j')

    def test_invalid_spans_fail(self):
        with self.assertRaises(ValueError): mask_pii('abc',[Finding('A',0,9)])

    def test_unicode_comprehend_offsets(self):
        client=Mock()
        text='Hi 👋 user@example.com'
        start=text.index('user')
        client.detect_pii_entities.return_value={'Entities':[{'Type':'EMAIL','BeginOffset':start,'EndOffset':len(text),'Score':0.4}]}
        findings=ComprehendDetector(client).detect(text)
        self.assertEqual(mask_pii(text,findings),'Hi 👋 [REDACTED]')
        self.assertNotIn('value',asdict(findings[0]))

    def test_real_sdk_contract(self):
        client=boto3.client('comprehend',region_name='us-east-1',aws_access_key_id='testing',aws_secret_access_key='testing')
        with Stubber(client) as stub:
            stub.add_response('detect_pii_entities',{'Entities':[{'Type':'EMAIL','BeginOffset':0,'EndOffset':5,'Score':0.9}]},{'Text':'a@b.c','LanguageCode':'en'})
            self.assertEqual(mask_pii('a@b.c',ComprehendDetector(client).detect('a@b.c')),'[REDACTED]')
            stub.assert_no_pending_responses()

    def test_cloudwatch_event(self):
        payload={'messageType':'DATA_MESSAGE','logEvents':[{'id':'1','message':'Email demo@example.com'}]}
        event={'awslogs':{'data':base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()}}
        self.assertNotIn('demo@example.com',json.dumps(process_event(event,RegexDetector())))

    def test_cloudwatch_control_message(self):
        payload={'messageType':'CONTROL_MESSAGE'}
        event={'awslogs':{'data':base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()}}
        self.assertEqual(process_event(event,RegexDetector())['sanitized_records'],[])

    def test_detection_failure_emits_no_partial_output(self):
        detector=Mock()
        detector.detect.side_effect=RuntimeError('sensitive upstream data')
        with self.assertRaisesRegex(RuntimeError,'no unsanitized output') as caught:
            process_event({'records':[{'message':'private'}]},detector)
        self.assertNotIn('sensitive upstream data',str(caught.exception))

    def test_missing_entities_is_not_treated_as_safe(self):
        client=Mock()
        client.detect_pii_entities.return_value={}
        with self.assertRaises(ValueError): ComprehendDetector(client).detect('private')

    def test_utf8_byte_limit(self):
        with self.assertRaises(ValueError): RegexDetector().detect('👋'*25001)

    def test_malformed_event_error_is_sanitized(self):
        with self.assertRaises(RuntimeError) as caught:
            process_event({'records':[{'message':{'secret':'private-value'}}]},RegexDetector())
        self.assertNotIn('private-value',str(caught.exception))

    def test_regex_backend_blocked_in_production(self):
        with patch.dict(os.environ,{'PII_BACKEND':'regex','ENVIRONMENT':'production'}):
            with self.assertRaises(RuntimeError): lambda_handler({'records':[]})

    def test_s3_sink_only_writes_sanitized_payload(self):
        client=Mock()
        with patch.dict(os.environ,{'PII_BACKEND':'regex','ENVIRONMENT':'development','SANITIZED_BUCKET':'sanitized-demo'}), patch('boto3.client',return_value=client):
            result=lambda_handler({'records':[{'message':'demo@example.com'}]})
        self.assertEqual(result['records_written'],1)
        kwargs=client.put_object.call_args.kwargs
        self.assertNotIn(b'demo@example.com',kwargs['Body'])
        self.assertEqual(kwargs['ServerSideEncryption'],'AES256')
