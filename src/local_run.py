"""Run with python -m src.local_run; offline mode sends no text to AWS."""
import json
from .lambda_handler import process_event
from .pii_detector import RegexDetector

if __name__ == '__main__':
    example = {'records': [{'message': 'Synthetic user demo@example.com called +12025550123'},
                           {'message': 'Synthetic card 4111 1111 1111 1111 failed'}]}
    print(json.dumps(process_event(example, RegexDetector()), indent=2))
