# aws-s3-security-scanner

Scan AWS S3 buckets for security misconfigurations: public access exposure, missing encryption, disabled versioning, absent logging, and wildcard bucket policies.

![CI](https://github.com/CarlosAlejandroPerezCeron/aws-s3-security-scanner/actions/workflows/ci.yml/badge.svg)

## Rules

| ID | Severity | Trigger |
|----|----------|---------|
| S3-001 | CRITICAL | Public Access Block setting disabled (any of 4) |
| S3-002 | HIGH | Default server-side encryption not configured |
| S3-003 | HIGH | Object versioning not enabled |
| S3-004 | MEDIUM | Server access logging disabled |
| S3-005 | HIGH | Bucket policy grants access to Principal: * |

## Install

```bash
pip install boto3 rich
```

## Usage

```bash
python main.py
python main.py --buckets my-bucket prod-data --min-severity HIGH
python main.py --output json | jq .
python main.py --csv-path findings.csv --fail-on-critical
python main.py --profile prod --region eu-west-1
```

## Dev

```bash
pip install pytest pytest-cov ruff
ruff check .
pytest tests/ -v --cov=scanner --cov=report
```

## Project structure

```
aws-s3-security-scanner/
├── scanner/
│   ├── __init__.py
│   ├── base.py        # dataclasses, severity map, public block keys
│   ├── collector.py   # boto3 S3 API — lists buckets and fetches configs
│   └── rules.py       # 5 detection rules + run_all()
├── tests/
│   └── test_scanner.py  # 21 unit tests, no AWS mocking required
├── report.py          # rich terminal table, JSON, CSV output
├── main.py            # CLI entrypoint
└── .github/workflows/ci.yml
```
