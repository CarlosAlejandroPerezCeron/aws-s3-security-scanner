from __future__ import annotations

import argparse
import sys

from report import print_json, print_terminal, write_csv
from scanner.base import ScanConfig
from scanner.collector import collect
from scanner.rules import run_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-s3-security-scanner",
        description="Scan S3 buckets for security misconfigurations.",
    )
    p.add_argument("--profile", help="AWS CLI profile name")
    p.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    p.add_argument("--buckets", nargs="+", metavar="BUCKET",
                   help="Specific bucket names to scan (default: all)")
    p.add_argument("--min-severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                   default="LOW", help="Minimum severity to report (default: LOW)")
    p.add_argument("--output", choices=["terminal", "json"], default="terminal")
    p.add_argument("--csv-path", metavar="PATH", help="Also write CSV report to PATH")
    p.add_argument("--fail-on-critical", action="store_true",
                   help="Exit with code 2 if any CRITICAL finding is detected")
    return p


def main() -> None:
    args = build_parser().parse_args()
    config = ScanConfig(
        profile=args.profile,
        region=args.region,
        buckets=args.buckets or [],
        min_severity=args.min_severity,
    )
    buckets = collect(config)
    findings = run_all(buckets, config)

    if args.output == "json":
        print_json(findings)
    else:
        print_terminal(findings)

    if args.csv_path:
        write_csv(findings, args.csv_path)

    if args.fail_on_critical and any(f.severity == "CRITICAL" for f in findings):
        sys.exit(2)


if __name__ == "__main__":
    main()
