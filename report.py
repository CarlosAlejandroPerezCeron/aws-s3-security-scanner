from __future__ import annotations

import csv
import json

from rich.console import Console
from rich.table import Table

from scanner.base import S3Finding

SEVERITY_COLOR = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}


def print_terminal(findings: list[S3Finding]) -> None:
    console = Console()
    if not findings:
        console.print("[bold green]✓ No findings — all buckets passed[/bold green]")
        return
    table = Table(title="aws-s3-security-scanner", show_lines=True)
    table.add_column("Rule", style="bold")
    table.add_column("Severity")
    table.add_column("Bucket")
    table.add_column("Title")
    for f in findings:
        color = SEVERITY_COLOR.get(f.severity, "white")
        table.add_row(f.rule_id, f"[{color}]{f.severity}[/{color}]", f.bucket, f.title)
    console.print(table)


def print_json(findings: list[S3Finding]) -> None:
    data = [{"rule_id": f.rule_id, "severity": f.severity, "bucket": f.bucket,
             "title": f.title, "detail": f.detail, "remediation": f.remediation}
            for f in findings]
    print(json.dumps(data, indent=2))


def write_csv(findings: list[S3Finding], path: str) -> None:
    fieldnames = ["rule_id", "severity", "bucket", "title", "detail", "remediation"]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for f in findings:
            writer.writerow({"rule_id": f.rule_id, "severity": f.severity, "bucket": f.bucket,
                             "title": f.title, "detail": f.detail, "remediation": f.remediation})
