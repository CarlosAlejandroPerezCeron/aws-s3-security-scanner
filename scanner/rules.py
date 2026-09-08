from __future__ import annotations

import re

from .base import PUBLIC_BLOCK_KEYS, SEVERITY_ORDER, BucketInfo, S3Finding, ScanConfig

_PUBLIC_PRINCIPAL_RE = re.compile(r'"Principal"\s*:\s*(?:"\*"|\{\s*"AWS"\s*:\s*"\*"\s*\})', re.DOTALL)


def check_public_access_block(info: BucketInfo, config: ScanConfig) -> list[S3Finding]:
    """S3-001: One or more Public Access Block settings disabled."""
    findings = []
    block = info.public_access_block
    disabled = [k for k in PUBLIC_BLOCK_KEYS if not block.get(k, False)]
    if disabled:
        findings.append(S3Finding(
            rule_id="S3-001",
            severity="CRITICAL",
            bucket=info.name,
            title=f"Public Access Block incomplete on '{info.name}'",
            detail=f"Settings not enforced: {', '.join(disabled)}.",
            remediation="Enable all four S3 Block Public Access settings at the bucket and account level.",
        ))
    return findings


def check_encryption(info: BucketInfo, config: ScanConfig) -> list[S3Finding]:
    """S3-002: Default server-side encryption not configured."""
    findings = []
    rules = info.encryption.get("Rules", [])
    if not rules:
        findings.append(S3Finding(
            rule_id="S3-002",
            severity="HIGH",
            bucket=info.name,
            title=f"No default encryption on '{info.name}'",
            detail="Bucket has no SSE configuration — objects stored without encryption by default.",
            remediation="Enable SSE-S3 (AES-256) or SSE-KMS as the default encryption for the bucket.",
        ))
    return findings


def check_versioning(info: BucketInfo, config: ScanConfig) -> list[S3Finding]:
    """S3-003: Versioning not enabled — objects cannot be recovered after deletion."""
    findings = []
    status = info.versioning.get("Status", "")
    if status != "Enabled":
        findings.append(S3Finding(
            rule_id="S3-003",
            severity="HIGH",
            bucket=info.name,
            title=f"Versioning disabled on '{info.name}'",
            detail=f"Versioning status is '{status or 'Suspended/Never enabled'}'. Accidental deletions are unrecoverable.",
            remediation="Enable S3 Versioning and optionally configure a lifecycle rule to expire old versions.",
        ))
    return findings


def check_logging(info: BucketInfo, config: ScanConfig) -> list[S3Finding]:
    """S3-004: Server access logging disabled — no audit trail for bucket requests."""
    findings = []
    if not info.logging:
        findings.append(S3Finding(
            rule_id="S3-004",
            severity="MEDIUM",
            bucket=info.name,
            title=f"Access logging disabled on '{info.name}'",
            detail="No TargetBucket configured. S3 access requests are not logged.",
            remediation="Enable S3 server access logging to a separate audit bucket. Retain logs for 90+ days.",
        ))
    return findings


def check_policy_public(info: BucketInfo, config: ScanConfig) -> list[S3Finding]:
    """S3-005: Bucket policy allows unauthenticated public access via wildcard Principal."""
    findings = []
    if info.policy and _PUBLIC_PRINCIPAL_RE.search(info.policy):
        findings.append(S3Finding(
            rule_id="S3-005",
            severity="HIGH",
            bucket=info.name,
            title=f"Bucket policy grants public access on '{info.name}'",
            detail="Policy contains Principal: '*' or Principal: {AWS: '*'} — anyone can access the bucket.",
            remediation="Restrict bucket policy to specific IAM principals. Use resource-based conditions to limit access.",
        ))
    return findings


ALL_RULES = [
    check_public_access_block,
    check_encryption,
    check_versioning,
    check_logging,
    check_policy_public,
]


def run_all(buckets: list[BucketInfo], config: ScanConfig | None = None) -> list[S3Finding]:
    if config is None:
        config = ScanConfig()
    results: list[S3Finding] = []
    for info in buckets:
        for rule in ALL_RULES:
            results.extend(rule(info, config))
    return sorted(results, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
