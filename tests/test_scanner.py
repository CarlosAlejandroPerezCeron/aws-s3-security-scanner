import json

from scanner.base import BucketInfo, ScanConfig
from scanner.rules import (
    check_encryption,
    check_logging,
    check_policy_public,
    check_public_access_block,
    check_versioning,
    run_all,
)

CFG = ScanConfig()

FULL_BLOCK = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

GOOD_ENC = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}


def _bucket(name="my-bucket", block=None, enc=None, versioning=None, logging=None, policy=None):
    return BucketInfo(
        name=name,
        public_access_block=block if block is not None else FULL_BLOCK.copy(),
        encryption=enc if enc is not None else GOOD_ENC.copy(),
        versioning=versioning if versioning is not None else {"Status": "Enabled"},
        logging=logging if logging is not None else {"TargetBucket": "logs-bucket"},
        policy=policy,
    )


# --- S3-001 Public Access Block ---

def test_full_block_no_finding():
    info = _bucket(block=FULL_BLOCK.copy())
    assert check_public_access_block(info, CFG) == []


def test_missing_block_all_critical():
    info = _bucket(block={})
    findings = check_public_access_block(info, CFG)
    assert any(f.rule_id == "S3-001" and f.severity == "CRITICAL" for f in findings)


def test_partial_block_flagged():
    block = {**FULL_BLOCK, "BlockPublicAcls": False}
    info = _bucket(block=block)
    findings = check_public_access_block(info, CFG)
    assert any(f.rule_id == "S3-001" for f in findings)
    assert "BlockPublicAcls" in findings[0].detail


def test_all_false_block_flagged():
    block = {k: False for k in FULL_BLOCK}
    info = _bucket(block=block)
    findings = check_public_access_block(info, CFG)
    assert len(findings) == 1 and findings[0].rule_id == "S3-001"


# --- S3-002 Encryption ---

def test_encryption_present_clean():
    info = _bucket(enc=GOOD_ENC.copy())
    assert check_encryption(info, CFG) == []


def test_no_encryption_flagged():
    info = _bucket(enc={})
    findings = check_encryption(info, CFG)
    assert any(f.rule_id == "S3-002" and f.severity == "HIGH" for f in findings)


def test_empty_rules_list_flagged():
    info = _bucket(enc={"Rules": []})
    findings = check_encryption(info, CFG)
    assert any(f.rule_id == "S3-002" for f in findings)


# --- S3-003 Versioning ---

def test_versioning_enabled_clean():
    info = _bucket(versioning={"Status": "Enabled"})
    assert check_versioning(info, CFG) == []


def test_versioning_suspended_flagged():
    info = _bucket(versioning={"Status": "Suspended"})
    findings = check_versioning(info, CFG)
    assert any(f.rule_id == "S3-003" and f.severity == "HIGH" for f in findings)


def test_versioning_never_enabled_flagged():
    info = _bucket(versioning={})
    findings = check_versioning(info, CFG)
    assert any(f.rule_id == "S3-003" for f in findings)


# --- S3-004 Logging ---

def test_logging_enabled_clean():
    info = _bucket(logging={"TargetBucket": "logs"})
    assert check_logging(info, CFG) == []


def test_no_logging_flagged():
    info = _bucket(logging={})
    findings = check_logging(info, CFG)
    assert any(f.rule_id == "S3-004" and f.severity == "MEDIUM" for f in findings)


# --- S3-005 Wildcard policy ---

def test_wildcard_principal_star_flagged():
    policy = json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]})
    info = _bucket(policy=policy)
    findings = check_policy_public(info, CFG)
    assert any(f.rule_id == "S3-005" and f.severity == "HIGH" for f in findings)


def test_wildcard_principal_aws_star_flagged():
    policy = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:*"}]})
    info = _bucket(policy=policy)
    findings = check_policy_public(info, CFG)
    assert any(f.rule_id == "S3-005" for f in findings)


def test_specific_principal_clean():
    policy = json.dumps({"Statement": [{"Effect": "Allow",
                                        "Principal": {"AWS": "arn:aws:iam::123:role/MyRole"},
                                        "Action": "s3:GetObject"}]})
    info = _bucket(policy=policy)
    assert check_policy_public(info, CFG) == []


def test_no_policy_clean():
    info = _bucket(policy=None)
    assert check_policy_public(info, CFG) == []


# --- run_all ---

def test_run_all_clean_bucket():
    info = _bucket()
    assert run_all([info], CFG) == []


def test_run_all_severity_order():
    info = _bucket(block={}, enc={}, versioning={}, logging={})
    findings = run_all([info], CFG)
    from scanner.base import SEVERITY_ORDER
    sevs = [f.severity for f in findings]
    assert sevs == sorted(sevs, key=lambda s: SEVERITY_ORDER.get(s, 99))


def test_run_all_multiple_buckets():
    b1 = _bucket(name="b1", block={})
    b2 = _bucket(name="b2", enc={})
    findings = run_all([b1, b2], CFG)
    buckets_found = {f.bucket for f in findings}
    assert "b1" in buckets_found and "b2" in buckets_found


def test_run_all_empty_bucket_list():
    assert run_all([], CFG) == []


def test_run_all_only_critical_when_block_missing():
    info = _bucket(block={})
    findings = run_all([info], CFG)
    critical = [f for f in findings if f.severity == "CRITICAL"]
    assert len(critical) >= 1 and critical[0].rule_id == "S3-001"
