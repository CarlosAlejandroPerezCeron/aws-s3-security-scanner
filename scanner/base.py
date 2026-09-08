from dataclasses import dataclass, field

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

PUBLIC_BLOCK_KEYS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


@dataclass
class S3Finding:
    rule_id: str
    severity: str
    bucket: str
    title: str
    detail: str
    remediation: str


@dataclass
class ScanConfig:
    profile: str | None = None
    region: str = "us-east-1"
    buckets: list[str] = field(default_factory=list)
    min_severity: str = "LOW"


@dataclass
class BucketInfo:
    name: str
    public_access_block: dict = field(default_factory=dict)
    encryption: dict = field(default_factory=dict)
    versioning: dict = field(default_factory=dict)
    logging: dict = field(default_factory=dict)
    policy: str | None = None
