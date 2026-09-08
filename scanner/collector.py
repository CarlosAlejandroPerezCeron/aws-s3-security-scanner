from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from .base import BucketInfo, ScanConfig


def _safe(client_call, **kwargs):
    try:
        return client_call(**kwargs)
    except ClientError:
        return {}


def collect(config: ScanConfig) -> list[BucketInfo]:
    session = boto3.Session(profile_name=config.profile, region_name=config.region)
    s3 = session.client("s3")

    try:
        resp = s3.list_buckets()
        all_buckets = [b["Name"] for b in resp.get("Buckets", [])]
    except ClientError:
        return []

    target = [b for b in all_buckets if not config.buckets or b in config.buckets]
    results: list[BucketInfo] = []

    for name in target:
        pub = _safe(s3.get_public_access_block, Bucket=name)
        enc = _safe(s3.get_bucket_encryption, Bucket=name)
        ver = _safe(s3.get_bucket_versioning, Bucket=name)
        log = _safe(s3.get_bucket_logging, Bucket=name)
        try:
            pol = s3.get_bucket_policy(Bucket=name)["Policy"]
        except ClientError:
            pol = None

        results.append(BucketInfo(
            name=name,
            public_access_block=pub.get("PublicAccessBlockConfiguration", {}),
            encryption=enc.get("ServerSideEncryptionConfiguration", {}),
            versioning=ver,
            logging=log.get("LoggingEnabled", {}),
            policy=pol,
        ))

    return results
