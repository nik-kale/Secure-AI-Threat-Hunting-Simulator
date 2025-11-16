"""
Data Exfiltration scenario generator.
S3 enumeration, data copy to external bucket, CloudTrail deletion.
"""
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

from generator.telemetry_synthesizer import TelemetrySynthesizer
from generator.utils.time_utils import generate_time_sequence, get_scenario_timeframe
from generator.utils.id_utils import (
    generate_ip_address,
    generate_user_agent,
    generate_session_id,
)


def generate_data_exfiltration_scenario(
    output_dir: Path,
    account_id: str = "123456789012",
    region: str = "us-east-1",
    duration_hours: float = 0.67,  # 40 minutes
    add_noise: bool = True
) -> Dict[str, Any]:
    """
    Generate data exfiltration attack scenario via S3.

    Args:
        output_dir: Directory to write telemetry
        account_id: AWS account ID
        region: AWS region
        duration_hours: Scenario duration in hours
        add_noise: Whether to add benign background events

    Returns:
        Metadata about the generated scenario
    """
    synthesizer = TelemetrySynthesizer(account_id=account_id, region=region)

    # Attack configuration
    attacker_ip = generate_ip_address(private=False)
    attacker_user_agent = generate_user_agent(malicious=True)
    compromised_principal = f"arn:aws:iam::{account_id}:user/data-analytics-service"
    attacker_account_id = "999999999999"
    attacker_bucket = f"exfil-staging-{attacker_account_id}"
    session_id = generate_session_id()

    # Time setup
    start_time, end_time = get_scenario_timeframe(duration_hours=duration_hours, days_ago=1)

    events: List[Dict[str, Any]] = []

    # Stage 1: Initial Reconnaissance (T+0 to T+5 minutes)
    recon_timestamps = generate_time_sequence(
        start_time, 0.125, 8, jitter_seconds=15  # ~5 minutes
    )

    # Initial IAM enumeration
    events.append(
        synthesizer.create_iam_event(
            action="GetUser",
            principal=compromised_principal,
            timestamp=recon_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            metadata={"attack_stage": "reconnaissance"},
        )
    )

    events.append(
        synthesizer.create_iam_event(
            action="ListAttachedUserPolicies",
            principal=compromised_principal,
            timestamp=recon_timestamps[1],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            metadata={"attack_stage": "reconnaissance"},
        )
    )

    # Stage 2: S3 Bucket Enumeration (T+5 to T+15 minutes)
    enum_timestamps = generate_time_sequence(
        start_time, 0.2, 15, jitter_seconds=20  # ~12 minutes in
    )

    # List all buckets
    events.append(
        synthesizer.create_s3_event(
            action="ListBuckets",
            principal=compromised_principal,
            timestamp=enum_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            metadata={
                "attack_stage": "discovery",
                "suspicious": "bucket_enumeration"
            },
        )
    )

    # Enumerate sensitive buckets
    sensitive_buckets = [
        "company-customer-data",
        "financial-records-archive",
        "employee-pii-data",
        "product-source-code",
        "security-audit-logs",
        "backup-databases"
    ]

    for i, bucket in enumerate(sensitive_buckets):
        if i + 1 >= len(enum_timestamps):
            break

        # Get bucket location
        events.append(
            synthesizer.create_s3_event(
                action="GetBucketLocation",
                principal=compromised_principal,
                bucket=bucket,
                timestamp=enum_timestamps[i + 1],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=session_id,
                metadata={"attack_stage": "discovery"},
            )
        )

        # Check bucket policy
        if i + 7 < len(enum_timestamps):
            events.append(
                synthesizer.create_s3_event(
                    action="GetBucketPolicy",
                    principal=compromised_principal,
                    bucket=bucket,
                    timestamp=enum_timestamps[i + 7],
                    source_ip=attacker_ip,
                    user_agent=attacker_user_agent,
                    status="success",
                    session_id=session_id,
                    metadata={
                        "attack_stage": "discovery",
                        "suspicious": "policy_enumeration"
                    },
                )
            )

    # Stage 3: Data Collection from S3 (T+15 to T+25 minutes)
    collection_timestamps = generate_time_sequence(
        start_time, 0.45, 20, jitter_seconds=25  # ~27 minutes in
    )

    # List objects in sensitive buckets
    for i, bucket in enumerate(sensitive_buckets[:4]):  # Focus on top 4 buckets
        if i * 3 >= len(collection_timestamps):
            break

        # List objects
        events.append(
            synthesizer.create_s3_event(
                action="ListObjects",
                principal=compromised_principal,
                bucket=bucket,
                timestamp=collection_timestamps[i * 3],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=session_id,
                request_parameters={
                    "bucketName": bucket,
                    "prefix": "",
                    "maxKeys": 1000
                },
                metadata={
                    "attack_stage": "collection",
                    "suspicious": "bulk_enumeration"
                },
            )
        )

        # Download multiple objects
        sensitive_files = [
            f"customers/2024/customer_records.csv",
            f"exports/financial_data.parquet",
            f"sensitive/user_credentials.json"
        ]

        for j, key in enumerate(sensitive_files):
            if i * 3 + j + 1 >= len(collection_timestamps):
                break

            events.append(
                synthesizer.create_s3_event(
                    action="GetObject",
                    principal=compromised_principal,
                    bucket=bucket,
                    key=key,
                    timestamp=collection_timestamps[i * 3 + j + 1],
                    source_ip=attacker_ip,
                    user_agent=attacker_user_agent,
                    status="success",
                    session_id=session_id,
                    request_parameters={
                        "bucketName": bucket,
                        "key": key
                    },
                    response_elements={
                        "x-amz-request-id": generate_session_id()[:16],
                        "contentLength": 1024 * 1024 * (j + 1) * 10  # 10-30 MB files
                    },
                    metadata={
                        "attack_stage": "collection",
                        "data_accessed": True,
                        "file_size_mb": (j + 1) * 10,
                        "suspicious": "sensitive_data_access"
                    },
                )
            )

    # Stage 4: Exfiltration to External Bucket (T+25 to T+35 minutes)
    exfil_timestamps = generate_time_sequence(
        start_time, 0.65, 15, jitter_seconds=30  # ~39 minutes in
    )

    # Check if attacker bucket exists (in attacker's account)
    events.append(
        synthesizer.create_s3_event(
            action="HeadBucket",
            principal=compromised_principal,
            bucket=attacker_bucket,
            timestamp=exfil_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            metadata={
                "attack_stage": "exfiltration",
                "external_bucket": True,
                "suspicious": "cross_account_access"
            },
        )
    )

    # Copy objects to attacker-controlled bucket
    exfil_operations = [
        ("company-customer-data", "customers/2024/customer_records.csv"),
        ("company-customer-data", "exports/financial_data.parquet"),
        ("financial-records-archive", "q4-2024/revenue_data.xlsx"),
        ("employee-pii-data", "hr/employee_ssn.csv"),
        ("product-source-code", "src/authentication/secrets.py"),
    ]

    for i, (source_bucket, key) in enumerate(exfil_operations):
        if i + 1 >= len(exfil_timestamps):
            break

        # Copy object to external bucket
        events.append(
            synthesizer.create_s3_event(
                action="CopyObject",
                principal=compromised_principal,
                bucket=attacker_bucket,  # Destination
                key=f"exfil/{source_bucket}/{key}",
                timestamp=exfil_timestamps[i + 1],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=session_id,
                request_parameters={
                    "destinationBucket": attacker_bucket,
                    "destinationKey": f"exfil/{source_bucket}/{key}",
                    "sourceArn": f"arn:aws:s3:::{source_bucket}/{key}",
                    "sourceBucket": source_bucket,
                    "sourceKey": key
                },
                metadata={
                    "attack_stage": "exfiltration",
                    "cross_account_copy": True,
                    "external_account": attacker_account_id,
                    "critical": True,
                    "data_exfiltration": True
                },
            )
        )

    # Additional PutObject to external bucket (direct upload)
    events.append(
        synthesizer.create_s3_event(
            action="PutObject",
            principal=compromised_principal,
            bucket=attacker_bucket,
            key="exfil/archive/complete_dump.tar.gz",
            timestamp=exfil_timestamps[7],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "bucketName": attacker_bucket,
                "key": "exfil/archive/complete_dump.tar.gz",
                "contentLength": 1024 * 1024 * 500  # 500 MB
            },
            metadata={
                "attack_stage": "exfiltration",
                "external_bucket": True,
                "critical": True,
                "large_upload": True
            },
        )
    )

    # Stage 5: Anti-Forensics - Delete CloudTrail and Logs (T+35 to T+45 minutes)
    cleanup_timestamps = generate_time_sequence(
        start_time, 0.82, 10, jitter_seconds=20  # ~49 minutes in (near end)
    )

    # Attempt to stop CloudTrail logging
    events.append(
        synthesizer.create_cloudtrail_event(
            action="StopLogging",
            principal=compromised_principal,
            trail_name="organization-trail",
            timestamp=cleanup_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            metadata={
                "attack_stage": "defense_evasion",
                "anti_forensics": True,
                "critical": True,
                "suspicious": "cloudtrail_disabled"
            },
        )
    )

    # Delete CloudTrail logs from S3
    cloudtrail_log_bucket = "cloudtrail-logs-bucket"
    log_files = [
        "AWSLogs/123456789012/CloudTrail/us-east-1/2024/11/16/log1.json.gz",
        "AWSLogs/123456789012/CloudTrail/us-east-1/2024/11/16/log2.json.gz",
        "AWSLogs/123456789012/CloudTrail/us-east-1/2024/11/16/log3.json.gz"
    ]

    for i, log_file in enumerate(log_files):
        if i + 1 >= len(cleanup_timestamps):
            break

        events.append(
            synthesizer.create_s3_event(
                action="DeleteObject",
                principal=compromised_principal,
                bucket=cloudtrail_log_bucket,
                key=log_file,
                timestamp=cleanup_timestamps[i + 1],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=session_id,
                metadata={
                    "attack_stage": "defense_evasion",
                    "anti_forensics": True,
                    "critical": True,
                    "log_deletion": True
                },
            )
        )

    # Try to delete S3 access logs
    events.append(
        synthesizer.create_s3_event(
            action="PutBucketLogging",
            principal=compromised_principal,
            bucket="company-customer-data",
            timestamp=cleanup_timestamps[5],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "bucketName": "company-customer-data",
                "loggingEnabled": False
            },
            metadata={
                "attack_stage": "defense_evasion",
                "anti_forensics": True,
                "logging_disabled": True
            },
        )
    )

    # Attempt to delete the CloudTrail trail itself
    events.append(
        synthesizer.create_cloudtrail_event(
            action="DeleteTrail",
            principal=compromised_principal,
            trail_name="organization-trail",
            timestamp=cleanup_timestamps[6],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="failure",  # Likely to fail if protected
            error_code="InsufficientPermissions",
            session_id=session_id,
            metadata={
                "attack_stage": "defense_evasion",
                "anti_forensics": True,
                "critical": True,
                "failed_attempt": True
            },
        )
    )

    # Add benign noise
    if add_noise:
        events = synthesizer.add_benign_noise(events, noise_ratio=0.3)

    # Write telemetry
    output_path = output_dir / "telemetry.jsonl"
    synthesizer.write_events_jsonl(events, output_path)

    # Generate metadata
    metadata = {
        "scenario_name": "data_exfiltration",
        "description": "S3 data exfiltration to external bucket with anti-forensics",
        "duration_hours": duration_hours,
        "num_events": len(events),
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "attacker_ip": attacker_ip,
        "compromised_principal": compromised_principal,
        "exfiltration_target": attacker_bucket,
        "attacker_account": attacker_account_id,
        "targeted_buckets": sensitive_buckets,
        "data_exfiltrated_mb": 650,  # Approximate total
        "attack_stages": [
            "reconnaissance",
            "discovery",
            "collection",
            "exfiltration",
            "defense_evasion"
        ],
        "mitre_techniques": [
            "T1530",       # Data from Cloud Storage Object
            "T1537",       # Transfer Data to Cloud Account
            "T1485",       # Data Destruction
            "T1070.001",   # Indicator Removal: Clear Logs
            "T1580",       # Cloud Infrastructure Discovery
            "T1619",       # Cloud Storage Object Discovery
        ],
    }

    return metadata


if __name__ == "__main__":
    # Example usage
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)

    metadata = generate_data_exfiltration_scenario(
        output_dir=output_dir,
        duration_hours=0.67,
        add_noise=True
    )

    print(f"Generated {metadata['num_events']} events")
    print(f"Output: {output_dir / 'telemetry.jsonl'}")
