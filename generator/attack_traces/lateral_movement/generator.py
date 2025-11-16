"""
Lateral Movement scenario generator.
Multi-account AssumeRole chain attack.
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
    generate_arn,
)


def generate_lateral_movement_scenario(
    output_dir: Path,
    account_id: str = "123456789012",
    region: str = "us-east-1",
    duration_hours: float = 1.5,  # 90 minutes
    add_noise: bool = True
) -> Dict[str, Any]:
    """
    Generate lateral movement attack scenario with cross-account role chaining.

    Args:
        output_dir: Directory to write telemetry
        account_id: Primary AWS account ID (production)
        region: AWS region
        duration_hours: Scenario duration in hours
        add_noise: Whether to add benign background events

    Returns:
        Metadata about the generated scenario
    """
    synthesizer = TelemetrySynthesizer(account_id=account_id, region=region)

    # Account setup
    dev_account_id = "111111111111"
    staging_account_id = "222222222222"
    prod_account_id = account_id  # 123456789012

    # Attack configuration
    attacker_ip = generate_ip_address(private=False)
    attacker_user_agent = generate_user_agent(malicious=True)

    # Principals in the attack chain
    dev_user = f"arn:aws:iam::{dev_account_id}:user/developer-jenkins"
    staging_role = f"arn:aws:iam::{staging_account_id}:role/CrossAccountDeployRole"
    prod_role = f"arn:aws:iam::{prod_account_id}:role/ProductionAccessRole"
    high_priv_prod_role = f"arn:aws:iam::{prod_account_id}:role/DataAdminRole"
    backdoor_role = f"arn:aws:iam::{prod_account_id}:role/LegacyBackupRole"

    # Session IDs for different stages
    dev_session = generate_session_id()
    staging_session = generate_session_id()
    prod_session = generate_session_id()
    elevated_session = generate_session_id()

    # Time setup
    start_time, end_time = get_scenario_timeframe(duration_hours=duration_hours, days_ago=1)

    events: List[Dict[str, Any]] = []

    # Stage 1: Initial Reconnaissance in Dev Account (T+0 to T+10 minutes)
    recon_timestamps = generate_time_sequence(
        start_time, 0.11, 12, jitter_seconds=20  # ~10 minutes
    )

    # IAM enumeration in dev account
    dev_recon_actions = [
        "ListRoles",
        "ListUsers",
        "GetUser",
        "ListAttachedUserPolicies",
        "GetUserPolicy",
        "ListRolePolicies",
        "GetRolePolicy",
    ]

    for i, action in enumerate(dev_recon_actions):
        if i >= len(recon_timestamps):
            break
        events.append(
            synthesizer.create_iam_event(
                action=action,
                principal=dev_user,
                timestamp=recon_timestamps[i],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=dev_session,
                metadata={
                    "attack_stage": "reconnaissance",
                    "account": dev_account_id,
                },
            )
        )

    # Discover cross-account roles
    events.append(
        synthesizer.create_iam_event(
            action="GetRole",
            principal=dev_user,
            timestamp=recon_timestamps[7],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            resource=staging_role,
            resource_type="role",
            status="success",
            session_id=dev_session,
            request_parameters={
                "roleName": "CrossAccountDeployRole"
            },
            response_elements={
                "role": {
                    "arn": staging_role,
                    "assumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{dev_account_id}:root"},
                            "Action": "sts:AssumeRole"
                        }]
                    }
                }
            },
            metadata={
                "attack_stage": "reconnaissance",
                "discovery": "cross_account_trust_found"
            },
        )
    )

    # Stage 2: First Lateral Movement - Dev to Staging (T+15 to T+25 minutes)
    lateral1_timestamps = generate_time_sequence(
        start_time, 0.25, 10, jitter_seconds=30  # ~22 minutes in
    )

    # AssumeRole to staging account
    events.append(
        synthesizer.create_sts_event(
            action="AssumeRole",
            principal=dev_user,
            timestamp=lateral1_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            assumed_role=staging_role,
            status="success",
            session_id=staging_session,
            request_parameters={
                "roleArn": staging_role,
                "roleSessionName": "jenkins-deploy-session",
                "durationSeconds": 3600
            },
            metadata={
                "attack_stage": "lateral_movement",
                "hop": "dev_to_staging",
                "suspicious": "cross_account_assume_role"
            },
        )
    )

    # Enumerate in staging account
    staging_actions = [
        "ListRoles",
        "GetRole",
        "ListAttachedRolePolicies",
        "GetRolePolicy",
    ]

    for i, action in enumerate(staging_actions):
        if i + 1 >= len(lateral1_timestamps):
            break
        events.append(
            synthesizer.create_iam_event(
                action=action,
                principal=staging_role,
                timestamp=lateral1_timestamps[i + 1],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=staging_session,
                metadata={
                    "attack_stage": "lateral_movement",
                    "account": staging_account_id,
                },
            )
        )

    # Discover production role from staging
    events.append(
        synthesizer.create_iam_event(
            action="GetRole",
            principal=staging_role,
            timestamp=lateral1_timestamps[5],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            resource=prod_role,
            resource_type="role",
            status="success",
            session_id=staging_session,
            request_parameters={
                "roleName": "ProductionAccessRole"
            },
            response_elements={
                "role": {
                    "arn": prod_role,
                    "assumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{staging_account_id}:root"},
                            "Action": "sts:AssumeRole"
                        }]
                    }
                }
            },
            metadata={
                "attack_stage": "lateral_movement",
                "discovery": "production_access_path_found"
            },
        )
    )

    # Stage 3: Second Lateral Movement - Staging to Production (T+30 to T+40 minutes)
    lateral2_timestamps = generate_time_sequence(
        start_time, 0.5, 12, jitter_seconds=30  # ~45 minutes in
    )

    # AssumeRole to production account
    events.append(
        synthesizer.create_sts_event(
            action="AssumeRole",
            principal=staging_role,
            timestamp=lateral2_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            assumed_role=prod_role,
            status="success",
            session_id=prod_session,
            request_parameters={
                "roleArn": prod_role,
                "roleSessionName": "staging-to-prod-deploy",
                "durationSeconds": 3600
            },
            metadata={
                "attack_stage": "lateral_movement",
                "hop": "staging_to_production",
                "suspicious": "cross_account_production_access",
                "critical": True
            },
        )
    )

    # Enumerate production environment
    prod_recon_actions = [
        "ListRoles",
        "ListUsers",
        "GetAccountSummary",
        "ListBuckets",
    ]

    for i, action in enumerate(prod_recon_actions):
        if i + 1 >= len(lateral2_timestamps):
            break
        events.append(
            synthesizer.create_iam_event(
                action=action,
                principal=prod_role,
                timestamp=lateral2_timestamps[i + 1],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=prod_session,
                metadata={
                    "attack_stage": "reconnaissance",
                    "account": prod_account_id,
                    "environment": "production"
                },
            )
        )

    # Discover high-privilege data admin role
    events.append(
        synthesizer.create_iam_event(
            action="GetRole",
            principal=prod_role,
            timestamp=lateral2_timestamps[6],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            resource=high_priv_prod_role,
            resource_type="role",
            status="success",
            session_id=prod_session,
            request_parameters={
                "roleName": "DataAdminRole"
            },
            metadata={
                "attack_stage": "privilege_escalation",
                "discovery": "high_privilege_role_found"
            },
        )
    )

    # AssumeRole to high-privilege production role
    events.append(
        synthesizer.create_sts_event(
            action="AssumeRole",
            principal=prod_role,
            timestamp=lateral2_timestamps[7],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            assumed_role=high_priv_prod_role,
            status="success",
            session_id=elevated_session,
            request_parameters={
                "roleArn": high_priv_prod_role,
                "roleSessionName": "data-admin-session",
                "durationSeconds": 3600
            },
            metadata={
                "attack_stage": "privilege_escalation",
                "hop": "escalation_in_production",
                "critical": True
            },
        )
    )

    # Stage 4: Persistence - Modify Trust Policy (T+50 to T+60 minutes)
    persistence_timestamps = generate_time_sequence(
        start_time, 0.67, 10, jitter_seconds=30  # ~60 minutes in
    )

    # Update trust policy to add backdoor
    events.append(
        synthesizer.create_iam_event(
            action="UpdateAssumeRolePolicy",
            principal=high_priv_prod_role,
            timestamp=persistence_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            resource=backdoor_role,
            resource_type="role",
            status="success",
            session_id=elevated_session,
            request_parameters={
                "roleName": "LegacyBackupRole",
                "policyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{prod_account_id}:root"},
                            "Action": "sts:AssumeRole"
                        },
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{dev_account_id}:user/developer-jenkins"},
                            "Action": "sts:AssumeRole"
                        }
                    ]
                }
            },
            metadata={
                "attack_stage": "persistence",
                "technique": "trust_policy_modification",
                "suspicious": "external_account_added_to_trust"
            },
        )
    )

    # Attach admin policy to backdoor role
    events.append(
        synthesizer.create_iam_event(
            action="PutRolePolicy",
            principal=high_priv_prod_role,
            timestamp=persistence_timestamps[1],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            resource=backdoor_role,
            resource_type="role",
            status="success",
            session_id=elevated_session,
            request_parameters={
                "roleName": "LegacyBackupRole",
                "policyName": "BackupAdminPolicy",
                "policyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["s3:*", "rds:*", "secretsmanager:*"],
                        "Resource": "*"
                    }]
                }
            },
            metadata={
                "attack_stage": "persistence",
                "overly_permissive": True
            },
        )
    )

    # Stage 5: Data Access and Exfiltration (T+60 to T+90 minutes)
    impact_timestamps = generate_time_sequence(
        start_time, 0.75, 20, jitter_seconds=40  # ~75 minutes in
    )

    # Access production S3 buckets
    sensitive_buckets = [
        "prod-customer-data",
        "prod-financial-records",
        "prod-analytics-exports",
        "prod-backup-archives"
    ]

    for i, bucket in enumerate(sensitive_buckets):
        if i >= len(impact_timestamps):
            break

        # List objects
        events.append(
            synthesizer.create_s3_event(
                action="ListObjects",
                principal=high_priv_prod_role,
                bucket=bucket,
                key="",  # Empty key for ListObjects operation
                timestamp=impact_timestamps[i * 2],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=elevated_session,
                metadata={
                    "attack_stage": "impact",
                    "data_access": True
                },
            )
        )

        # Download data
        events.append(
            synthesizer.create_s3_event(
                action="GetObject",
                principal=high_priv_prod_role,
                bucket=bucket,
                key=f"sensitive/data_{i+1}.parquet",
                timestamp=impact_timestamps[i * 2 + 1],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=elevated_session,
                metadata={
                    "attack_stage": "impact",
                    "data_exfiltration": True,
                    "critical": True
                },
            )
        )

    # Access RDS databases
    events.append(
        synthesizer.create_database_event(
            action="DescribeDBInstances",
            principal=high_priv_prod_role,
            database_name="production-db",
            timestamp=impact_timestamps[10],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=elevated_session,
            metadata={
                "attack_stage": "impact",
                "database": "production"
            },
        )
    )

    events.append(
        synthesizer.create_database_event(
            action="DescribeDBSnapshots",
            principal=high_priv_prod_role,
            database_name="production-db",
            timestamp=impact_timestamps[11],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=elevated_session,
            metadata={
                "attack_stage": "impact",
                "suspicious": "database_snapshot_enumeration"
            },
        )
    )

    # Access Secrets Manager
    events.append(
        synthesizer.create_secrets_manager_event(
            action="ListSecrets",
            principal=high_priv_prod_role,
            secret_name="*",  # Wildcard for list operation
            timestamp=impact_timestamps[12],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=elevated_session,
            metadata={
                "attack_stage": "impact"
            },
        )
    )

    secret_names = ["prod/db/master", "prod/api/keys", "prod/encryption/kms"]
    for i, secret in enumerate(secret_names):
        if 13 + i >= len(impact_timestamps):
            break
        events.append(
            synthesizer.create_secrets_manager_event(
                action="GetSecretValue",
                principal=high_priv_prod_role,
                secret_name=secret,
                timestamp=impact_timestamps[13 + i],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=elevated_session,
                metadata={
                    "attack_stage": "impact",
                    "credential_theft": True,
                    "critical": True
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
        "scenario_name": "lateral_movement",
        "description": "Multi-account lateral movement via AssumeRole chains",
        "duration_hours": duration_hours,
        "num_events": len(events),
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "attacker_ip": attacker_ip,
        "compromised_principal": dev_user,
        "attack_path": [
            f"Dev Account ({dev_account_id})",
            f"Staging Account ({staging_account_id})",
            f"Production Account ({prod_account_id})",
            "Elevated Production Access"
        ],
        "compromised_roles": [
            staging_role,
            prod_role,
            high_priv_prod_role
        ],
        "backdoor_created": backdoor_role,
        "attack_stages": [
            "reconnaissance",
            "lateral_movement",
            "privilege_escalation",
            "persistence",
            "impact"
        ],
        "mitre_techniques": [
            "T1021",       # Remote Services
            "T1550.001",   # Use Alternate Authentication Material
            "T1098",       # Account Manipulation
            "T1580",       # Cloud Infrastructure Discovery
            "T1087.004",   # Account Discovery: Cloud Account
            "T1530",       # Data from Cloud Storage Object
        ],
    }

    return metadata


if __name__ == "__main__":
    # Example usage
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)

    metadata = generate_lateral_movement_scenario(
        output_dir=output_dir,
        duration_hours=1.5,
        add_noise=True
    )

    print(f"Generated {metadata['num_events']} events")
    print(f"Output: {output_dir / 'telemetry.jsonl'}")
