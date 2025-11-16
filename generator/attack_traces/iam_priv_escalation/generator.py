"""
IAM Privilege Escalation scenario generator.
"""
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

from telemetry_synthesizer import TelemetrySynthesizer
from utils.time_utils import generate_time_sequence, get_scenario_timeframe
from utils.id_utils import (
    generate_ip_address,
    generate_user_agent,
    generate_session_id,
    generate_arn,
    generate_api_key,
)


def generate_iam_privilege_escalation_scenario(
    output_dir: Path,
    account_id: str = "123456789012",
    region: str = "us-east-1",
    duration_hours: float = 1.0,
    add_noise: bool = True
) -> Dict[str, Any]:
    """
    Generate IAM privilege escalation attack scenario.

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
    attacker_ip = generate_ip_address(private=False)  # External IP
    attacker_user_agent = generate_user_agent(malicious=True)
    compromised_principal = f"arn:aws:iam::{account_id}:user/service-account-readonly"
    high_priv_role = f"arn:aws:iam::{account_id}:role/HighPrivilegeRole"
    backdoor_role_name = "BackdoorAdminRole"
    backdoor_role_arn = f"arn:aws:iam::{account_id}:role/{backdoor_role_name}"
    session_id = generate_session_id()

    # Time setup
    start_time, end_time = get_scenario_timeframe(duration_hours=duration_hours, days_ago=1)

    events: List[Dict[str, Any]] = []

    # Stage 1: Reconnaissance (T+0 to T+10 minutes)
    recon_timestamps = generate_time_sequence(
        start_time, 0.17, 15, jitter_seconds=30  # ~10 minutes
    )

    # IAM enumeration
    iam_recon_actions = [
        "ListRoles",
        "ListUsers",
        "ListPolicies",
        "GetUser",
        "ListAttachedUserPolicies",
        "ListUserPolicies",
        "GetUserPolicy",
        "ListRolePolicies",
        "GetRolePolicy",
        "GetPolicy",
        "GetPolicyVersion",
    ]

    for i, action in enumerate(iam_recon_actions):
        if i >= len(recon_timestamps):
            break
        events.append(
            synthesizer.create_iam_event(
                action=action,
                principal=compromised_principal,
                timestamp=recon_timestamps[i],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=session_id,
                metadata={"attack_stage": "reconnaissance"},
            )
        )

    # Stage 2: Identify PassRole vulnerability (T+10 to T+15 minutes)
    vuln_discovery_time = generate_time_sequence(
        start_time, 0.25, 5, jitter_seconds=20  # ~15 minutes in
    )

    # Multiple GetRolePolicy calls to understand permissions
    events.append(
        synthesizer.create_iam_event(
            action="GetRolePolicy",
            principal=compromised_principal,
            timestamp=vuln_discovery_time[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            resource=high_priv_role,
            resource_type="role",
            status="success",
            session_id=session_id,
            request_parameters={
                "roleName": "HighPrivilegeRole",
                "policyName": "HighPrivilegePolicy"
            },
            metadata={"attack_stage": "reconnaissance"},
        )
    )

    # Check own permissions
    events.append(
        synthesizer.create_iam_event(
            action="GetUserPolicy",
            principal=compromised_principal,
            timestamp=vuln_discovery_time[1],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "userName": "service-account-readonly",
                "policyName": "ServiceAccountPolicy"
            },
            metadata={"attack_stage": "reconnaissance"},
        )
    )

    # Stage 3: Privilege Escalation via Lambda + PassRole (T+20 to T+30 minutes)
    escalation_timestamps = generate_time_sequence(
        start_time, 0.42, 8, jitter_seconds=30  # ~25 minutes in
    )

    # Create Lambda function with high-privilege role
    malicious_function_name = "data-processor-temp"

    events.append(
        synthesizer.create_lambda_event(
            action="CreateFunction",
            principal=compromised_principal,
            function_name=malicious_function_name,
            timestamp=escalation_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "functionName": malicious_function_name,
                "role": high_priv_role,  # PassRole exploitation!
                "runtime": "python3.11",
                "handler": "index.handler",
                "code": {"zipFile": "<base64-encoded-payload>"}
            },
            response_elements={
                "functionArn": f"arn:aws:lambda:{region}:{account_id}:function:{malicious_function_name}",
                "role": high_priv_role
            },
            metadata={
                "attack_stage": "privilege_escalation",
                "technique": "PassRole abuse"
            },
        )
    )

    # Invoke the Lambda function (executes with high privileges)
    events.append(
        synthesizer.create_lambda_event(
            action="Invoke",
            principal=compromised_principal,
            function_name=malicious_function_name,
            timestamp=escalation_timestamps[1],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            metadata={
                "attack_stage": "privilege_escalation",
                "invocation_type": "RequestResponse"
            },
        )
    )

    # Stage 4: Persistence - Create backdoor role (T+30 to T+40 minutes)
    persistence_timestamps = generate_time_sequence(
        start_time, 0.58, 10, jitter_seconds=30  # ~35 minutes in
    )

    # Create backdoor IAM role (now using escalated privileges)
    events.append(
        synthesizer.create_iam_event(
            action="CreateRole",
            principal=high_priv_role,  # Lambda execution role
            timestamp=persistence_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            resource=backdoor_role_arn,
            resource_type="role",
            status="success",
            session_id=session_id,
            request_parameters={
                "roleName": backdoor_role_name,
                "assumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "sts:AssumeRole"
                    }]
                }
            },
            response_elements={
                "role": {
                    "arn": backdoor_role_arn,
                    "roleName": backdoor_role_name
                }
            },
            metadata={
                "attack_stage": "persistence",
                "suspicious": "role_created_outside_normal_process"
            },
        )
    )

    # Attach administrative policy to backdoor role
    events.append(
        synthesizer.create_iam_event(
            action="PutRolePolicy",
            principal=high_priv_role,
            timestamp=persistence_timestamps[1],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            resource=backdoor_role_arn,
            resource_type="role",
            status="success",
            session_id=session_id,
            request_parameters={
                "roleName": backdoor_role_name,
                "policyName": "AdminAccess",
                "policyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }]
                }
            },
            metadata={
                "attack_stage": "persistence",
                "policy_type": "inline",
                "overly_permissive": True
            },
        )
    )

    # Create access keys for the backdoor role (via user)
    # First create a user for long-term access
    backdoor_user = "backup-automation-user"
    events.append(
        synthesizer.create_iam_event(
            action="CreateUser",
            principal=high_priv_role,
            timestamp=persistence_timestamps[2],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            resource=f"arn:aws:iam::{account_id}:user/{backdoor_user}",
            resource_type="user",
            status="success",
            session_id=session_id,
            request_parameters={"userName": backdoor_user},
            metadata={"attack_stage": "persistence"},
        )
    )

    # Create access key
    fake_access_key = generate_api_key()
    events.append(
        synthesizer.create_iam_event(
            action="CreateAccessKey",
            principal=high_priv_role,
            timestamp=persistence_timestamps[3],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={"userName": backdoor_user},
            response_elements={
                "accessKey": {
                    "accessKeyId": fake_access_key,
                    "status": "Active",
                    "userName": backdoor_user
                }
            },
            metadata={
                "attack_stage": "persistence",
                "credential_theft": True
            },
        )
    )

    # Attach admin policy to backdoor user
    events.append(
        synthesizer.create_iam_event(
            action="AttachUserPolicy",
            principal=high_priv_role,
            timestamp=persistence_timestamps[4],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            resource=f"arn:aws:iam::{account_id}:user/{backdoor_user}",
            status="success",
            session_id=session_id,
            request_parameters={
                "userName": backdoor_user,
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            metadata={"attack_stage": "persistence"},
        )
    )

    # Stage 5: Impact - Access sensitive data (T+40 to T+50 minutes)
    impact_timestamps = generate_time_sequence(
        start_time, 0.75, 8, jitter_seconds=30  # ~45 minutes in
    )

    # List S3 buckets
    events.append(
        synthesizer.create_iam_event(
            action="ListBuckets",
            principal=backdoor_role_arn,
            timestamp=impact_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=generate_session_id(),  # New session with backdoor
            metadata={"attack_stage": "impact"},
        )
    )

    # Access sensitive S3 data
    sensitive_buckets = ["prod-data-bucket", "customer-data-archive", "financial-records"]
    for i, bucket in enumerate(sensitive_buckets):
        if i + 1 >= len(impact_timestamps):
            break
        events.append(
            synthesizer.create_s3_event(
                action="GetObject",
                principal=backdoor_role_arn,
                bucket=bucket,
                key="sensitive/customer_data.json",
                timestamp=impact_timestamps[i + 1],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=generate_session_id(),
                metadata={
                    "attack_stage": "impact",
                    "data_exfiltration": True
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
        "scenario_name": "iam_priv_escalation",
        "description": "IAM privilege escalation via PassRole and Lambda",
        "duration_hours": duration_hours,
        "num_events": len(events),
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "attacker_ip": attacker_ip,
        "compromised_principal": compromised_principal,
        "created_backdoors": [backdoor_role_arn, f"arn:aws:iam::{account_id}:user/{backdoor_user}"],
        "attack_stages": [
            "reconnaissance",
            "privilege_escalation",
            "persistence",
            "impact"
        ],
        "mitre_techniques": [
            "T1087.004",  # Account Discovery: Cloud Account
            "T1078.004",  # Valid Accounts: Cloud Accounts
            "T1548.005",  # Abuse Elevation Control Mechanism
            "T1136.003",  # Create Account: Cloud Account
            "T1530",      # Data from Cloud Storage Object
        ],
    }

    return metadata


if __name__ == "__main__":
    # Example usage
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)

    metadata = generate_iam_privilege_escalation_scenario(
        output_dir=output_dir,
        duration_hours=1.0,
        add_noise=True
    )

    print(f"Generated {metadata['num_events']} events")
    print(f"Output: {output_dir / 'telemetry.jsonl'}")
