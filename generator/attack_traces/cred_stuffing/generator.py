"""
Credential stuffing attack scenario generator.
"""
import sys
import random
from pathlib import Path
from typing import List, Dict, Any

sys.path.append(str(Path(__file__).parent.parent.parent))

from telemetry_synthesizer import TelemetrySynthesizer
from utils.time_utils import generate_time_sequence, get_scenario_timeframe
from utils.id_utils import generate_ip_address, generate_user_agent, generate_session_id


def generate_credential_stuffing_scenario(
    output_dir: Path,
    account_id: str = "123456789012",
    region: str = "us-east-1",
    duration_hours: float = 0.33,  # ~20 minutes
    add_noise: bool = True
) -> Dict[str, Any]:
    """Generate credential stuffing attack scenario."""
    synthesizer = TelemetrySynthesizer(account_id=account_id, region=region)

    # Attack configuration - distributed botnet IPs
    botnet_ips = [generate_ip_address(private=False) for _ in range(15)]
    successful_ip = random.choice(botnet_ips)

    # Fake usernames for stuffing attempts
    fake_usernames = [
        "john.doe@example.com",
        "jane.smith@example.com",
        "admin@example.com",
        "test.user@example.com",
        "developer@example.com",
        "sarah.johnson@example.com",  # This one will succeed
        "mike.wilson@example.com",
        "emily.davis@example.com",
    ]
    successful_username = "sarah.johnson@example.com"

    start_time, end_time = get_scenario_timeframe(duration_hours=duration_hours, days_ago=1)

    events: List[Dict[str, Any]] = []

    # Stage 1: Reconnaissance (T+0 to T+2 minutes)
    recon_timestamps = generate_time_sequence(start_time, 0.1, 5, jitter_seconds=10)

    # Test authentication endpoint
    events.append(
        synthesizer.create_api_gateway_event(
            method="GET",
            path="/api/auth/login",
            timestamp=recon_timestamps[0],
            source_ip=botnet_ips[0],
            status_code=200,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            metadata={"attack_stage": "reconnaissance"}
        )
    )

    # Stage 2: Credential stuffing - high volume (T+2 to T+15 minutes)
    stuffing_timestamps = generate_time_sequence(
        start_time, 0.75, 100, jitter_seconds=5  # High volume!
    )

    # Generate many failed authentication attempts
    for i, timestamp in enumerate(stuffing_timestamps[:85]):  # 85 failures
        username = random.choice(fake_usernames)
        source_ip = random.choice(botnet_ips)

        events.append(
            synthesizer.create_api_gateway_event(
                method="POST",
                path="/api/auth/login",
                timestamp=timestamp,
                source_ip=source_ip,
                status_code=401,  # Unauthorized
                user_agent=generate_user_agent(malicious=True),
                metadata={
                    "attack_stage": "credential_stuffing",
                    "username": username,
                    "authentication": "failed",
                    "reason": "invalid_credentials"
                }
            )
        )

    # Successful authentication (T+15)
    success_timestamp = stuffing_timestamps[85]
    events.append(
        synthesizer.create_api_gateway_event(
            method="POST",
            path="/api/auth/login",
            timestamp=success_timestamp,
            source_ip=successful_ip,
            status_code=200,
            user_agent=generate_user_agent(malicious=True),
            principal=f"arn:aws:iam::{account_id}:user/{successful_username}",
            principal_type="user",
            metadata={
                "attack_stage": "credential_stuffing",
                "username": successful_username,
                "authentication": "success",
                "compromised_account": True
            }
        )
    )

    # Stage 3: Account validation (T+15 to T+18 minutes)
    validation_timestamps = generate_time_sequence(
        start_time, 0.85, 10, jitter_seconds=10
    )

    compromised_principal = f"arn:aws:iam::{account_id}:user/{successful_username}"
    session_id = generate_session_id()

    # Validate access
    events.append(
        synthesizer.create_iam_event(
            action="GetUser",
            principal=compromised_principal,
            timestamp=validation_timestamps[0],
            source_ip=successful_ip,
            user_agent=generate_user_agent(malicious=True),
            status="success",
            session_id=session_id,
            metadata={"attack_stage": "validation"}
        )
    )

    # Enumerate permissions
    enum_actions = ["ListAttachedUserPolicies", "ListUserPolicies", "GetUserPolicy"]
    for i, action in enumerate(enum_actions):
        events.append(
            synthesizer.create_iam_event(
                action=action,
                principal=compromised_principal,
                timestamp=validation_timestamps[i + 1],
                source_ip=successful_ip,
                user_agent=generate_user_agent(malicious=True),
                status="success",
                session_id=session_id,
                metadata={"attack_stage": "validation"}
            )
        )

    # List S3 buckets
    events.append(
        synthesizer.create_iam_event(
            action="ListBuckets",
            principal=compromised_principal,
            timestamp=validation_timestamps[4],
            source_ip=successful_ip,
            user_agent=generate_user_agent(malicious=True),
            status="success",
            session_id=session_id,
            metadata={"attack_stage": "validation"}
        )
    )

    if add_noise:
        events = synthesizer.add_benign_noise(events, noise_ratio=0.15)  # Less noise for this scenario

    # Write telemetry
    output_path = output_dir / "telemetry.jsonl"
    synthesizer.write_events_jsonl(events, output_path)

    metadata = {
        "scenario_name": "cred_stuffing",
        "description": "Credential stuffing attack with distributed botnet",
        "duration_hours": duration_hours,
        "num_events": len(events),
        "num_stuffing_attempts": 86,  # 85 failures + 1 success
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "botnet_ips": botnet_ips,
        "compromised_account": successful_username,
        "attack_stages": [
            "reconnaissance",
            "credential_stuffing",
            "validation"
        ],
        "mitre_techniques": [
            "T1589.001",  # Gather Victim Identity Information
            "T1110.004",  # Brute Force: Credential Stuffing
            "T1087",      # Account Discovery
            "T1078.004",  # Valid Accounts: Cloud Accounts
        ],
    }

    return metadata


if __name__ == "__main__":
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)

    metadata = generate_credential_stuffing_scenario(
        output_dir=output_dir,
        add_noise=True
    )

    print(f"Generated {metadata['num_events']} events")
    print(f"Output: {output_dir / 'telemetry.jsonl'}")
