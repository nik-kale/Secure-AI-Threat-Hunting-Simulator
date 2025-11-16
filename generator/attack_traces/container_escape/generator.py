"""
Container escape/breakout scenario generator.
"""
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

sys.path.append(str(Path(__file__).parent.parent.parent))

from telemetry_synthesizer import TelemetrySynthesizer
from utils.time_utils import generate_time_sequence, get_scenario_timeframe
from utils.id_utils import (
    generate_ip_address,
    generate_user_agent,
    generate_session_id,
    generate_instance_id,
)


def generate_container_escape_scenario(
    output_dir: Path,
    account_id: str = "123456789012",
    region: str = "us-east-1",
    duration_hours: float = 0.67,  # ~40 minutes
    add_noise: bool = True
) -> Dict[str, Any]:
    """Generate container escape attack scenario."""
    synthesizer = TelemetrySynthesizer(account_id=account_id, region=region)

    # Attack configuration
    attacker_ip = generate_ip_address(private=False)
    container_ip = generate_ip_address(private=True, subnet="10.0.10")
    host_instance_id = generate_instance_id()
    container_id = "cont-" + generate_instance_id()[:12]
    host_role = f"arn:aws:iam::{account_id}:role/EC2InstanceRole"
    session_id = generate_session_id()

    start_time, end_time = get_scenario_timeframe(duration_hours=duration_hours, days_ago=1)

    events: List[Dict[str, Any]] = []

    # Stage 1: Initial access via web exploit (T+0)
    initial_timestamps = generate_time_sequence(start_time, 0.08, 5, jitter_seconds=10)

    # Suspicious web requests
    for i in range(3):
        events.append(
            synthesizer.create_api_gateway_event(
                method="POST",
                path="/api/upload",
                timestamp=initial_timestamps[i],
                source_ip=attacker_ip,
                status_code=500 if i < 2 else 200,  # Failed attempts then success
                user_agent="python-requests/2.28.1",
                metadata={
                    "attack_stage": "initial_access",
                    "exploit_attempt": True
                }
            )
        )

    # Container execution event
    events.append(
        synthesizer.create_container_event(
            action="exec",
            container_id=container_id,
            timestamp=initial_timestamps[3],
            status="success",
            image="web-app:latest",
            principal=host_role,
            metadata={
                "attack_stage": "initial_access",
                "command": "/bin/bash",
                "suspicious": "unexpected_exec"
            }
        )
    )

    # Stage 2: Container escape attempts (T+5 to T+10 minutes)
    escape_timestamps = generate_time_sequence(
        start_time, 0.17, 10, jitter_seconds=20
    )

    # Reconnaissance within container
    recon_commands = [
        "cat /proc/self/cgroup",
        "ls -la /dev",
        "mount | grep docker",
        "cat /etc/passwd",
        "ps aux"
    ]

    for i, cmd in enumerate(recon_commands):
        if i >= len(escape_timestamps):
            break
        events.append(
            synthesizer.create_container_event(
                action="exec",
                container_id=container_id,
                timestamp=escape_timestamps[i],
                image="web-app:latest",
                principal=host_role,
                metadata={
                    "attack_stage": "container_escape",
                    "command": cmd,
                    "suspicious": "recon_command"
                }
            )
        )

    # Container breakout - mount host filesystem
    events.append(
        synthesizer.create_container_event(
            action="exec",
            container_id=container_id,
            timestamp=escape_timestamps[5],
            image="web-app:latest",
            principal=host_role,
            metadata={
                "attack_stage": "container_escape",
                "command": "mount /dev/xvda1 /mnt/host",
                "suspicious": "host_filesystem_mount",
                "privileged": True
            }
        )
    )

    # Access host filesystem
    events.append(
        synthesizer.create_container_event(
            action="exec",
            container_id=container_id,
            timestamp=escape_timestamps[6],
            image="web-app:latest",
            principal=host_role,
            metadata={
                "attack_stage": "container_escape",
                "command": "chroot /mnt/host /bin/bash",
                "suspicious": "container_breakout",
                "severity": "critical"
            }
        )
    )

    # Stage 3: Credential access via metadata service (T+10 to T+15 minutes)
    cred_timestamps = generate_time_sequence(
        start_time, 0.33, 8, jitter_seconds=15
    )

    # Query metadata service
    metadata_paths = [
        "/latest/meta-data/",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/meta-data/iam/security-credentials/EC2InstanceRole",
    ]

    for i, path in enumerate(metadata_paths):
        events.append(
            synthesizer.create_api_gateway_event(
                method="GET",
                path=path,
                timestamp=cred_timestamps[i],
                source_ip=container_ip,  # From container IP
                status_code=200,
                user_agent="curl/7.68.0",
                metadata={
                    "attack_stage": "credential_access",
                    "metadata_service": True,
                    "suspicious": "metadata_access_from_container"
                }
            )
        )

    # Use stolen credentials for IAM reconnaissance
    events.append(
        synthesizer.create_iam_event(
            action="GetCallerIdentity",
            principal=host_role,
            timestamp=cred_timestamps[3],
            source_ip=container_ip,
            user_agent="Boto3/1.26.137 Python/3.9.16",
            status="success",
            session_id=generate_session_id(),
            metadata={
                "attack_stage": "credential_access",
                "stolen_credentials": True
            }
        )
    )

    # Stage 4: Lateral movement (T+20 to T+25 minutes)
    lateral_timestamps = generate_time_sequence(
        start_time, 0.58, 10, jitter_seconds=20
    )

    # Enumerate other containers
    events.append(
        synthesizer.create_container_event(
            action="list",
            container_id="host-daemon",
            timestamp=lateral_timestamps[0],
            principal=host_role,
            metadata={
                "attack_stage": "lateral_movement",
                "docker_api_call": "containers/json"
            }
        )
    )

    # EC2 instance enumeration
    events.append(
        synthesizer.create_iam_event(
            action="DescribeInstances",
            principal=host_role,
            timestamp=lateral_timestamps[1],
            source_ip=container_ip,
            user_agent="Boto3/1.26.137 Python/3.9.16",
            status="success",
            session_id=generate_session_id(),
            metadata={"attack_stage": "lateral_movement"}
        )
    )

    # Network scanning
    for i in range(3):
        events.append(
            synthesizer.create_network_flow_event(
                src_ip=container_ip,
                dst_ip=generate_ip_address(private=True, subnet="10.0.10"),
                src_port=45000 + i,
                dst_port=22,  # SSH scanning
                protocol="TCP",
                timestamp=lateral_timestamps[i + 2],
                accepted=False,  # Blocked by security groups
                metadata={
                    "attack_stage": "lateral_movement",
                    "port_scan": True
                }
            )
        )

    # Stage 5: Impact - cryptominer deployment (T+25 to T+40 minutes)
    impact_timestamps = generate_time_sequence(
        start_time, 0.75, 8, jitter_seconds=30
    )

    # Download cryptominer
    events.append(
        synthesizer.create_network_flow_event(
            src_ip=container_ip,
            dst_ip=generate_ip_address(private=False),  # External miner source
            src_port=51234,
            dst_port=443,
            protocol="TCP",
            timestamp=impact_timestamps[0],
            bytes=1024000,  # Large download
            metadata={
                "attack_stage": "impact",
                "cryptominer_download": True,
                "external_connection": True
            }
        )
    )

    # Execute cryptominer
    events.append(
        synthesizer.create_container_event(
            action="exec",
            container_id=container_id,
            timestamp=impact_timestamps[1],
            image="web-app:latest",
            principal=host_role,
            metadata={
                "attack_stage": "impact",
                "command": "./xmrig --donate-level 1 -o pool.minexmr.com:4444",
                "cryptominer": True,
                "severity": "critical"
            }
        )
    )

    # High CPU usage events
    for i in range(3):
        events.append(
            synthesizer.create_container_event(
                action="stats",
                container_id=container_id,
                timestamp=impact_timestamps[i + 2],
                image="web-app:latest",
                metadata={
                    "attack_stage": "impact",
                    "cpu_usage_percent": 95.0 + i,
                    "anomalous": "high_cpu"
                }
            )
        )

    # Connection to mining pool
    events.append(
        synthesizer.create_network_flow_event(
            src_ip=container_ip,
            dst_ip=generate_ip_address(private=False),
            src_port=52341,
            dst_port=4444,  # Common mining port
            protocol="TCP",
            timestamp=impact_timestamps[5],
            bytes=50000,
            packets=1000,
            metadata={
                "attack_stage": "impact",
                "mining_pool_connection": True,
                "destination": "pool.minexmr.com"
            }
        )
    )

    if add_noise:
        events = synthesizer.add_benign_noise(events, noise_ratio=0.3)

    # Write telemetry
    output_path = output_dir / "telemetry.jsonl"
    synthesizer.write_events_jsonl(events, output_path)

    metadata = {
        "scenario_name": "container_escape",
        "description": "Container breakout with cryptominer deployment",
        "duration_hours": duration_hours,
        "num_events": len(events),
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "attacker_ip": attacker_ip,
        "compromised_container": container_id,
        "attack_stages": [
            "initial_access",
            "container_escape",
            "credential_access",
            "lateral_movement",
            "impact"
        ],
        "mitre_techniques": [
            "T1190",  # Exploit Public-Facing Application
            "T1611",  # Escape to Host
            "T1552.005",  # Cloud Instance Metadata API
            "T1021",  # Remote Services
            "T1496",  # Resource Hijacking
        ],
    }

    return metadata


if __name__ == "__main__":
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)

    metadata = generate_container_escape_scenario(
        output_dir=output_dir,
        add_noise=True
    )

    print(f"Generated {metadata['num_events']} events")
    print(f"Output: {output_dir / 'telemetry.jsonl'}")
