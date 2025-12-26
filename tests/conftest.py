"""
Shared pytest fixtures for all tests.
"""
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any
import pytest
import tempfile

from generator.telemetry_synthesizer import TelemetrySynthesizer
from generator.utils.time_utils import generate_timestamp


@pytest.fixture
def sample_account_id():
    """Sample AWS account ID."""
    return "123456789012"


@pytest.fixture
def sample_region():
    """Sample AWS region."""
    return "us-east-1"


@pytest.fixture
def telemetry_synthesizer(sample_account_id, sample_region):
    """Create a telemetry synthesizer instance."""
    return TelemetrySynthesizer(
        account_id=sample_account_id,
        region=sample_region
    )


@pytest.fixture
def sample_iam_events(telemetry_synthesizer) -> List[Dict[str, Any]]:
    """Sample IAM privilege escalation events."""
    base_time = datetime.utcnow()
    events = []
    
    principal = "arn:aws:iam::123456789012:user/attacker"
    session_id = "sess-attack-12345"
    
    # Initial reconnaissance
    events.append(
        telemetry_synthesizer.create_iam_event(
            action="ListRoles",
            principal=principal,
            timestamp=(base_time).isoformat() + "Z",
            session_id=session_id,
            metadata={"attack_stage": "reconnaissance"}
        )
    )
    
    events.append(
        telemetry_synthesizer.create_iam_event(
            action="GetRole",
            principal=principal,
            timestamp=(base_time + timedelta(minutes=1)).isoformat() + "Z",
            session_id=session_id,
            resource="arn:aws:iam::123456789012:role/AdminRole",
            metadata={"attack_stage": "reconnaissance"}
        )
    )
    
    # Privilege escalation
    events.append(
        telemetry_synthesizer.create_iam_event(
            action="AttachUserPolicy",
            principal=principal,
            timestamp=(base_time + timedelta(minutes=5)).isoformat() + "Z",
            session_id=session_id,
            resource="arn:aws:iam::aws:policy/AdministratorAccess",
            metadata={"attack_stage": "privilege_escalation", "critical": True}
        )
    )
    
    return events


@pytest.fixture
def sample_s3_events(telemetry_synthesizer) -> List[Dict[str, Any]]:
    """Sample S3 data access events."""
    base_time = datetime.utcnow()
    events = []
    
    principal = "arn:aws:iam::123456789012:user/data-service"
    session_id = "sess-data-67890"
    
    # Bucket enumeration
    events.append(
        telemetry_synthesizer.create_s3_event(
            action="ListBuckets",
            principal=principal,
            bucket="",
            key="",
            timestamp=(base_time).isoformat() + "Z",
            session_id=session_id,
            metadata={"discovery": True}
        )
    )
    
    # Data access
    events.append(
        telemetry_synthesizer.create_s3_event(
            action="GetObject",
            principal=principal,
            bucket="sensitive-data-bucket",
            key="customer/pii_data.csv",
            timestamp=(base_time + timedelta(minutes=2)).isoformat() + "Z",
            session_id=session_id,
            metadata={"sensitive": True}
        )
    )
    
    # Data exfiltration
    events.append(
        telemetry_synthesizer.create_s3_event(
            action="CopyObject",
            principal=principal,
            bucket="external-attacker-bucket",
            key="exfil/pii_data.csv",
            timestamp=(base_time + timedelta(minutes=5)).isoformat() + "Z",
            session_id=session_id,
            metadata={"exfiltration": True, "critical": True}
        )
    )
    
    return events


@pytest.fixture
def sample_network_flows(telemetry_synthesizer) -> List[Dict[str, Any]]:
    """Sample network flow logs."""
    base_time = datetime.utcnow()
    events = []
    
    # Internal to external unusual connection
    events.append(
        telemetry_synthesizer.create_network_flow_event(
            src_ip="10.0.1.45",
            dst_ip="203.0.113.50",  # External IP
            src_port=45123,
            dst_port=443,
            protocol="TCP",
            timestamp=(base_time).isoformat() + "Z",
            bytes=1048576,  # 1 MB
            packets=1024
        )
    )
    
    # Port scanning behavior
    for port in [22, 80, 443, 3389, 8080]:
        events.append(
            telemetry_synthesizer.create_network_flow_event(
                src_ip="10.0.1.45",
                dst_ip="10.0.2.100",
                src_port=50000 + port,
                dst_port=port,
                protocol="TCP",
                timestamp=(base_time + timedelta(seconds=port)).isoformat() + "Z",
                bytes=64,
                packets=1,
                accepted=False
            )
        )
    
    return events


@pytest.fixture
def sample_lambda_events(telemetry_synthesizer) -> List[Dict[str, Any]]:
    """Sample Lambda function events."""
    base_time = datetime.utcnow()
    events = []
    
    principal = "arn:aws:iam::123456789012:role/LambdaExecutionRole"
    
    events.append(
        telemetry_synthesizer.create_lambda_event(
            action="CreateFunction",
            principal=principal,
            function_name="suspicious-function",
            timestamp=(base_time).isoformat() + "Z",
            metadata={"suspicious": True}
        )
    )
    
    events.append(
        telemetry_synthesizer.create_lambda_event(
            action="UpdateFunctionCode",
            principal=principal,
            function_name="production-api-handler",
            timestamp=(base_time + timedelta(minutes=1)).isoformat() + "Z",
            metadata={"production": True}
        )
    )
    
    return events


@pytest.fixture
def sample_mixed_events(
    sample_iam_events,
    sample_s3_events,
    sample_network_flows,
    sample_lambda_events
) -> List[Dict[str, Any]]:
    """Combined sample events from multiple sources."""
    all_events = (
        sample_iam_events +
        sample_s3_events +
        sample_network_flows +
        sample_lambda_events
    )
    
    # Sort by timestamp
    all_events.sort(key=lambda e: e["timestamp"])
    
    return all_events


@pytest.fixture
def temp_telemetry_file(sample_mixed_events) -> Path:
    """Create a temporary JSONL file with sample telemetry."""
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.jsonl',
        delete=False
    ) as f:
        for event in sample_mixed_events:
            f.write(json.dumps(event) + '\n')
        temp_path = Path(f.name)
    
    yield temp_path
    
    # Cleanup
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_output_dir():
    """Create a temporary output directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_mitre_mapping():
    """Sample MITRE ATT&CK technique mapping."""
    return {
        "T1078": {
            "name": "Valid Accounts",
            "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]
        },
        "T1098": {
            "name": "Account Manipulation",
            "tactics": ["Persistence", "Privilege Escalation"]
        },
        "T1530": {
            "name": "Data from Cloud Storage Object",
            "tactics": ["Collection"]
        },
        "T1537": {
            "name": "Transfer Data to Cloud Account",
            "tactics": ["Exfiltration"]
        }
    }


@pytest.fixture
def sample_correlation_result():
    """Sample correlation analysis result."""
    return {
        "session_id": "sess-attack-12345",
        "principal": "arn:aws:iam::123456789012:user/attacker",
        "time_range": {
            "start": "2024-01-01T00:00:00Z",
            "end": "2024-01-01T01:00:00Z"
        },
        "event_count": 15,
        "suspicious_patterns": [
            {
                "pattern": "rapid_permission_changes",
                "confidence": 0.85,
                "description": "Multiple IAM policy modifications in short time"
            },
            {
                "pattern": "cross_account_access",
                "confidence": 0.92,
                "description": "STS AssumeRole to external account"
            }
        ],
        "attack_stages": ["reconnaissance", "privilege_escalation", "lateral_movement"],
        "mitre_techniques": ["T1078", "T1098", "T1550.001"]
    }


@pytest.fixture
def sample_detection_rule():
    """Sample Sigma detection rule."""
    return {
        "title": "AWS IAM Administrator Policy Attached to User",
        "id": "test-rule-001",
        "status": "experimental",
        "description": "Detects when AdministratorAccess policy is attached to a user",
        "logsource": {
            "product": "aws",
            "service": "cloudtrail"
        },
        "detection": {
            "selection": {
                "event_source": "iam",
                "action": "AttachUserPolicy",
                "request_parameters|contains": "AdministratorAccess"
            },
            "condition": "selection"
        },
        "falsepositives": ["Legitimate administrative actions"],
        "level": "high"
    }

