"""
ID and identifier utilities for telemetry generation.
"""
import uuid
import random
import string
from typing import Optional


def generate_event_id() -> str:
    """Generate a unique event ID (UUID4)."""
    return str(uuid.uuid4())


def generate_session_id() -> str:
    """Generate a session identifier."""
    return f"sess-{uuid.uuid4().hex[:16]}"


def generate_request_id() -> str:
    """Generate a request identifier (similar to AWS request IDs)."""
    return f"req-{uuid.uuid4().hex[:24]}"


def generate_ip_address(private: bool = False, subnet: Optional[str] = None) -> str:
    """
    Generate a synthetic IP address.

    Args:
        private: If True, generate RFC 1918 private IP
        subnet: Optional subnet prefix (e.g., "10.0")

    Returns:
        IP address string
    """
    if subnet:
        parts = subnet.split('.')
        remaining = 4 - len(parts)
        for _ in range(remaining):
            parts.append(str(random.randint(0, 255)))
        return '.'.join(parts[:4])

    if private:
        # Generate RFC 1918 private IP
        first_octet = random.choice([10, 172, 192])
        if first_octet == 10:
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        elif first_octet == 172:
            return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:  # 192
            return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        # Generate public IP (avoiding reserved ranges - this is synthetic)
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_user_agent(malicious: bool = False) -> str:
    """
    Generate a user agent string.

    Args:
        malicious: If True, generate suspicious user agent

    Returns:
        User agent string
    """
    if malicious:
        suspicious_agents = [
            "python-requests/2.28.1",
            "aws-cli/1.18.69 Python/3.6.9 Linux/4.15.0",
            "Boto3/1.26.137 Python/3.9.16 Linux/5.10.0",
            "curl/7.68.0",
            "Go-http-client/1.1",
            "custom-scanner/1.0",
        ]
        return random.choice(suspicious_agents)
    else:
        legitimate_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "aws-sdk-java/1.12.261 Linux/5.10.0 OpenJDK_64-Bit_Server_VM/25.312-b07",
            "aws-cli/2.13.0 Python/3.11.4 Darwin/22.5.0 source/x86_64",
            "Boto3/1.28.25 Python/3.11.4 Linux/5.15.0 Botocore/1.31.25",
        ]
        return random.choice(legitimate_agents)


def generate_account_id() -> str:
    """Generate a synthetic 12-digit AWS-style account ID."""
    return ''.join([str(random.randint(0, 9)) for _ in range(12)])


def generate_arn(
    service: str,
    resource_type: str,
    resource_id: str,
    account_id: str = "123456789012",
    region: str = "us-east-1"
) -> str:
    """
    Generate an AWS ARN.

    Args:
        service: AWS service (e.g., "iam", "s3", "ec2")
        resource_type: Resource type (e.g., "role", "bucket", "instance")
        resource_id: Resource identifier
        account_id: AWS account ID
        region: AWS region

    Returns:
        ARN string
    """
    if service == "s3":
        # S3 ARNs don't include region or account
        return f"arn:aws:s3:::{resource_id}"
    elif service == "iam":
        # IAM ARNs don't include region
        return f"arn:aws:iam::{account_id}:{resource_type}/{resource_id}"
    else:
        return f"arn:aws:{service}:{region}:{account_id}:{resource_type}/{resource_id}"


def generate_instance_id() -> str:
    """Generate an EC2-style instance ID."""
    return f"i-{uuid.uuid4().hex[:17]}"


def generate_vpc_id() -> str:
    """Generate a VPC ID."""
    return f"vpc-{uuid.uuid4().hex[:17]}"


def generate_api_key() -> str:
    """Generate a synthetic API key."""
    return f"AKIA{''.join(random.choices(string.ascii_uppercase + string.digits, k=16))}"


def generate_access_token() -> str:
    """Generate a synthetic access token."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=40))
