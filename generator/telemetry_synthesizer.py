"""
Core telemetry synthesizer for generating realistic cloud events.
"""
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from generator.utils.time_utils import generate_timestamp, get_scenario_timeframe
from generator.utils.id_utils import (
    generate_event_id,
    generate_session_id,
    generate_ip_address,
    generate_user_agent,
)


class TelemetrySynthesizer:
    """Generates synthetic cloud telemetry events."""

    def __init__(
        self,
        account_id: str = "123456789012",
        region: str = "us-east-1",
        topology_path: Optional[Path] = None
    ):
        """
        Initialize the synthesizer.

        Args:
            account_id: Cloud account ID
            region: Cloud region
            topology_path: Path to topology JSON file
        """
        self.account_id = account_id
        self.region = region
        self.topology = self._load_topology(topology_path) if topology_path else None

    def _load_topology(self, topology_path: Path) -> Dict[str, Any]:
        """Load cloud topology configuration."""
        with open(topology_path, 'r') as f:
            return json.load(f)

    def create_base_event(
        self,
        event_type: str,
        event_source: str,
        timestamp: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a base telemetry event with common fields.

        Args:
            event_type: Type of event
            event_source: Source service
            timestamp: ISO 8601 timestamp
            **kwargs: Additional event fields

        Returns:
            Event dictionary
        """
        event = {
            "event_id": generate_event_id(),
            "timestamp": timestamp,
            "event_type": event_type,
            "event_source": event_source,
            "account_id": self.account_id,
            "region": self.region,
        }

        # Merge additional fields
        event.update(kwargs)

        return event

    def create_iam_event(
        self,
        action: str,
        principal: str,
        timestamp: str,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource: Optional[str] = None,
        status: str = "success",
        **kwargs
    ) -> Dict[str, Any]:
        """Create an IAM-related event."""
        event = self.create_base_event(
            event_type=f"iam.{action.lower().replace(':', '_')}",
            event_source="iam",
            timestamp=timestamp,
            principal=principal,
            principal_type=kwargs.get("principal_type", "user"),
            source_ip=source_ip or generate_ip_address(),
            user_agent=user_agent or generate_user_agent(),
            action=action,
            status=status,
        )

        if resource:
            event["resource"] = resource
            event["resource_type"] = kwargs.get("resource_type", "role")

        if "request_parameters" in kwargs:
            event["request_parameters"] = kwargs["request_parameters"]
        if "response_elements" in kwargs:
            event["response_elements"] = kwargs["response_elements"]

        event["metadata"] = kwargs.get("metadata", {})
        event["session_id"] = kwargs.get("session_id", generate_session_id())

        return event

    def create_s3_event(
        self,
        action: str,
        principal: str,
        bucket: str,
        key: str,
        timestamp: str,
        source_ip: Optional[str] = None,
        status: str = "success",
        **kwargs
    ) -> Dict[str, Any]:
        """Create an S3-related event."""
        event = self.create_base_event(
            event_type=f"s3.{action.lower()}",
            event_source="s3",
            timestamp=timestamp,
            principal=principal,
            principal_type=kwargs.get("principal_type", "user"),
            source_ip=source_ip or generate_ip_address(),
            user_agent=kwargs.get("user_agent", generate_user_agent()),
            action=action,
            resource=f"arn:aws:s3:::{bucket}/{key}",
            resource_type="object",
            status=status,
        )

        event["request_parameters"] = {
            "bucketName": bucket,
            "key": key,
        }
        event["metadata"] = kwargs.get("metadata", {})
        event["session_id"] = kwargs.get("session_id", generate_session_id())

        return event

    def create_lambda_event(
        self,
        action: str,
        principal: str,
        function_name: str,
        timestamp: str,
        source_ip: Optional[str] = None,
        status: str = "success",
        **kwargs
    ) -> Dict[str, Any]:
        """Create a Lambda-related event."""
        function_arn = f"arn:aws:lambda:{self.region}:{self.account_id}:function:{function_name}"

        event = self.create_base_event(
            event_type=f"lambda.{action.lower().replace(':', '_')}",
            event_source="lambda",
            timestamp=timestamp,
            principal=principal,
            principal_type=kwargs.get("principal_type", "user"),
            source_ip=source_ip or generate_ip_address(),
            user_agent=kwargs.get("user_agent", generate_user_agent()),
            action=action,
            resource=function_arn,
            resource_type="function",
            status=status,
        )

        event["request_parameters"] = kwargs.get("request_parameters", {"functionName": function_name})
        event["response_elements"] = kwargs.get("response_elements", {})
        event["metadata"] = kwargs.get("metadata", {})
        event["session_id"] = kwargs.get("session_id", generate_session_id())

        return event

    def create_api_gateway_event(
        self,
        method: str,
        path: str,
        timestamp: str,
        source_ip: Optional[str] = None,
        status_code: int = 200,
        **kwargs
    ) -> Dict[str, Any]:
        """Create an API Gateway access log event."""
        event = self.create_base_event(
            event_type="api.request",
            event_source="api_gateway",
            timestamp=timestamp,
            source_ip=source_ip or generate_ip_address(),
            user_agent=kwargs.get("user_agent", generate_user_agent()),
            action=method,
            status="success" if 200 <= status_code < 300 else "failure",
        )

        event["metadata"] = {
            "method": method,
            "path": path,
            "status_code": status_code,
            "request_id": kwargs.get("request_id", generate_event_id()),
            "api_id": kwargs.get("api_id", "api-" + generate_event_id()[:10]),
        }

        if "principal" in kwargs:
            event["principal"] = kwargs["principal"]
            event["principal_type"] = kwargs.get("principal_type", "user")

        event["session_id"] = kwargs.get("session_id", generate_session_id())

        return event

    def create_network_flow_event(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        timestamp: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Create a VPC flow log event."""
        event = self.create_base_event(
            event_type="network.flow",
            event_source="vpc",
            timestamp=timestamp,
            source_ip=src_ip,
            action="ACCEPT" if kwargs.get("accepted", True) else "REJECT",
            status="success",
        )

        event["metadata"] = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "bytes": kwargs.get("bytes", random.randint(100, 10000)),
            "packets": kwargs.get("packets", random.randint(1, 100)),
            "vpc_id": kwargs.get("vpc_id", "vpc-" + generate_event_id()[:10]),
            "interface_id": kwargs.get("interface_id", "eni-" + generate_event_id()[:10]),
        }

        return event

    def create_container_event(
        self,
        action: str,
        container_id: str,
        timestamp: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Create a container/ECS event."""
        event = self.create_base_event(
            event_type=f"container.{action.lower()}",
            event_source="ecs",
            timestamp=timestamp,
            action=action,
            status=kwargs.get("status", "success"),
        )

        event["metadata"] = {
            "container_id": container_id,
            "image": kwargs.get("image", "nginx:latest"),
            "cluster": kwargs.get("cluster", "default-cluster"),
            "task_arn": kwargs.get("task_arn", f"arn:aws:ecs:{self.region}:{self.account_id}:task/default-cluster/{generate_event_id()}"),
        }

        if "principal" in kwargs:
            event["principal"] = kwargs["principal"]
            event["principal_type"] = kwargs.get("principal_type", "role")

        return event

    def create_sts_event(
        self,
        action: str,
        principal: str,
        timestamp: str,
        assumed_role: Optional[str] = None,
        source_ip: Optional[str] = None,
        status: str = "success",
        **kwargs
    ) -> Dict[str, Any]:
        """Create an STS (Security Token Service) event."""
        event = self.create_base_event(
            event_type=f"sts.{action.lower().replace(':', '_')}",
            event_source="sts",
            timestamp=timestamp,
            principal=principal,
            principal_type=kwargs.get("principal_type", "user"),
            source_ip=source_ip or generate_ip_address(),
            user_agent=kwargs.get("user_agent", generate_user_agent()),
            action=action,
            status=status,
        )

        if assumed_role:
            event["assumed_role"] = assumed_role
            event["resource"] = assumed_role
            event["resource_type"] = "role"

        event["request_parameters"] = kwargs.get("request_parameters", {})
        event["response_elements"] = kwargs.get("response_elements", {})
        event["metadata"] = kwargs.get("metadata", {})
        event["session_id"] = kwargs.get("session_id", generate_session_id())

        return event

    def create_database_event(
        self,
        action: str,
        principal: str,
        database_name: str,
        timestamp: str,
        database_type: str = "rds",
        source_ip: Optional[str] = None,
        status: str = "success",
        **kwargs
    ) -> Dict[str, Any]:
        """Create a database event (RDS, DynamoDB, etc.)."""
        event = self.create_base_event(
            event_type=f"{database_type}.{action.lower().replace(':', '_')}",
            event_source=database_type,
            timestamp=timestamp,
            principal=principal,
            principal_type=kwargs.get("principal_type", "user"),
            source_ip=source_ip or generate_ip_address(),
            user_agent=kwargs.get("user_agent", generate_user_agent()),
            action=action,
            status=status,
        )

        event["resource"] = f"arn:aws:{database_type}:{self.region}:{self.account_id}:db:{database_name}"
        event["resource_type"] = "database"
        event["metadata"] = kwargs.get("metadata", {})
        event["metadata"]["database_name"] = database_name
        event["metadata"]["database_type"] = database_type
        event["request_parameters"] = kwargs.get("request_parameters", {})
        event["response_elements"] = kwargs.get("response_elements", {})
        event["session_id"] = kwargs.get("session_id", generate_session_id())

        return event

    def create_kms_event(
        self,
        action: str,
        principal: str,
        key_id: str,
        timestamp: str,
        source_ip: Optional[str] = None,
        status: str = "success",
        **kwargs
    ) -> Dict[str, Any]:
        """Create a KMS (Key Management Service) event."""
        event = self.create_base_event(
            event_type=f"kms.{action.lower().replace(':', '_')}",
            event_source="kms",
            timestamp=timestamp,
            principal=principal,
            principal_type=kwargs.get("principal_type", "user"),
            source_ip=source_ip or generate_ip_address(),
            user_agent=kwargs.get("user_agent", generate_user_agent()),
            action=action,
            status=status,
        )

        event["resource"] = f"arn:aws:kms:{self.region}:{self.account_id}:key/{key_id}"
        event["resource_type"] = "key"
        event["metadata"] = kwargs.get("metadata", {})
        event["request_parameters"] = kwargs.get("request_parameters", {})
        event["response_elements"] = kwargs.get("response_elements", {})
        event["session_id"] = kwargs.get("session_id", generate_session_id())

        return event

    def create_cloudtrail_event(
        self,
        action: str,
        principal: str,
        trail_name: str,
        timestamp: str,
        source_ip: Optional[str] = None,
        status: str = "success",
        **kwargs
    ) -> Dict[str, Any]:
        """Create a CloudTrail management event."""
        event = self.create_base_event(
            event_type=f"cloudtrail.{action.lower().replace(':', '_')}",
            event_source="cloudtrail",
            timestamp=timestamp,
            principal=principal,
            principal_type=kwargs.get("principal_type", "user"),
            source_ip=source_ip or generate_ip_address(),
            user_agent=kwargs.get("user_agent", generate_user_agent()),
            action=action,
            status=status,
        )

        event["resource"] = f"arn:aws:cloudtrail:{self.region}:{self.account_id}:trail/{trail_name}"
        event["resource_type"] = "trail"
        event["metadata"] = kwargs.get("metadata", {})
        event["request_parameters"] = kwargs.get("request_parameters", {})
        event["response_elements"] = kwargs.get("response_elements", {})
        event["session_id"] = kwargs.get("session_id", generate_session_id())

        return event

    def create_secrets_manager_event(
        self,
        action: str,
        principal: str,
        secret_name: str,
        timestamp: str,
        source_ip: Optional[str] = None,
        status: str = "success",
        **kwargs
    ) -> Dict[str, Any]:
        """Create a Secrets Manager event."""
        event = self.create_base_event(
            event_type=f"secretsmanager.{action.lower().replace(':', '_')}",
            event_source="secretsmanager",
            timestamp=timestamp,
            principal=principal,
            principal_type=kwargs.get("principal_type", "user"),
            source_ip=source_ip or generate_ip_address(),
            user_agent=kwargs.get("user_agent", generate_user_agent()),
            action=action,
            status=status,
        )

        event["resource"] = f"arn:aws:secretsmanager:{self.region}:{self.account_id}:secret:{secret_name}"
        event["resource_type"] = "secret"
        event["metadata"] = kwargs.get("metadata", {})
        event["request_parameters"] = kwargs.get("request_parameters", {})
        event["response_elements"] = kwargs.get("response_elements", {})
        event["session_id"] = kwargs.get("session_id", generate_session_id())

        return event

    def create_ecr_event(
        self,
        action: str,
        principal: str,
        repository_name: str,
        timestamp: str,
        source_ip: Optional[str] = None,
        status: str = "success",
        **kwargs
    ) -> Dict[str, Any]:
        """Create an ECR (Elastic Container Registry) event."""
        event = self.create_base_event(
            event_type=f"ecr.{action.lower().replace(':', '_')}",
            event_source="ecr",
            timestamp=timestamp,
            principal=principal,
            principal_type=kwargs.get("principal_type", "user"),
            source_ip=source_ip or generate_ip_address(),
            user_agent=kwargs.get("user_agent", generate_user_agent()),
            action=action,
            status=status,
        )

        event["resource"] = f"arn:aws:ecr:{self.region}:{self.account_id}:repository/{repository_name}"
        event["resource_type"] = "repository"
        event["metadata"] = kwargs.get("metadata", {})
        event["request_parameters"] = kwargs.get("request_parameters", {})
        event["response_elements"] = kwargs.get("response_elements", {})
        event["session_id"] = kwargs.get("session_id", generate_session_id())

        return event

    def create_codebuild_event(
        self,
        action: str,
        principal: str,
        project_name: str,
        timestamp: str,
        source_ip: Optional[str] = None,
        status: str = "success",
        **kwargs
    ) -> Dict[str, Any]:
        """Create a CodeBuild event."""
        event = self.create_base_event(
            event_type=f"codebuild.{action.lower().replace(':', '_')}",
            event_source="codebuild",
            timestamp=timestamp,
            principal=principal,
            principal_type=kwargs.get("principal_type", "role"),
            source_ip=source_ip or generate_ip_address(),
            user_agent=kwargs.get("user_agent", generate_user_agent()),
            action=action,
            status=status,
        )

        event["resource"] = f"arn:aws:codebuild:{self.region}:{self.account_id}:project/{project_name}"
        event["resource_type"] = "project"
        event["metadata"] = kwargs.get("metadata", {})
        event["request_parameters"] = kwargs.get("request_parameters", {})
        event["response_elements"] = kwargs.get("response_elements", {})
        event["session_id"] = kwargs.get("session_id", generate_session_id())

        return event

    def create_codepipeline_event(
        self,
        action: str,
        principal: str,
        pipeline_name: str,
        timestamp: str,
        source_ip: Optional[str] = None,
        status: str = "success",
        **kwargs
    ) -> Dict[str, Any]:
        """Create a CodePipeline event."""
        event = self.create_base_event(
            event_type=f"codepipeline.{action.lower().replace(':', '_')}",
            event_source="codepipeline",
            timestamp=timestamp,
            principal=principal,
            principal_type=kwargs.get("principal_type", "role"),
            source_ip=source_ip or generate_ip_address(),
            user_agent=kwargs.get("user_agent", generate_user_agent()),
            action=action,
            status=status,
        )

        event["resource"] = f"arn:aws:codepipeline:{self.region}:{self.account_id}:pipeline/{pipeline_name}"
        event["resource_type"] = "pipeline"
        event["metadata"] = kwargs.get("metadata", {})
        event["request_parameters"] = kwargs.get("request_parameters", {})
        event["response_elements"] = kwargs.get("response_elements", {})
        event["session_id"] = kwargs.get("session_id", generate_session_id())

        return event

    def add_benign_noise(
        self,
        events: List[Dict[str, Any]],
        noise_ratio: float = 0.3
    ) -> List[Dict[str, Any]]:
        """
        Add benign background events to make telemetry realistic.

        Args:
            events: List of attack events
            noise_ratio: Ratio of noise events to attack events

        Returns:
            Combined list of events
        """
        num_noise_events = int(len(events) * noise_ratio)

        if not events:
            return events

        # Extract time range from attack events
        timestamps = [e["timestamp"] for e in events]
        start_time = min(timestamps)
        end_time = max(timestamps)

        noise_events = []

        benign_principals = [
            "arn:aws:iam::123456789012:user/legitimate-user",
            "arn:aws:iam::123456789012:role/AutomationRole",
            "arn:aws:iam::123456789012:role/MonitoringRole",
        ]

        for _ in range(num_noise_events):
            # Random timestamp within range
            # Parse start and end times to generate proper random timestamps
            start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
            time_diff = (end_dt - start_dt).total_seconds()
            random_offset = random.uniform(0, time_diff)
            random_dt = start_dt + timedelta(seconds=random_offset)
            timestamp = random_dt.isoformat()

            event_type = random.choice(["iam", "s3", "api", "network"])

            if event_type == "iam":
                noise_events.append(
                    self.create_iam_event(
                        action="GetUser",
                        principal=random.choice(benign_principals),
                        timestamp=timestamp,
                        status="success",
                    )
                )
            elif event_type == "s3":
                noise_events.append(
                    self.create_s3_event(
                        action="GetObject",
                        principal=random.choice(benign_principals),
                        bucket="public-assets-bucket",
                        key="images/logo.png",
                        timestamp=timestamp,
                    )
                )
            elif event_type == "api":
                noise_events.append(
                    self.create_api_gateway_event(
                        method="GET",
                        path="/health",
                        timestamp=timestamp,
                        status_code=200,
                    )
                )
            elif event_type == "network":
                noise_events.append(
                    self.create_network_flow_event(
                        src_ip=generate_ip_address(private=True),
                        dst_ip=generate_ip_address(private=True),
                        src_port=random.randint(10000, 65000),
                        dst_port=443,
                        protocol="TCP",
                        timestamp=timestamp,
                    )
                )

        # Combine and sort by timestamp
        all_events = events + noise_events
        all_events.sort(key=lambda e: e["timestamp"])

        return all_events

    def write_events_jsonl(
        self,
        events: List[Dict[str, Any]],
        output_path: Path
    ) -> None:
        """
        Write events to a JSONL file.

        Args:
            events: List of event dictionaries
            output_path: Path to output file
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + '\n')

    def write_events_json(
        self,
        events: List[Dict[str, Any]],
        output_path: Path
    ) -> None:
        """
        Write events to a JSON file.

        Args:
            events: List of event dictionaries
            output_path: Path to output file
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(events, f, indent=2)
