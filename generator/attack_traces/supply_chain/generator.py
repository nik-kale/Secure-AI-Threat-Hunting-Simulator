"""
Supply Chain Attack scenario generator.
CI/CD compromise, malicious Lambda layer injection, production deployment.
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


def generate_supply_chain_scenario(
    output_dir: Path,
    account_id: str = "123456789012",
    region: str = "us-east-1",
    duration_hours: float = 1.83,  # 110 minutes
    add_noise: bool = True
) -> Dict[str, Any]:
    """
    Generate supply chain attack scenario via CI/CD compromise.

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
    compromised_principal = f"arn:aws:iam::{account_id}:user/cicd-automation-service"
    cicd_role = f"arn:aws:iam::{account_id}:role/CodeBuildServiceRole"
    pipeline_name = "production-api-pipeline"
    build_project_name = "api-service-build"
    malicious_layer_name = "security-utils-layer"
    malicious_layer_version = "v2.1.5"

    session_id = generate_session_id()
    build_session = generate_session_id()

    # Time setup
    start_time, end_time = get_scenario_timeframe(duration_hours=duration_hours, days_ago=1)

    events: List[Dict[str, Any]] = []

    # Stage 1: Initial Reconnaissance of CI/CD (T+0 to T+10 minutes)
    recon_timestamps = generate_time_sequence(
        start_time, 0.09, 12, jitter_seconds=20  # ~10 minutes
    )

    # IAM enumeration
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

    # Enumerate CodePipeline
    events.append(
        synthesizer.create_codepipeline_event(
            action="ListPipelines",
            principal=compromised_principal,
            pipeline_name="*",  # Wildcard for list operation
            timestamp=recon_timestamps[2],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            metadata={
                "attack_stage": "reconnaissance",
                "suspicious": "cicd_enumeration"
            },
        )
    )

    events.append(
        synthesizer.create_codepipeline_event(
            action="GetPipeline",
            principal=compromised_principal,
            pipeline_name=pipeline_name,
            timestamp=recon_timestamps[3],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "name": pipeline_name
            },
            response_elements={
                "pipeline": {
                    "name": pipeline_name,
                    "roleArn": cicd_role,
                    "stages": [
                        {"name": "Source"},
                        {"name": "Build"},
                        {"name": "Deploy"}
                    ]
                }
            },
            metadata={
                "attack_stage": "reconnaissance",
                "discovery": "production_pipeline_found"
            },
        )
    )

    # Enumerate CodeBuild projects
    events.append(
        synthesizer.create_codebuild_event(
            action="ListProjects",
            principal=compromised_principal,
            project_name="*",  # Wildcard for list operation
            timestamp=recon_timestamps[4],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            metadata={"attack_stage": "reconnaissance"},
        )
    )

    events.append(
        synthesizer.create_codebuild_event(
            action="BatchGetProjects",
            principal=compromised_principal,
            project_name=build_project_name,
            timestamp=recon_timestamps[5],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "names": [build_project_name]
            },
            metadata={
                "attack_stage": "reconnaissance",
                "discovery": "build_configuration_accessed"
            },
        )
    )

    # Stage 2: Lambda Infrastructure Discovery (T+10 to T+30 minutes)
    discovery_timestamps = generate_time_sequence(
        start_time, 0.18, 20, jitter_seconds=30  # ~27 minutes in
    )

    # List Lambda functions
    events.append(
        synthesizer.create_lambda_event(
            action="ListFunctions",
            principal=compromised_principal,
            function_name="*",  # Wildcard for list operation
            timestamp=discovery_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            metadata={
                "attack_stage": "discovery",
                "suspicious": "lambda_enumeration"
            },
        )
    )

    # Enumerate production Lambda functions
    prod_functions = [
        "api-authentication-handler",
        "api-data-processor",
        "api-notification-service",
        "api-payment-handler",
        "api-user-service"
    ]

    for i, func_name in enumerate(prod_functions):
        if i + 1 >= len(discovery_timestamps):
            break

        events.append(
            synthesizer.create_lambda_event(
                action="GetFunction",
                principal=compromised_principal,
                function_name=func_name,
                timestamp=discovery_timestamps[i + 1],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=session_id,
                response_elements={
                    "configuration": {
                        "functionName": func_name,
                        "runtime": "python3.11",
                        "role": f"arn:aws:iam::{account_id}:role/LambdaExecutionRole",
                        "layers": []
                    }
                },
                metadata={
                    "attack_stage": "discovery",
                    "environment": "production"
                },
            )
        )

    # List existing Lambda layers
    events.append(
        synthesizer.create_lambda_event(
            action="ListLayers",
            principal=compromised_principal,
            function_name="*",  # Wildcard for list operation
            timestamp=discovery_timestamps[7],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            metadata={"attack_stage": "discovery"},
        )
    )

    # Get layer versions
    events.append(
        synthesizer.create_lambda_event(
            action="ListLayerVersions",
            principal=compromised_principal,
            function_name="existing-utils-layer",  # Layer name for this operation
            timestamp=discovery_timestamps[8],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "layerName": "existing-utils-layer"
            },
            metadata={"attack_stage": "discovery"},
        )
    )

    # Stage 3: Malicious Lambda Layer Creation (T+30 to T+50 minutes)
    weaponization_timestamps = generate_time_sequence(
        start_time, 0.45, 15, jitter_seconds=40  # ~55 minutes in
    )

    # Create S3 bucket for malicious layer code (or use existing)
    layer_code_bucket = "cicd-build-artifacts"
    layer_code_key = f"layers/{malicious_layer_name}/{malicious_layer_version}.zip"

    # Upload malicious layer code to S3
    events.append(
        synthesizer.create_s3_event(
            action="PutObject",
            principal=compromised_principal,
            bucket=layer_code_bucket,
            key=layer_code_key,
            timestamp=weaponization_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "bucketName": layer_code_bucket,
                "key": layer_code_key,
                "contentLength": 1024 * 256  # 256 KB
            },
            metadata={
                "attack_stage": "weaponization",
                "malicious_artifact": True,
                "layer_code": True
            },
        )
    )

    # Publish malicious Lambda layer
    layer_arn = f"arn:aws:lambda:{region}:{account_id}:layer:{malicious_layer_name}"
    layer_version_arn = f"{layer_arn}:7"

    events.append(
        synthesizer.create_lambda_event(
            action="PublishLayerVersion",
            principal=compromised_principal,
            function_name=malicious_layer_name,  # Layer name for this operation
            timestamp=weaponization_timestamps[1],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "layerName": malicious_layer_name,
                "description": "Security utilities and monitoring helpers v2.1.5",
                "content": {
                    "s3Bucket": layer_code_bucket,
                    "s3Key": layer_code_key
                },
                "compatibleRuntimes": ["python3.11", "python3.10"],
                "licenseInfo": "MIT"
            },
            response_elements={
                "layerArn": layer_arn,
                "layerVersionArn": layer_version_arn,
                "version": 7
            },
            metadata={
                "attack_stage": "weaponization",
                "malicious_layer": True,
                "critical": True,
                "suspicious": "layer_published_outside_cicd"
            },
        )
    )

    # Grant layer permissions (make it accessible)
    events.append(
        synthesizer.create_lambda_event(
            action="AddLayerVersionPermission",
            principal=compromised_principal,
            function_name=malicious_layer_name,  # Layer name for this operation
            timestamp=weaponization_timestamps[2],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "layerName": malicious_layer_name,
                "versionNumber": 7,
                "statementId": "allow-account-access",
                "action": "lambda:GetLayerVersion",
                "principal": account_id
            },
            metadata={
                "attack_stage": "weaponization"
            },
        )
    )

    # Stage 4: CI/CD Pipeline Manipulation (T+50 to T+70 minutes)
    manipulation_timestamps = generate_time_sequence(
        start_time, 0.64, 18, jitter_seconds=35  # ~77 minutes in
    )

    # Modify buildspec file in S3 (if stored there) or CodeCommit
    buildspec_bucket = "cicd-build-configs"
    events.append(
        synthesizer.create_s3_event(
            action="GetObject",
            principal=compromised_principal,
            bucket=buildspec_bucket,
            key=f"{build_project_name}/buildspec.yml",
            timestamp=manipulation_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            metadata={
                "attack_stage": "execution",
                "suspicious": "buildspec_access"
            },
        )
    )

    # Upload modified buildspec
    events.append(
        synthesizer.create_s3_event(
            action="PutObject",
            principal=compromised_principal,
            bucket=buildspec_bucket,
            key=f"{build_project_name}/buildspec.yml",
            timestamp=manipulation_timestamps[1],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "bucketName": buildspec_bucket,
                "key": f"{build_project_name}/buildspec.yml"
            },
            metadata={
                "attack_stage": "execution",
                "buildspec_modified": True,
                "critical": True,
                "suspicious": "cicd_config_change"
            },
        )
    )

    # Update Lambda function configurations to use malicious layer
    for i, func_name in enumerate(prod_functions[:3]):  # Attack first 3 functions
        if i * 2 + 2 >= len(manipulation_timestamps):
            break

        # Get current function configuration
        events.append(
            synthesizer.create_lambda_event(
                action="GetFunctionConfiguration",
                principal=compromised_principal,
                function_name=func_name,
                timestamp=manipulation_timestamps[i * 2 + 2],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=session_id,
                metadata={"attack_stage": "execution"},
            )
        )

        # Update function to include malicious layer
        events.append(
            synthesizer.create_lambda_event(
                action="UpdateFunctionConfiguration",
                principal=compromised_principal,
                function_name=func_name,
                timestamp=manipulation_timestamps[i * 2 + 3],
                source_ip=attacker_ip,
                user_agent=attacker_user_agent,
                status="success",
                session_id=session_id,
                request_parameters={
                    "functionName": func_name,
                    "layers": [layer_version_arn]
                },
                response_elements={
                    "functionArn": f"arn:aws:lambda:{region}:{account_id}:function:{func_name}",
                    "layers": [
                        {
                            "arn": layer_version_arn,
                            "codeSize": 262144
                        }
                    ]
                },
                metadata={
                    "attack_stage": "execution",
                    "malicious_layer_attached": True,
                    "critical": True,
                    "environment": "production"
                },
            )
        )

    # Stage 5: Trigger Malicious Deployment (T+70 to T+90 minutes)
    deployment_timestamps = generate_time_sequence(
        start_time, 0.77, 20, jitter_seconds=30  # ~92 minutes in
    )

    # Update CodeBuild project
    events.append(
        synthesizer.create_codebuild_event(
            action="UpdateProject",
            principal=compromised_principal,
            project_name=build_project_name,
            timestamp=deployment_timestamps[0],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "name": build_project_name,
                "source": {
                    "type": "S3",
                    "location": f"{buildspec_bucket}/{build_project_name}/buildspec.yml"
                }
            },
            metadata={
                "attack_stage": "persistence",
                "build_config_modified": True,
                "suspicious": True
            },
        )
    )

    # Start CodeBuild build
    build_id = f"{build_project_name}:malicious-build-{generate_session_id()[:8]}"
    events.append(
        synthesizer.create_codebuild_event(
            action="StartBuild",
            principal=compromised_principal,
            project_name=build_project_name,
            timestamp=deployment_timestamps[1],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "projectName": build_project_name
            },
            response_elements={
                "build": {
                    "id": build_id,
                    "buildStatus": "IN_PROGRESS",
                    "projectName": build_project_name
                }
            },
            metadata={
                "attack_stage": "persistence",
                "malicious_build_triggered": True,
                "critical": True
            },
        )
    )

    # Build phase events (from CodeBuild service role)
    build_phase_timestamps = deployment_timestamps[2:8]

    for i, phase in enumerate(["SUBMITTED", "PROVISIONING", "DOWNLOAD_SOURCE", "BUILD", "POST_BUILD", "UPLOAD_ARTIFACTS"]):
        if i >= len(build_phase_timestamps):
            break

        events.append(
            synthesizer.create_codebuild_event(
                action="BuildPhaseChange",
                principal=cicd_role,
                project_name=build_project_name,
                timestamp=build_phase_timestamps[i],
                source_ip=generate_ip_address(private=True, subnet="10.0.1"),
                user_agent="AWS Internal",
                status="success",
                session_id=build_session,
                request_parameters={
                    "buildId": build_id,
                    "phase": phase
                },
                metadata={
                    "attack_stage": "persistence",
                    "build_phase": phase
                },
            )
        )

    # Upload malicious artifacts
    events.append(
        synthesizer.create_s3_event(
            action="PutObject",
            principal=cicd_role,
            bucket=layer_code_bucket,
            key=f"builds/{build_project_name}/artifacts-{generate_session_id()[:8]}.zip",
            timestamp=deployment_timestamps[8],
            source_ip=generate_ip_address(private=True, subnet="10.0.1"),
            user_agent="AWS Internal",
            status="success",
            session_id=build_session,
            request_parameters={
                "contentLength": 1024 * 512  # 512 KB
            },
            metadata={
                "attack_stage": "persistence",
                "malicious_artifact": True,
                "build_output": True
            },
        )
    )

    # Start pipeline execution
    execution_id = f"exec-{generate_session_id()[:12]}"
    events.append(
        synthesizer.create_codepipeline_event(
            action="StartPipelineExecution",
            principal=compromised_principal,
            pipeline_name=pipeline_name,
            timestamp=deployment_timestamps[9],
            source_ip=attacker_ip,
            user_agent=attacker_user_agent,
            status="success",
            session_id=session_id,
            request_parameters={
                "name": pipeline_name
            },
            response_elements={
                "pipelineExecutionId": execution_id
            },
            metadata={
                "attack_stage": "persistence",
                "malicious_deployment_triggered": True,
                "critical": True
            },
        )
    )

    # Stage 6: Production Deployment (T+90 to T+110 minutes)
    production_timestamps = generate_time_sequence(
        start_time, 0.91, 15, jitter_seconds=25  # ~100 minutes in
    )

    # Deploy Lambda functions with malicious layer
    for i, func_name in enumerate(prod_functions):
        if i >= len(production_timestamps):
            break

        # Update function code (via deployment)
        events.append(
            synthesizer.create_lambda_event(
                action="UpdateFunctionCode",
                principal=cicd_role,
                function_name=func_name,
                timestamp=production_timestamps[i],
                source_ip=generate_ip_address(private=True, subnet="10.0.1"),
                user_agent="AWS Internal",
                status="success",
                session_id=build_session,
                request_parameters={
                    "functionName": func_name,
                    "s3Bucket": layer_code_bucket,
                    "s3Key": f"builds/{build_project_name}/artifacts-{generate_session_id()[:8]}.zip"
                },
                response_elements={
                    "functionArn": f"arn:aws:lambda:{region}:{account_id}:function:{func_name}",
                    "layers": [{"arn": layer_version_arn}],
                    "lastModified": production_timestamps[i]
                },
                metadata={
                    "attack_stage": "impact",
                    "production_deployment": True,
                    "malicious_code_deployed": True,
                    "critical": True
                },
            )
        )

    # Pipeline completion
    events.append(
        synthesizer.create_codepipeline_event(
            action="PipelineExecutionStateChange",
            principal=cicd_role,
            pipeline_name=pipeline_name,
            timestamp=production_timestamps[6],
            source_ip=generate_ip_address(private=True, subnet="10.0.1"),
            user_agent="AWS Internal",
            status="success",
            session_id=build_session,
            request_parameters={
                "pipelineExecutionId": execution_id,
                "state": "SUCCEEDED"
            },
            metadata={
                "attack_stage": "impact",
                "deployment_complete": True,
                "production_compromised": True
            },
        )
    )

    # Post-deployment: Malicious Lambda invocations
    for i in range(3):
        if 7 + i >= len(production_timestamps):
            break

        events.append(
            synthesizer.create_lambda_event(
                action="Invoke",
                principal=f"arn:aws:iam::{account_id}:role/APIGatewayLambdaRole",
                function_name=prod_functions[0],  # First compromised function
                timestamp=production_timestamps[7 + i],
                source_ip=generate_ip_address(private=False),
                user_agent="Mozilla/5.0",
                status="success",
                session_id=generate_session_id(),
                metadata={
                    "attack_stage": "impact",
                    "backdoor_execution": True,
                    "malicious_layer_active": True
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
        "scenario_name": "supply_chain",
        "description": "CI/CD supply chain compromise via malicious Lambda layer",
        "duration_hours": duration_hours,
        "num_events": len(events),
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "attacker_ip": attacker_ip,
        "compromised_principal": compromised_principal,
        "malicious_layer": {
            "name": malicious_layer_name,
            "version": malicious_layer_version,
            "arn": layer_version_arn
        },
        "compromised_pipeline": pipeline_name,
        "compromised_build_project": build_project_name,
        "affected_functions": prod_functions,
        "attack_stages": [
            "reconnaissance",
            "discovery",
            "weaponization",
            "execution",
            "persistence",
            "impact"
        ],
        "mitre_techniques": [
            "T1195.001",   # Supply Chain Compromise: Software Dependencies
            "T1195.002",   # Supply Chain Compromise: Software Supply Chain
            "T1525",       # Implant Internal Image
            "T1580",       # Cloud Infrastructure Discovery
            "T1078.004",   # Valid Accounts: Cloud Accounts
            "T1020",       # Automated Exfiltration
        ],
    }

    return metadata


if __name__ == "__main__":
    # Example usage
    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)

    metadata = generate_supply_chain_scenario(
        output_dir=output_dir,
        duration_hours=1.83,
        add_noise=True
    )

    print(f"Generated {metadata['num_events']} events")
    print(f"Output: {output_dir / 'telemetry.jsonl'}")
