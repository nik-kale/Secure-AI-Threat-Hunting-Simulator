# Supply Chain Attack Scenario

## Overview

This scenario simulates a sophisticated supply chain attack where an attacker compromises a CI/CD pipeline (CodePipeline/CodeBuild), injects malicious code via a compromised Lambda layer, and deploys backdoored functions to production. This represents a critical threat where the development and deployment infrastructure itself becomes the attack vector.

## Attack Chain

### Stage 1: Initial Access to CI/CD (Kill Chain: Initial Access)
- **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts)
- Attacker compromises CI/CD service account credentials
- Gains access to CodePipeline and CodeBuild
- Enumerates build projects and deployment pipelines
- Identifies automated deployment workflows

### Stage 2: CI/CD Infrastructure Reconnaissance (Kill Chain: Reconnaissance)
- **MITRE ATT&CK**: T1580 (Cloud Infrastructure Discovery)
- Enumerates CodePipeline pipelines
- Lists CodeBuild projects and build specifications
- Discovers Lambda functions and layers
- Maps deployment automation and artifact repositories
- Identifies production deployment paths

### Stage 3: Supply Chain Compromise - Malicious Layer Creation (Kill Chain: Resource Development)
- **MITRE ATT&CK**: T1195.001 (Supply Chain Compromise: Compromise Software Dependencies and Development Tools)
- Creates malicious Lambda layer with backdoor code
- Injects data exfiltration capabilities
- Adds command and control functionality
- Disguises layer as legitimate dependency update
- Uploads layer to Lambda service

### Stage 4: Pipeline Manipulation (Kill Chain: Execution)
- **MITRE ATT&CK**: T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)
- Modifies CodeBuild buildspec.yaml
- Updates Lambda function configurations
- Attaches malicious layer to production functions
- Modifies deployment pipeline stages
- Injects malicious code into build artifacts

### Stage 5: Malicious Deployment to Production (Kill Chain: Persistence)
- **MITRE ATT&CK**: T1525 (Implant Internal Image)
- Triggers automated deployment pipeline
- Malicious layer deployed with legitimate updates
- Backdoored Lambda functions deployed to production
- Establishes persistence through legitimate deployment process
- Production functions now execute attacker code

### Stage 6: Post-Deployment Activities (Kill Chain: Actions on Objectives)
- **MITRE ATT&CK**: T1020 (Automated Exfiltration)
- Malicious Lambda functions execute in production
- Data exfiltration through backdoored functions
- Command and control communication established
- Lateral movement through Lambda execution role
- Continued access via compromised supply chain

## Indicators of Compromise (IOCs)

- Unusual access to CodePipeline/CodeBuild from unexpected IPs
- Lambda layer creation outside normal deployment windows
- Modifications to Lambda function configurations
- New Lambda layers from non-standard sources
- Changes to CodeBuild buildspec files
- Pipeline executions outside normal hours
- Lambda function updates with new layers attached
- Unexpected IAM role assumptions by CodeBuild
- Modified deployment artifact checksums
- Unusual network connections from Lambda functions
- CodeCommit/CodeBuild access from suspicious geolocations
- Lambda layer versions with unusual naming patterns

## Timeline

Total duration: ~90-120 minutes

1. **T+0:00** - Initial reconnaissance of CI/CD infrastructure
2. **T+0:10** - CodePipeline and CodeBuild enumeration
3. **T+0:20** - Lambda function and layer discovery
4. **T+0:30** - Analysis of existing deployment pipelines
5. **T+0:40** - Malicious Lambda layer creation begins
6. **T+0:50** - Layer uploaded with backdoor code
7. **T+0:60** - CodeBuild buildspec modification
8. **T+0:70** - Lambda function configuration updates
9. **T+0:80** - Malicious layer attached to functions
10. **T+0:90** - Pipeline execution triggered
11. **T+0:100** - Deployment to production environment
12. **T+0:110** - Post-deployment validation and persistence

## Detection Opportunities

1. **Abnormal CI/CD Access**
   - CodePipeline/CodeBuild access from unusual IP addresses
   - API calls outside normal business hours
   - Service account behavior anomalies
   - Geographic impossibility for CI/CD access

2. **Lambda Layer Anomalies**
   - New layer creation by non-standard principals
   - Layer versions with unusual sizes or checksums
   - Layers attached to multiple production functions rapidly
   - Layer source code from unexpected S3 locations

3. **Pipeline Manipulation**
   - Buildspec file modifications outside version control
   - Pipeline stage changes without approval
   - Deployment triggers from unexpected sources
   - Modified artifact signing or validation

4. **Deployment Anomalies**
   - Production deployments outside change windows
   - Lambda function updates without corresponding code commits
   - Rapid updates to multiple functions simultaneously
   - Configuration drift from infrastructure-as-code

5. **Runtime Behavior**
   - Lambda functions making unexpected network calls
   - Unusual IAM role assumptions from Lambda
   - Data access patterns inconsistent with function purpose
   - Execution duration or memory usage anomalies

## Mitigation Strategies

1. **Preventive Controls**
   - Implement strict IAM policies for CI/CD access
   - Require MFA for CI/CD service accounts
   - Use VPC endpoints for CodeBuild
   - Implement code signing for Lambda functions and layers
   - Enforce approval gates in deployment pipelines
   - Use AWS Signer for artifact signing
   - Implement least privilege for build service roles
   - Store buildspec files in version-controlled repositories
   - Use CodeArtifact for dependency management
   - Implement network isolation for build environments

2. **Detective Controls**
   - Monitor CloudTrail for CodePipeline/CodeBuild events
   - Alert on Lambda layer creation and attachment
   - Track buildspec file modifications
   - Monitor pipeline execution patterns
   - Implement runtime application security monitoring
   - Use AWS GuardDuty for threat detection
   - Enable VPC Flow Logs for Lambda network activity
   - Baseline normal CI/CD access patterns
   - Monitor Lambda function configuration changes

3. **Response Actions**
   - Immediately disable compromised CI/CD credentials
   - Roll back affected Lambda deployments
   - Remove malicious Lambda layers
   - Audit all recent pipeline executions
   - Review CloudTrail logs for attack scope
   - Scan all Lambda functions for malicious layers
   - Restore known-good function configurations
   - Implement emergency change freeze
   - Validate integrity of all deployment artifacts

## MITRE ATT&CK Mapping

- **T1195.001** - Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1195.002** - Supply Chain Compromise: Compromise Software Supply Chain
- **T1525** - Implant Internal Image
- **T1580** - Cloud Infrastructure Discovery
- **T1078.004** - Valid Accounts: Cloud Accounts
- **T1020** - Automated Exfiltration
- **T1059** - Command and Scripting Interpreter

## Metadata

- **Scenario Type**: CI/CD supply chain compromise
- **Complexity**: Very High
- **Target Environment**: AWS CodePipeline, CodeBuild, Lambda
- **Duration**: 90-120 minutes
- **Event Count**: 100-120 events
- **Noise Ratio**: 30% benign events
- **Attack Sophistication**: Advanced Persistent Threat (APT)
- **Business Impact**: Critical - Production compromise via trusted deployment pipeline
