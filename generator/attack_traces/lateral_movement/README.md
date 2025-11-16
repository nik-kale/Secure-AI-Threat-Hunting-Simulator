# Lateral Movement Attack Scenario

## Overview

This scenario simulates an advanced attacker who has compromised a development account and uses AWS IAM role chaining (AssumeRole) to move laterally from the development environment to production, ultimately accessing sensitive data across multiple accounts.

## Attack Chain

### Stage 1: Initial Foothold (Kill Chain: Initial Access)
- **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts)
- Attacker uses compromised development account credentials
- Initial access to low-privilege development resources
- Reconnaissance of available roles and trust relationships

### Stage 2: Cross-Account Discovery (Kill Chain: Reconnaissance)
- **MITRE ATT&CK**: T1580 (Cloud Infrastructure Discovery)
- Enumerates IAM roles and trust policies
- Discovers cross-account AssumeRole permissions
- Maps the multi-account architecture
- Identifies production account access paths

### Stage 3: Lateral Movement to Production (Kill Chain: Lateral Movement)
- **MITRE ATT&CK**: T1021 (Remote Services), T1550.001 (Use Alternate Authentication Material: Application Access Token)
- Assumes cross-account role in staging environment
- Chains multiple AssumeRole operations
- Pivots from Dev → Staging → Production
- Each hop increases privilege level

### Stage 4: Privilege Escalation in Production (Kill Chain: Privilege Escalation)
- **MITRE ATT&CK**: T1098 (Account Manipulation)
- Assumes high-privilege production role
- Modifies trust policies for persistence
- Creates additional backdoor roles
- Establishes long-term access mechanisms

### Stage 5: Data Access and Collection (Kill Chain: Actions on Objectives)
- **MITRE ATT&CK**: T1530 (Data from Cloud Storage Object)
- Accesses production databases (RDS)
- Downloads sensitive data from production S3 buckets
- Queries secrets from AWS Secrets Manager
- Exfiltrates customer and financial data

## Indicators of Compromise (IOCs)

- Unusual cross-account AssumeRole activity
- Role assumption chains with multiple hops
- Development accounts accessing production resources
- AssumeRole calls from unexpected IP addresses or geolocations
- Modification of IAM role trust policies
- Production data access from non-production principals
- High volume of S3 GetObject calls to sensitive buckets
- Secrets Manager access from unexpected roles
- Session duration anomalies (longer than typical)

## Timeline

Total duration: ~60-90 minutes

1. **T+0:00** - Initial reconnaissance in dev account
2. **T+0:10** - Enumeration of cross-account roles
3. **T+0:20** - First AssumeRole to staging account
4. **T+0:30** - Lateral movement to production account
5. **T+0:40** - Privilege escalation in production
6. **T+0:50** - Trust policy modification for persistence
7. **T+0:60** - Production data access begins
8. **T+0:70** - S3 data exfiltration
9. **T+0:80** - Secrets Manager enumeration

## Detection Opportunities

1. **Cross-Account Role Assumption Anomalies**
   - Dev accounts assuming production roles
   - Unusual role chaining patterns
   - AssumeRole from non-standard IP addresses

2. **Trust Policy Modifications**
   - Changes to IAM role trust relationships
   - New principals added to trust policies
   - Trust policy updates outside of IaC workflows

3. **Abnormal Data Access Patterns**
   - Production data access from dev/staging accounts
   - High-volume S3 operations from unusual sources
   - Secrets Manager access outside normal application patterns

4. **Session Behavior Anomalies**
   - Long-duration sessions
   - Rapid succession of role assumptions
   - Geographic impossibility (session from different locations)

## Mitigation Strategies

1. **Preventive Controls**
   - Implement strict cross-account trust policies
   - Require external ID for cross-account access
   - Use session policies to limit assumed role permissions
   - Enforce MFA for sensitive role assumptions
   - Implement SCPs to restrict cross-account access
   - Use AWS Organizations for centralized governance

2. **Detective Controls**
   - Monitor CloudTrail for AssumeRole events
   - Alert on cross-account role chains
   - Baseline normal cross-account access patterns
   - Track role trust policy modifications
   - Monitor production resource access from non-prod accounts

3. **Response Actions**
   - Immediately revoke active sessions
   - Update trust policies to remove unauthorized principals
   - Rotate credentials for all affected accounts
   - Review CloudTrail logs for full attack scope
   - Implement break-glass procedures for emergency access

## MITRE ATT&CK Mapping

- **T1021** - Remote Services
- **T1550.001** - Use Alternate Authentication Material: Application Access Token
- **T1098** - Account Manipulation
- **T1580** - Cloud Infrastructure Discovery
- **T1087.004** - Account Discovery: Cloud Account
- **T1530** - Data from Cloud Storage Object

## Metadata

- **Scenario Type**: Multi-account lateral movement
- **Complexity**: High
- **Target Environment**: Multi-account AWS organization
- **Duration**: 60-90 minutes
- **Event Count**: 80-100 events
- **Noise Ratio**: 30% benign events
