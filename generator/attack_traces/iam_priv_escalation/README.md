# IAM Privilege Escalation Attack Scenario

## Overview

This scenario simulates an attacker who has obtained credentials for a low-privilege service account and exploits IAM misconfigurations to escalate privileges and establish persistence.

## Attack Chain

### Stage 1: Reconnaissance (Kill Chain: Reconnaissance)
- **MITRE ATT&CK**: T1087.004 (Account Discovery: Cloud Account)
- Attacker enumerates IAM roles, policies, and permissions
- Lists users, groups, and attached policies
- Identifies misconfigured permissions

### Stage 2: Initial Access (Kill Chain: Weaponization/Delivery)
- **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts)
- Uses compromised service account credentials
- Low-privilege account with read access to IAM

### Stage 3: Privilege Escalation (Kill Chain: Exploitation)
- **MITRE ATT&CK**: T1548.005 (Abuse Elevation Control Mechanism)
- Exploits `iam:PassRole` + `lambda:CreateFunction` combination
- Creates Lambda function with high-privilege role
- Executes function to assume elevated permissions

### Stage 4: Persistence (Kill Chain: Installation)
- **MITRE ATT&CK**: T1136.003 (Create Account: Cloud Account)
- Creates backdoor IAM role with administrative privileges
- Attaches inline policies for persistent access
- Creates access keys for long-term access

### Stage 5: Impact (Kill Chain: Actions on Objectives)
- **MITRE ATT&CK**: T1530 (Data from Cloud Storage Object)
- Accesses sensitive S3 buckets
- Exfiltrates data from restricted resources

## Indicators of Compromise (IOCs)

- Unusual IP addresses accessing IAM APIs
- Rapid sequence of IAM enumeration calls
- Lambda function creation with high-privilege role
- New IAM role creation outside of normal workflows
- S3 access from newly created roles
- Suspicious user agent strings (boto3, aws-cli from unexpected sources)

## Timeline

Total duration: ~45-60 minutes

1. **T+0:00** - Initial reconnaissance begins
2. **T+0:05** - Comprehensive IAM enumeration
3. **T+0:15** - Discovery of PassRole vulnerability
4. **T+0:20** - Lambda function creation with high-privilege role
5. **T+0:25** - Lambda function invocation
6. **T+0:30** - Backdoor role creation
7. **T+0:35** - Access key generation
8. **T+0:40** - S3 data access
9. **T+0:45** - Continued reconnaissance with elevated privileges

## Detection Opportunities

1. **Anomalous IAM Activity**
   - Service accounts performing IAM administrative actions
   - High volume of List*/Get* IAM calls in short timeframe

2. **PassRole Abuse**
   - Lambda function created with role more privileged than creator
   - PassRole action from non-administrative principal

3. **Out-of-Band Resource Creation**
   - IAM resources created outside of IaC/automation pipelines
   - Resources with unusual naming patterns

4. **Behavioral Anomalies**
   - Service account accessing resources outside normal scope
   - API calls from unexpected geolocation or IP ranges

## Mitigation Strategies

1. **Preventive Controls**
   - Implement least privilege IAM policies
   - Restrict `iam:PassRole` to specific roles
   - Use SCPs to limit privilege escalation paths
   - Enforce MFA for sensitive operations

2. **Detective Controls**
   - Monitor CloudTrail for IAM policy changes
   - Alert on PassRole actions
   - Baseline normal IAM activity patterns
   - Implement anomaly detection for service accounts

3. **Response Actions**
   - Revoke compromised credentials immediately
   - Delete unauthorized IAM resources
   - Review audit logs for full scope of access
   - Rotate all potentially exposed credentials
