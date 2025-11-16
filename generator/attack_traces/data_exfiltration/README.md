# Data Exfiltration Attack Scenario

## Overview

This scenario simulates a sophisticated data exfiltration attack where an attacker with compromised credentials systematically enumerates S3 buckets, copies sensitive data to an external attacker-controlled bucket, and attempts to cover their tracks by deleting CloudTrail logs.

## Attack Chain

### Stage 1: Initial Access and Reconnaissance (Kill Chain: Initial Access)
- **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts)
- Attacker uses compromised IAM credentials
- Initial enumeration of accessible resources
- Discovery of S3 buckets and permissions

### Stage 2: S3 Bucket Enumeration (Kill Chain: Reconnaissance)
- **MITRE ATT&CK**: T1580 (Cloud Infrastructure Discovery), T1619 (Cloud Storage Object Discovery)
- Lists all S3 buckets in the account
- Enumerates bucket policies and ACLs
- Identifies buckets with sensitive data
- Checks bucket encryption and versioning settings
- Maps out data repositories

### Stage 3: Data Staging and Collection (Kill Chain: Collection)
- **MITRE ATT&CK**: T1530 (Data from Cloud Storage Object)
- Downloads objects from sensitive buckets
- Targets high-value data (customer info, financial records, PII)
- Bulk download operations using S3 batch operations
- Multiple GetObject calls with large byte transfers

### Stage 4: Data Exfiltration (Kill Chain: Exfiltration)
- **MITRE ATT&CK**: T1537 (Transfer Data to Cloud Account)
- Creates or uses existing external S3 bucket
- Copies data to attacker-controlled bucket in different account
- Uses S3 cross-account replication or direct copy
- High-volume S3-to-S3 transfers
- Data leaves organizational control

### Stage 5: Anti-Forensics (Kill Chain: Defense Evasion)
- **MITRE ATT&CK**: T1485 (Data Destruction), T1070.001 (Clear Logs)
- Attempts to delete CloudTrail event logs
- Stops CloudTrail logging
- Deletes S3 access logs
- Removes evidence of exfiltration activity
- May delete original data to cause impact

## Indicators of Compromise (IOCs)

- Unusual S3 bucket enumeration activity
- High volume of S3 GetObject API calls
- Large data transfers from S3 buckets
- S3 copy operations to external accounts
- Cross-account S3 replication to unknown accounts
- CloudTrail deletion or modification attempts
- S3 access from unexpected IP addresses or geolocations
- Abnormal data egress patterns
- After-hours S3 access from service accounts
- Bucket policy modifications
- Unusual user agent strings for S3 operations

## Timeline

Total duration: ~30-45 minutes

1. **T+0:00** - Initial reconnaissance begins
2. **T+0:05** - S3 bucket enumeration
3. **T+0:10** - Bucket policy and ACL enumeration
4. **T+0:15** - First data downloads begin
5. **T+0:20** - Bulk S3 GetObject operations
6. **T+0:25** - External bucket creation/setup
7. **T+0:30** - Cross-account S3 copy operations
8. **T+0:35** - CloudTrail log deletion attempts
9. **T+0:40** - S3 access log deletion
10. **T+0:45** - Final cleanup activities

## Detection Opportunities

1. **Abnormal S3 Access Patterns**
   - High volume of GetObject calls in short timeframe
   - Sequential access to multiple buckets
   - Large byte transfers from S3
   - S3 access outside normal business hours

2. **Cross-Account Data Transfer**
   - S3 copy operations to external accounts
   - Unknown destination bucket ARNs
   - Cross-region replication to suspicious accounts
   - Bucket policy changes allowing external access

3. **Anti-Forensics Indicators**
   - CloudTrail DeleteTrail or StopLogging events
   - S3 server access logging disabled
   - Bulk log file deletions
   - Attempts to modify audit configurations

4. **Behavioral Anomalies**
   - Service accounts accessing unusual S3 buckets
   - API calls from unexpected geographic locations
   - Unusual patterns in data access volume
   - Access to dormant or archive buckets

## Mitigation Strategies

1. **Preventive Controls**
   - Implement least privilege S3 bucket policies
   - Enable S3 Block Public Access
   - Require MFA for sensitive S3 operations
   - Use S3 Object Lock for critical data
   - Implement VPC endpoints for S3 access
   - Use AWS Organizations SCPs to restrict cross-account access
   - Enable S3 default encryption
   - Implement data classification and DLP

2. **Detective Controls**
   - Enable CloudTrail with log file validation
   - Store CloudTrail logs in separate security account
   - Enable S3 server access logging
   - Monitor S3 data transfer metrics
   - Alert on CloudTrail modifications
   - Implement anomaly detection for S3 access patterns
   - Use GuardDuty for threat detection
   - Monitor VPC Flow Logs for unusual S3 traffic

3. **Response Actions**
   - Immediately revoke compromised credentials
   - Enable S3 versioning to recover deleted objects
   - Isolate affected buckets with restrictive policies
   - Review CloudTrail logs before they're deleted
   - Identify scope of data accessed
   - Notify affected parties per breach response plan
   - Restore CloudTrail logging if disabled

## MITRE ATT&CK Mapping

- **T1530** - Data from Cloud Storage Object
- **T1537** - Transfer Data to Cloud Account
- **T1485** - Data Destruction
- **T1070.001** - Indicator Removal: Clear Logs
- **T1580** - Cloud Infrastructure Discovery
- **T1619** - Cloud Storage Object Discovery
- **T1078.004** - Valid Accounts: Cloud Accounts

## Metadata

- **Scenario Type**: Data exfiltration via S3
- **Complexity**: Medium-High
- **Target Environment**: AWS S3 and CloudTrail
- **Duration**: 30-45 minutes
- **Event Count**: 50-70 events
- **Noise Ratio**: 30% benign events
- **Data at Risk**: Customer data, financial records, PII, intellectual property
