# Threat Scenarios

## Overview

This document describes the attack scenarios included in the AI Threat Hunting Simulator. Each scenario represents a realistic cloud attack pattern with detailed telemetry generation.

## Scenario Index

1. [IAM Privilege Escalation](#iam-privilege-escalation)
2. [Container Escape](#container-escape)
3. [Credential Stuffing](#credential-stuffing)
4. [Lateral Movement](#lateral-movement) *(Future)*
5. [API Key Theft](#api-key-theft) *(Future)*
6. [Persistence Creation](#persistence-creation) *(Future)*

---

## IAM Privilege Escalation

**Scenario ID:** `iam_priv_escalation`

### Attack Summary

An attacker with low-privilege service account credentials exploits IAM misconfiguration (specifically `iam:PassRole` combined with `lambda:CreateFunction`) to escalate privileges, establish persistence, and access sensitive data.

### Attack Chain

#### Stage 1: Reconnaissance (T+0-10 min)
- **MITRE ATT&CK**: T1087.004 (Account Discovery: Cloud Account)
- **Activities**:
  - Enumerate IAM roles, users, and policies
  - Identify permission boundaries
  - Map out cloud environment structure

**Sample Events:**
```json
{"event_type": "iam.list_roles", "principal": "service-account-readonly", ...}
{"event_type": "iam.get_role_policy", "resource": "HighPrivilegeRole", ...}
```

#### Stage 2: Privilege Escalation (T+20-30 min)
- **MITRE ATT&CK**: T1548.005 (Temporary Elevated Cloud Access)
- **Activities**:
  - Create Lambda function with high-privilege role (PassRole abuse)
  - Invoke function to execute with elevated permissions
  - Gain access to admin-level APIs

**Sample Events:**
```json
{"event_type": "lambda.create_function",
 "request_parameters": {"role": "arn:aws:iam::123456789012:role/HighPrivilegeRole"}, ...}
{"event_type": "lambda.invoke", ...}
```

#### Stage 3: Persistence (T+30-40 min)
- **MITRE ATT&CK**: T1136.003 (Create Account: Cloud Account)
- **Activities**:
  - Create backdoor IAM role with admin permissions
  - Generate access keys for long-term access
  - Attach overly permissive policies

**Sample Events:**
```json
{"event_type": "iam.create_role", "resource": "BackdoorAdminRole", ...}
{"event_type": "iam.create_access_key", ...}
```

#### Stage 4: Impact (T+40-50 min)
- **MITRE ATT&CK**: T1530 (Data from Cloud Storage Object)
- **Activities**:
  - Access sensitive S3 buckets
  - Exfiltrate customer data
  - Query secrets manager

### Key IOCs

- **Compromised Account**: `service-account-readonly`
- **Suspicious IPs**: External IP performing IAM enumeration
- **Created Resources**:
  - Lambda function: `data-processor-temp`
  - IAM role: `BackdoorAdminRole`
  - IAM user: `backup-automation-user`
- **Suspicious Patterns**:
  - Rapid IAM enumeration (15+ calls in 10 minutes)
  - PassRole with Lambda from non-admin account
  - IAM resource creation outside normal hours

### Detection Opportunities

1. **Behavioral Anomalies**
   - Service account performing administrative actions
   - Unusual time-of-day for IAM operations

2. **Pattern Detection**
   - PassRole followed by CreateFunction
   - New IAM resources created programmatically

3. **Policy Violations**
   - Overly permissive inline policies
   - Resources created outside IaC pipelines

### Mitigation

- Restrict `iam:PassRole` to specific roles
- Implement SCPs to prevent privilege escalation
- Alert on PassRole actions from non-admin principals
- Require MFA for sensitive IAM operations

---

## Container Escape

**Scenario ID:** `container_escape`

### Attack Summary

Attacker exploits a web application vulnerability to gain code execution within a container, then breaks out to the host system using container misconfigurations. Uses stolen instance credentials to enumerate cloud resources and deploys a cryptominer.

### Attack Chain

#### Stage 1: Initial Access (T+0-2 min)
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- Web application exploit via file upload vulnerability
- Establishes shell in container

#### Stage 2: Container Escape (T+5-10 min)
- **MITRE ATT&CK**: T1611 (Escape to Host)
- Exploits privileged container mode
- Mounts host filesystem
- Breaks out of container namespace

**Sample Events:**
```json
{"event_type": "container.exec", "metadata": {"command": "mount /dev/xvda1 /mnt/host"}, ...}
{"event_type": "container.exec", "metadata": {"command": "chroot /mnt/host /bin/bash"}, ...}
```

#### Stage 3: Credential Access (T+10-15 min)
- **MITRE ATT&CK**: T1552.005 (Cloud Instance Metadata API)
- Queries EC2 metadata service
- Extracts IAM role credentials

#### Stage 4: Impact (T+25-40 min)
- **MITRE ATT&CK**: T1496 (Resource Hijacking)
- Downloads cryptominer binary
- Executes mining software
- Connects to mining pool

### Key IOCs

- **Container ID**: `cont-a1b2c3d4e5f6`
- **Malicious Commands**:
  - `mount /dev/xvda1 /mnt/host`
  - `chroot /mnt/host /bin/bash`
  - `./xmrig --donate-level 1 -o pool.minexmr.com:4444`
- **Network IOCs**:
  - Connection to mining pool: `pool.minexmr.com:4444`
  - High volume outbound traffic
- **Resource Indicators**:
  - CPU usage >95% in container
  - Unexpected process `xmrig`

### Detection Opportunities

1. **Container Anomalies**
   - Privileged syscalls from container
   - Mount operations
   - Unexpected binaries executing

2. **Network Patterns**
   - Connections to known mining pools
   - High volume of small packets
   - Unusual destination ports

3. **Resource Consumption**
   - Sustained high CPU usage
   - Containers exceeding resource limits

### Mitigation

- Disable privileged container mode
- Implement seccomp/AppArmor profiles
- Block container access to metadata service
- Monitor for cryptocurrency mining indicators

---

## Credential Stuffing

**Scenario ID:** `cred_stuffing`

### Attack Summary

Automated credential stuffing attack using leaked username/password combinations against cloud authentication endpoints. Distributed across multiple IPs to evade rate limiting.

### Attack Chain

#### Stage 1: Reconnaissance (T+0-2 min)
- **MITRE ATT&CK**: T1589.001 (Gather Victim Identity Information)
- Identify authentication endpoints
- Test login mechanisms

#### Stage 2: Credential Stuffing (T+2-15 min)
- **MITRE ATT&CK**: T1110.004 (Brute Force: Credential Stuffing)
- High-volume login attempts
- ~85 failures across distributed IPs
- 1 successful authentication

**Sample Events:**
```json
// Failures
{"event_type": "api.request", "path": "/api/auth/login", "status_code": 401, ...}
{"event_type": "api.request", "path": "/api/auth/login", "status_code": 401, ...}

// Success
{"event_type": "api.request", "path": "/api/auth/login", "status_code": 200,
 "metadata": {"username": "sarah.johnson@example.com", "authentication": "success"}, ...}
```

#### Stage 3: Validation (T+15-18 min)
- **MITRE ATT&CK**: T1087 (Account Discovery)
- Validate compromised account
- Enumerate permissions

### Key IOCs

- **Attack Pattern**: 85+ failed auth attempts in 15 minutes
- **Botnet IPs**: 15 unique source IPs
- **Compromised Account**: `sarah.johnson@example.com`
- **User Agents**: `python-requests/2.28.1`, `curl/7.68.0` (automated tools)

### Detection Opportunities

1. **Volume-Based**
   - High authentication failure rate
   - Multiple failed logins for same username
   - Distributed source IPs

2. **Pattern-Based**
   - Sequential username attempts
   - Automated user agent strings
   - Unusual authentication timing

3. **Geolocation**
   - Logins from unusual locations
   - Impossible travel scenarios

### Mitigation

- Implement rate limiting per IP and per account
- Deploy CAPTCHA for repeated failures
- Enforce MFA for all accounts
- Monitor for credential exposure in breach dumps

---

## Future Scenarios

### Lateral Movement
- Pivot from compromised instance to other cloud resources
- Abuse trust relationships between accounts
- Network-based lateral movement in VPCs

### API Key Theft
- Exfiltration of API keys from code repositories
- Use of stolen keys to access cloud resources
- Privilege escalation via key permissions

### Persistence Creation
- Multiple persistence techniques combined
- Scheduled tasks (EventBridge rules)
- Hidden IAM roles and backdoor accounts
- Modified Lambda layers

---

## Scenario Comparison Matrix

| Scenario | Duration | Events | Sophistication | Risk Level |
|----------|----------|--------|----------------|------------|
| IAM Priv Escalation | ~60 min | ~50-70 | High | Critical |
| Container Escape | ~40 min | ~40-60 | Moderate | Critical |
| Credential Stuffing | ~20 min | ~100-120 | Low | High |

## Adding Custom Scenarios

See `generator/attack_traces/README.md` for instructions on creating custom scenarios.
