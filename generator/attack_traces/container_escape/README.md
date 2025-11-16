# Container Breakout Attack Scenario

## Overview

Simulates an attacker who has gained code execution within a containerized workload and attempts to escape to the underlying host system, then pivots to cloud resources.

## Attack Chain

### Stage 1: Initial Access (Kill Chain: Delivery/Exploitation)
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- Web application vulnerability leads to container compromise
- Establishes shell access within container

### Stage 2: Container Escape (Kill Chain: Exploitation)
- **MITRE ATT&CK**: T1611 (Escape to Host)
- Exploits container misconfiguration (privileged mode, exposed Docker socket)
- Mounts host filesystem
- Breaks out of container namespace

### Stage 3: Credential Access (Kill Chain: Actions on Objectives)
- **MITRE ATT&CK**: T1552.005 (Cloud Instance Metadata API)
- Queries EC2 instance metadata service
- Extracts IAM role credentials
- Obtains temporary security tokens

### Stage 4: Lateral Movement (Kill Chain: Lateral Movement)
- **MITRE ATT&CK**: T1021 (Remote Services)
- Uses stolen credentials to access cloud APIs
- Enumerates other containers and instances
- Attempts to access internal services

### Stage 5: Impact (Kill Chain: Actions on Objectives)
- **MITRE ATT&CK**: T1496 (Resource Hijacking)
- Deploys cryptominer in compromised containers
- Establishes persistence via modified container images

## Indicators of Compromise

- Container executing unexpected system calls (mount, chroot, nsenter)
- Unusual processes within container (docker, kubectl)
- Metadata service requests from container
- High CPU usage from containers (cryptomining)
- Container images modified outside CI/CD pipeline
- Network connections to cryptocurrency pools

## Timeline

Total duration: ~30-40 minutes

1. **T+0:00** - Web application exploit
2. **T+0:02** - Shell established in container
3. **T+0:05** - Container escape attempt
4. **T+0:08** - Host filesystem access
5. **T+0:10** - Metadata service queries
6. **T+0:15** - Credential extraction
7. **T+0:20** - Cloud API enumeration
8. **T+0:25** - Cryptominer deployment
