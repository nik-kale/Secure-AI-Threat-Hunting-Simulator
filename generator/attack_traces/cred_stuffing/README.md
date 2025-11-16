# Credential Stuffing Attack Scenario

## Overview

Simulates an automated credential stuffing attack against cloud authentication endpoints using leaked username/password combinations.

## Attack Chain

### Stage 1: Reconnaissance
- **MITRE ATT&CK**: T1589.001 (Gather Victim Identity Information)
- Identify target authentication endpoints
- Test authentication mechanisms

### Stage 2: Credential Stuffing
- **MITRE ATT&CK**: T1110.004 (Brute Force: Credential Stuffing)
- Automated login attempts with leaked credentials
- High volume authentication requests from distributed IPs
- Mix of failures and occasional successes

### Stage 3: Account Validation
- **MITRE ATT&CK**: T1087 (Account Discovery)
- Validate compromised accounts
- Enumerate permissions and access

### Stage 4: Account Access
- **MITRE ATT&CK**: T1078.004 (Valid Accounts: Cloud Accounts)
- Login with successfully stuffed credentials
- Maintain persistent access

## Indicators of Compromise

- High volume authentication failures from single or distributed sources
- Sequential authentication attempts with different usernames
- Authentication from unusual geolocations
- Automated user agent strings
- Unusual time-of-day for authentication
- Multiple accounts accessed from same IP in short timeframe

## Timeline

Total duration: ~20 minutes

1. **T+0:00** - Initial authentication endpoint discovery
2. **T+0:02** - Credential stuffing begins (high volume)
3. **T+0:15** - Successful authentication
4. **T+0:18** - Account enumeration
