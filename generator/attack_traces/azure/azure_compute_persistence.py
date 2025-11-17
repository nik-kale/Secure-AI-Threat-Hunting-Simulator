"""Azure VM persistence and lateral movement scenario."""
from typing import List, Dict, Any
from datetime import datetime, timedelta
import random

class AzureComputePersistenceGenerator:
    """Generate Azure VM persistence attack trace.

    Attack Flow:
    1. Compromise VM via exposed management port
    2. Deploy custom script extension for persistence
    3. Create managed identity with elevated privileges
    4. Lateral movement to other VMs via Azure Bastion
    5. Establish C2 via Azure Functions

    MITRE ATT&CK Techniques:
    - T1078.004: Valid Accounts: Cloud Accounts
    - T1098.001: Account Manipulation: Additional Cloud Credentials
    - T1525: Implant Internal Image
    - T1021.007: Remote Services: Cloud Services
    """

    def __init__(self, attacker_ip: str = "198.51.100.78"):
        self.attacker_ip = attacker_ip
        self.attacker_principal = "compromised-vm-identity@contoso.com"
        self.target_vm = "prod-web-vm-01"
        self.target_resource_group = "rg-production"

    def generate(self, duration_hours: int = 4) -> List[Dict[str, Any]]:
        """Generate Azure compute persistence event trace.

        Args:
            duration_hours: Duration of attack in hours

        Returns:
            List of security events
        """
        events = []
        start_time = datetime.now()

        # Phase 1: Initial access (0-30 minutes)
        events.extend(self._generate_initial_access(start_time))

        # Phase 2: Establish persistence (30 min - 1.5 hours)
        events.extend(self._generate_persistence(
            start_time + timedelta(minutes=30)
        ))

        # Phase 3: Privilege escalation (1.5-2.5 hours)
        events.extend(self._generate_privilege_escalation(
            start_time + timedelta(hours=1, minutes=30)
        ))

        # Phase 4: Lateral movement (2.5-4 hours)
        events.extend(self._generate_lateral_movement(
            start_time + timedelta(hours=2, minutes=30)
        ))

        return events

    def _generate_initial_access(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate initial access events."""
        events = []

        # SSH brute force attempts (failed)
        for i in range(15):
            events.append({
                "timestamp": (start_time + timedelta(minutes=i)).isoformat(),
                "event_type": "azure.compute.ssh_login",
                "action": "Microsoft.Compute/virtualMachines/login/action",
                "principal": f"attacker-attempt-{i}",
                "resource": f"/subscriptions/sub-12345/resourceGroups/{self.target_resource_group}/providers/Microsoft.Compute/virtualMachines/{self.target_vm}",
                "status": "failed",
                "source_ip": self.attacker_ip,
                "region": "eastus",
                "cloud_provider": "azure",
                "severity": "medium",
                "mitre_techniques": ["T1110.001"],
                "metadata": {
                    "vm_name": self.target_vm,
                    "authentication_method": "ssh_key",
                    "error": "AuthenticationFailed"
                }
            })

        # Successful login via exposed management port
        events.append({
            "timestamp": (start_time + timedelta(minutes=20)).isoformat(),
            "event_type": "azure.compute.ssh_login",
            "action": "Microsoft.Compute/virtualMachines/login/action",
            "principal": "admin",
            "resource": f"/subscriptions/sub-12345/resourceGroups/{self.target_resource_group}/providers/Microsoft.Compute/virtualMachines/{self.target_vm}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "high",
            "mitre_techniques": ["T1078.004"],
            "metadata": {
                "vm_name": self.target_vm,
                "authentication_method": "password",
                "vm_size": "Standard_D4s_v3",
                "unusual_login_location": True
            }
        })

        # Reconnaissance commands on VM
        events.append({
            "timestamp": (start_time + timedelta(minutes=25)).isoformat(),
            "event_type": "azure.compute.run_command",
            "action": "Microsoft.Compute/virtualMachines/runCommand/action",
            "principal": self.attacker_principal,
            "resource": f"{self.target_vm}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "medium",
            "mitre_techniques": ["T1059.004"],
            "metadata": {
                "command": "whoami && az account show && az vm list",
                "command_id": "RunShellScript"
            }
        })

        return events

    def _generate_persistence(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate persistence mechanism events."""
        events = []

        # Deploy custom script extension (backdoor)
        events.append({
            "timestamp": start_time.isoformat(),
            "event_type": "azure.compute.create_extension",
            "action": "Microsoft.Compute/virtualMachines/extensions/write",
            "principal": self.attacker_principal,
            "resource": f"{self.target_vm}/extensions/backdoor-script",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "critical",
            "mitre_techniques": ["T1505.003"],
            "metadata": {
                "extension_name": "CustomScriptExtension",
                "publisher": "Microsoft.Azure.Extensions",
                "script_url": "https://attacker-storage.blob.core.windows.net/scripts/persist.sh",
                "script_hash": "a1b2c3d4e5f6...",
                "auto_upgrade": True
            }
        })

        # Create scheduled task for persistence
        events.append({
            "timestamp": (start_time + timedelta(minutes=10)).isoformat(),
            "event_type": "azure.compute.run_command",
            "action": "Microsoft.Compute/virtualMachines/runCommand/action",
            "principal": self.attacker_principal,
            "resource": f"{self.target_vm}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "high",
            "mitre_techniques": ["T1053.005"],
            "metadata": {
                "command": "crontab -e && echo '*/10 * * * * /tmp/beacon.sh' >> /var/spool/cron/root",
                "command_id": "RunShellScript"
            }
        })

        # Modify VM configuration
        events.append({
            "timestamp": (start_time + timedelta(minutes=20)).isoformat(),
            "event_type": "azure.compute.update_vm",
            "action": "Microsoft.Compute/virtualMachines/write",
            "principal": self.attacker_principal,
            "resource": f"{self.target_vm}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "high",
            "mitre_techniques": ["T1578.002"],
            "metadata": {
                "changes": ["disable_boot_diagnostics", "add_nsg_rule"],
                "nsg_rule": "allow_inbound_4444"
            }
        })

        # Create custom VM image with backdoor
        events.append({
            "timestamp": (start_time + timedelta(minutes=40)).isoformat(),
            "event_type": "azure.compute.create_image",
            "action": "Microsoft.Compute/images/write",
            "principal": self.attacker_principal,
            "resource": "/subscriptions/sub-12345/resourceGroups/rg-production/providers/Microsoft.Compute/images/backdoored-image",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "critical",
            "mitre_techniques": ["T1525"],
            "metadata": {
                "source_vm": self.target_vm,
                "image_name": "ubuntu-22.04-backdoored",
                "os_type": "Linux"
            }
        })

        return events

    def _generate_privilege_escalation(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate privilege escalation events."""
        events = []

        # Create managed identity
        events.append({
            "timestamp": start_time.isoformat(),
            "event_type": "azure.identity.create_managed_identity",
            "action": "Microsoft.ManagedIdentity/userAssignedIdentities/write",
            "principal": self.attacker_principal,
            "resource": "/subscriptions/sub-12345/resourceGroups/rg-production/providers/Microsoft.ManagedIdentity/userAssignedIdentities/elevated-identity",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "high",
            "mitre_techniques": ["T1098.001"],
            "metadata": {
                "identity_name": "elevated-identity",
                "principal_id": "12345-abcde-67890-fghij"
            }
        })

        # Assign Contributor role to managed identity
        events.append({
            "timestamp": (start_time + timedelta(minutes=5)).isoformat(),
            "event_type": "azure.authorization.create_role_assignment",
            "action": "Microsoft.Authorization/roleAssignments/write",
            "principal": self.attacker_principal,
            "resource": "/subscriptions/sub-12345",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "critical",
            "mitre_techniques": ["T1098.003"],
            "metadata": {
                "role_definition": "Contributor",
                "principal_id": "12345-abcde-67890-fghij",
                "scope": "subscription"
            }
        })

        # Attach managed identity to compromised VM
        events.append({
            "timestamp": (start_time + timedelta(minutes=15)).isoformat(),
            "event_type": "azure.compute.assign_identity",
            "action": "Microsoft.Compute/virtualMachines/write",
            "principal": self.attacker_principal,
            "resource": f"{self.target_vm}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "critical",
            "mitre_techniques": ["T1098.001"],
            "metadata": {
                "identity_type": "UserAssigned",
                "identity_id": "elevated-identity",
                "previous_identity": "system-assigned"
            }
        })

        # Use elevated identity to access Key Vault
        events.append({
            "timestamp": (start_time + timedelta(minutes=25)).isoformat(),
            "event_type": "azure.keyvault.get_secret",
            "action": "Microsoft.KeyVault/vaults/secrets/read",
            "principal": "elevated-identity",
            "resource": "/subscriptions/sub-12345/resourceGroups/rg-production/providers/Microsoft.KeyVault/vaults/prod-keyvault/secrets/database-password",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "critical",
            "mitre_techniques": ["T1552.001"],
            "metadata": {
                "secret_name": "database-password",
                "secret_version": "current",
                "vault_name": "prod-keyvault"
            }
        })

        return events

    def _generate_lateral_movement(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate lateral movement events."""
        events = []

        target_vms = ["prod-web-vm-02", "prod-app-vm-01", "prod-db-vm-01"]

        for i, target in enumerate(target_vms):
            offset = timedelta(minutes=i * 20)

            # Use Azure Bastion for lateral movement
            events.append({
                "timestamp": (start_time + offset).isoformat(),
                "event_type": "azure.bastion.connect",
                "action": "Microsoft.Network/bastionHosts/connect/action",
                "principal": self.attacker_principal,
                "resource": f"/subscriptions/sub-12345/resourceGroups/{self.target_resource_group}/providers/Microsoft.Compute/virtualMachines/{target}",
                "status": "success",
                "source_ip": self.attacker_ip,
                "region": "eastus",
                "cloud_provider": "azure",
                "severity": "high",
                "mitre_techniques": ["T1021.007"],
                "metadata": {
                    "target_vm": target,
                    "bastion_host": "prod-bastion",
                    "connection_type": "RDP"
                }
            })

            # Deploy extension on lateral target
            events.append({
                "timestamp": (start_time + offset + timedelta(minutes=5)).isoformat(),
                "event_type": "azure.compute.create_extension",
                "action": "Microsoft.Compute/virtualMachines/extensions/write",
                "principal": self.attacker_principal,
                "resource": f"{target}/extensions/backdoor-script",
                "status": "success",
                "source_ip": self.attacker_ip,
                "region": "eastus",
                "cloud_provider": "azure",
                "severity": "critical",
                "mitre_techniques": ["T1505.003"],
                "metadata": {
                    "extension_name": "CustomScriptExtension",
                    "target_vm": target
                }
            })

        # Create Azure Function for C2
        events.append({
            "timestamp": (start_time + timedelta(hours=1)).isoformat(),
            "event_type": "azure.functions.create_function",
            "action": "Microsoft.Web/sites/functions/write",
            "principal": self.attacker_principal,
            "resource": "/subscriptions/sub-12345/resourceGroups/rg-production/providers/Microsoft.Web/sites/c2-function-app/functions/beacon",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "critical",
            "mitre_techniques": ["T1071.001"],
            "metadata": {
                "function_name": "beacon",
                "runtime": "python",
                "trigger_type": "http",
                "function_url": "https://c2-function-app.azurewebsites.net/api/beacon"
            }
        })

        return events
