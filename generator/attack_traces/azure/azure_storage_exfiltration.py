"""Azure Storage data exfiltration scenario."""
from typing import List, Dict, Any
from datetime import datetime, timedelta
import random

class AzureStorageExfiltrationGenerator:
    """Generate Azure Blob Storage data exfiltration attack trace.

    Attack Flow:
    1. Initial reconnaissance - list storage accounts
    2. Enumerate containers and blobs
    3. Grant public access to container
    4. Exfiltrate sensitive data via bulk downloads
    5. Cover tracks by reverting permissions

    MITRE ATT&CK Techniques:
    - T1530: Data from Cloud Storage Object
    - T1537: Transfer Data to Cloud Account
    - T1562.008: Impair Defenses: Disable Cloud Logs
    """

    def __init__(self, attacker_ip: str = "203.0.113.45"):
        self.attacker_ip = attacker_ip
        self.attacker_principal = "compromised-app@contoso.com"
        self.target_storage = "contosofinance"
        self.target_container = "financial-reports"

    def generate(self, duration_hours: int = 3) -> List[Dict[str, Any]]:
        """Generate Azure storage exfiltration event trace.

        Args:
            duration_hours: Duration of attack in hours

        Returns:
            List of security events representing the attack
        """
        events = []
        start_time = datetime.now()

        # Phase 1: Reconnaissance (0-30 minutes)
        events.extend(self._generate_reconnaissance(start_time))

        # Phase 2: Permission modification (30-60 minutes)
        events.extend(self._generate_permission_change(
            start_time + timedelta(minutes=35)
        ))

        # Phase 3: Data exfiltration (1-2.5 hours)
        events.extend(self._generate_exfiltration(
            start_time + timedelta(hours=1)
        ))

        # Phase 4: Cover tracks (2.5-3 hours)
        events.extend(self._generate_cleanup(
            start_time + timedelta(hours=2, minutes=30)
        ))

        return events

    def _generate_reconnaissance(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate reconnaissance events."""
        events = []

        # List storage accounts
        events.append({
            "timestamp": start_time.isoformat(),
            "event_type": "azure.storage.list_accounts",
            "action": "Microsoft.Storage/storageAccounts/listAccountSas/action",
            "principal": self.attacker_principal,
            "resource": f"/subscriptions/sub-12345/providers/Microsoft.Storage",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "low",
            "mitre_techniques": ["T1526"],
            "metadata": {
                "user_agent": "Azure-CLI/2.45.0",
                "subscription_id": "sub-12345",
                "resource_group": "rg-finance"
            }
        })

        # Enumerate containers
        for i in range(5):
            events.append({
                "timestamp": (start_time + timedelta(minutes=i*3)).isoformat(),
                "event_type": "azure.storage.list_containers",
                "action": "Microsoft.Storage/storageAccounts/blobServices/containers/list",
                "principal": self.attacker_principal,
                "resource": f"/subscriptions/sub-12345/resourceGroups/rg-finance/providers/Microsoft.Storage/storageAccounts/{self.target_storage}",
                "status": "success",
                "source_ip": self.attacker_ip,
                "region": "eastus",
                "cloud_provider": "azure",
                "severity": "low",
                "mitre_techniques": ["T1530"],
                "metadata": {
                    "storage_account": self.target_storage,
                    "container_count": 12
                }
            })

        # List blobs in target container
        events.append({
            "timestamp": (start_time + timedelta(minutes=20)).isoformat(),
            "event_type": "azure.storage.list_blobs",
            "action": "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/list",
            "principal": self.attacker_principal,
            "resource": f"{self.target_storage}/{self.target_container}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "medium",
            "mitre_techniques": ["T1530"],
            "metadata": {
                "container": self.target_container,
                "blob_count": 847,
                "total_size_gb": 125
            }
        })

        return events

    def _generate_permission_change(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate permission modification events."""
        events = []

        # Change container ACL to allow public access
        events.append({
            "timestamp": start_time.isoformat(),
            "event_type": "azure.storage.set_container_acl",
            "action": "Microsoft.Storage/storageAccounts/blobServices/containers/setAcl",
            "principal": self.attacker_principal,
            "resource": f"{self.target_storage}/{self.target_container}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "high",
            "mitre_techniques": ["T1222.002"],
            "metadata": {
                "old_access_level": "private",
                "new_access_level": "blob",
                "public_access_enabled": True
            }
        })

        # Generate SAS token with full permissions
        events.append({
            "timestamp": (start_time + timedelta(minutes=5)).isoformat(),
            "event_type": "azure.storage.generate_sas_token",
            "action": "Microsoft.Storage/storageAccounts/listAccountSas/action",
            "principal": self.attacker_principal,
            "resource": f"{self.target_storage}/{self.target_container}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "high",
            "mitre_techniques": ["T1528"],
            "metadata": {
                "permissions": "rwdl",
                "expiry": "2024-12-31T23:59:59Z",
                "token_type": "account_sas"
            }
        })

        return events

    def _generate_exfiltration(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate data exfiltration events."""
        events = []

        sensitive_files = [
            "financial-reports-2024-Q1.xlsx",
            "salary-data-executive.csv",
            "customer-payment-info.db",
            "merger-acquisition-plans.pdf",
            "trade-secrets-formulas.zip",
            "employee-ssn-data.csv",
            "audit-internal-controls.docx"
        ]

        # Bulk download of sensitive files
        for i, filename in enumerate(sensitive_files * 20):  # Download each file 20 times
            download_time = start_time + timedelta(minutes=i*2)

            events.append({
                "timestamp": download_time.isoformat(),
                "event_type": "azure.storage.get_blob",
                "action": "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
                "principal": self.attacker_principal,
                "resource": f"{self.target_storage}/{self.target_container}/{filename}",
                "status": "success",
                "source_ip": self.attacker_ip,
                "region": "eastus",
                "cloud_provider": "azure",
                "severity": "critical",
                "mitre_techniques": ["T1530", "T1537"],
                "metadata": {
                    "blob_name": filename,
                    "blob_size_mb": random.randint(10, 500),
                    "transfer_speed_mbps": random.randint(50, 200),
                    "authentication": "SAS_token"
                }
            })

        # Copy blobs to external storage account
        events.append({
            "timestamp": (start_time + timedelta(hours=1)).isoformat(),
            "event_type": "azure.storage.copy_blob",
            "action": "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/copy",
            "principal": self.attacker_principal,
            "resource": f"{self.target_storage}/{self.target_container}/*",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "critical",
            "mitre_techniques": ["T1537"],
            "metadata": {
                "destination_account": "attacker-exfil-storage",
                "destination_container": "stolen-data",
                "blob_count": 847,
                "total_size_gb": 125
            }
        })

        return events

    def _generate_cleanup(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate cleanup/anti-forensics events."""
        events = []

        # Revert container ACL to private
        events.append({
            "timestamp": start_time.isoformat(),
            "event_type": "azure.storage.set_container_acl",
            "action": "Microsoft.Storage/storageAccounts/blobServices/containers/setAcl",
            "principal": self.attacker_principal,
            "resource": f"{self.target_storage}/{self.target_container}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "medium",
            "mitre_techniques": ["T1070"],
            "metadata": {
                "old_access_level": "blob",
                "new_access_level": "private",
                "public_access_enabled": False
            }
        })

        # Attempt to disable storage logging
        events.append({
            "timestamp": (start_time + timedelta(minutes=5)).isoformat(),
            "event_type": "azure.storage.set_service_properties",
            "action": "Microsoft.Storage/storageAccounts/blobServices/setServiceProperties",
            "principal": self.attacker_principal,
            "resource": f"{self.target_storage}",
            "status": "failed",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "high",
            "mitre_techniques": ["T1562.008"],
            "metadata": {
                "attempted_change": "disable_logging",
                "error": "InsufficientPermissions"
            }
        })

        # Delete activity logs (attempt)
        events.append({
            "timestamp": (start_time + timedelta(minutes=10)).isoformat(),
            "event_type": "azure.monitor.delete_diagnostic_settings",
            "action": "Microsoft.Insights/diagnosticSettings/delete",
            "principal": self.attacker_principal,
            "resource": f"{self.target_storage}",
            "status": "failed",
            "source_ip": self.attacker_ip,
            "region": "eastus",
            "cloud_provider": "azure",
            "severity": "critical",
            "mitre_techniques": ["T1562.008"],
            "metadata": {
                "error": "InsufficientPermissions",
                "required_role": "Monitoring Contributor"
            }
        })

        return events
