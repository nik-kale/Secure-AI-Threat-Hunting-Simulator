"""GCP Cloud Storage data exfiltration scenario."""
from typing import List, Dict, Any
from datetime import datetime, timedelta
import random

class GCPStorageExfiltrationGenerator:
    """Generate GCP Cloud Storage data exfiltration attack trace.

    Attack Flow:
    1. Enumerate storage buckets and objects
    2. Modify bucket IAM to allow external access
    3. Exfiltrate sensitive data via bulk downloads
    4. Transfer data to external bucket
    5. Attempt to cover tracks

    MITRE ATT&CK Techniques:
    - T1530: Data from Cloud Storage Object
    - T1537: Transfer Data to Cloud Account
    - T1213: Data from Information Repositories
    - T1562.008: Impair Defenses: Disable Cloud Logs
    """

    def __init__(self, attacker_ip: str = "185.220.101.45"):
        self.attacker_ip = attacker_ip
        self.attacker_principal = "compromised-sa@project.iam.gserviceaccount.com"
        self.target_bucket = "corporate-sensitive-data"
        self.project_id = "production-project-12345"

    def generate(self, duration_hours: int = 3) -> List[Dict[str, Any]]:
        """Generate GCP storage exfiltration event trace.

        Args:
            duration_hours: Duration of attack in hours

        Returns:
            List of security events
        """
        events = []
        start_time = datetime.now()

        # Phase 1: Discovery (0-30 minutes)
        events.extend(self._generate_discovery(start_time))

        # Phase 2: Permission modification (30-60 minutes)
        events.extend(self._generate_permission_change(
            start_time + timedelta(minutes=30)
        ))

        # Phase 3: Data exfiltration (1-2.5 hours)
        events.extend(self._generate_exfiltration(
            start_time + timedelta(hours=1)
        ))

        # Phase 4: Anti-forensics (2.5-3 hours)
        events.extend(self._generate_anti_forensics(
            start_time + timedelta(hours=2, minutes=30)
        ))

        return events

    def _generate_discovery(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate discovery phase events."""
        events = []

        # List all buckets
        events.append({
            "timestamp": start_time.isoformat(),
            "event_type": "gcp.storage.buckets.list",
            "action": "storage.buckets.list",
            "principal": self.attacker_principal,
            "resource": f"projects/{self.project_id}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "low",
            "mitre_techniques": ["T1526"],
            "metadata": {
                "project_id": self.project_id,
                "bucket_count": 27,
                "method": "storage.googleapis.com/buckets.list"
            }
        })

        # Get bucket metadata for sensitive bucket
        events.append({
            "timestamp": (start_time + timedelta(minutes=5)).isoformat(),
            "event_type": "gcp.storage.buckets.get",
            "action": "storage.buckets.get",
            "principal": self.attacker_principal,
            "resource": f"projects/{self.project_id}/buckets/{self.target_bucket}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "low",
            "mitre_techniques": ["T1530"],
            "metadata": {
                "bucket_name": self.target_bucket,
                "storage_class": "STANDARD",
                "location": "US",
                "versioning_enabled": True
            }
        })

        # List objects in bucket
        for i in range(8):
            events.append({
                "timestamp": (start_time + timedelta(minutes=10+i*2)).isoformat(),
                "event_type": "gcp.storage.objects.list",
                "action": "storage.objects.list",
                "principal": self.attacker_principal,
                "resource": f"{self.target_bucket}",
                "status": "success",
                "source_ip": self.attacker_ip,
                "region": "us-central1",
                "cloud_provider": "gcp",
                "severity": "medium",
                "mitre_techniques": ["T1530"],
                "metadata": {
                    "bucket": self.target_bucket,
                    "prefix": f"sensitive-data-{i}/",
                    "object_count": random.randint(50, 200)
                }
            })

        # Get IAM policy to understand permissions
        events.append({
            "timestamp": (start_time + timedelta(minutes=25)).isoformat(),
            "event_type": "gcp.storage.buckets.getIamPolicy",
            "action": "storage.buckets.getIamPolicy",
            "principal": self.attacker_principal,
            "resource": f"{self.target_bucket}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "medium",
            "mitre_techniques": ["T1069.003"],
            "metadata": {
                "bucket": self.target_bucket,
                "bindings_count": 5
            }
        })

        return events

    def _generate_permission_change(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate permission modification events."""
        events = []

        # Modify bucket IAM policy to allow public access
        events.append({
            "timestamp": start_time.isoformat(),
            "event_type": "gcp.storage.buckets.setIamPolicy",
            "action": "storage.buckets.setIamPolicy",
            "principal": self.attacker_principal,
            "resource": f"{self.target_bucket}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1222.002"],
            "metadata": {
                "bucket": self.target_bucket,
                "added_bindings": [
                    {"role": "roles/storage.objectViewer", "member": "allUsers"}
                ],
                "public_access_enabled": True
            }
        })

        # Create service account key for persistence
        events.append({
            "timestamp": (start_time + timedelta(minutes=10)).isoformat(),
            "event_type": "gcp.iam.serviceAccountKeys.create",
            "action": "google.iam.admin.v1.CreateServiceAccountKey",
            "principal": self.attacker_principal,
            "resource": f"projects/{self.project_id}/serviceAccounts/{self.attacker_principal}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "high",
            "mitre_techniques": ["T1098.001"],
            "metadata": {
                "key_type": "USER_MANAGED",
                "key_algorithm": "KEY_ALG_RSA_2048",
                "service_account": self.attacker_principal
            }
        })

        # Disable uniform bucket-level access (to enable object-level ACLs)
        events.append({
            "timestamp": (start_time + timedelta(minutes=15)).isoformat(),
            "event_type": "gcp.storage.buckets.update",
            "action": "storage.buckets.update",
            "principal": self.attacker_principal,
            "resource": f"{self.target_bucket}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "high",
            "mitre_techniques": ["T1222.002"],
            "metadata": {
                "bucket": self.target_bucket,
                "uniform_bucket_level_access": False,
                "previous_value": True
            }
        })

        return events

    def _generate_exfiltration(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate data exfiltration events."""
        events = []

        sensitive_objects = [
            "financial/quarterly-reports-2024.xlsx",
            "hr/employee-salaries.csv",
            "legal/merger-agreements.pdf",
            "engineering/source-code-backup.tar.gz",
            "customers/payment-card-data.db",
            "security/api-keys-production.json",
            "research/proprietary-algorithms.zip"
        ]

        # Bulk object downloads
        for i, obj in enumerate(sensitive_objects * 30):  # Download each 30 times
            download_time = start_time + timedelta(minutes=i)

            events.append({
                "timestamp": download_time.isoformat(),
                "event_type": "gcp.storage.objects.get",
                "action": "storage.objects.get",
                "principal": self.attacker_principal,
                "resource": f"{self.target_bucket}/{obj}",
                "status": "success",
                "source_ip": self.attacker_ip,
                "region": "us-central1",
                "cloud_provider": "gcp",
                "severity": "critical",
                "mitre_techniques": ["T1530"],
                "metadata": {
                    "bucket": self.target_bucket,
                    "object": obj,
                    "object_size_mb": random.randint(5, 500),
                    "generation": random.randint(1, 10)
                }
            })

        # Copy objects to external bucket
        events.append({
            "timestamp": (start_time + timedelta(hours=1)).isoformat(),
            "event_type": "gcp.storage.objects.copy",
            "action": "storage.objects.copy",
            "principal": self.attacker_principal,
            "resource": f"{self.target_bucket}/*",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1537"],
            "metadata": {
                "source_bucket": self.target_bucket,
                "destination_bucket": "attacker-exfil-bucket-external",
                "destination_project": "attacker-project-99999",
                "object_count": 2100,
                "total_size_gb": 340
            }
        })

        # Upload to external cloud provider via signed URL
        events.append({
            "timestamp": (start_time + timedelta(hours=1, minutes=20)).isoformat(),
            "event_type": "gcp.storage.objects.generateSignedUrl",
            "action": "storage.objects.generateSignedUrl",
            "principal": self.attacker_principal,
            "resource": f"{self.target_bucket}/*",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "high",
            "mitre_techniques": ["T1567.002"],
            "metadata": {
                "bucket": self.target_bucket,
                "url_expiration": "2024-12-31T23:59:59Z",
                "http_method": "GET",
                "signed_url_count": 2100
            }
        })

        return events

    def _generate_anti_forensics(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate anti-forensics events."""
        events = []

        # Revert bucket IAM policy
        events.append({
            "timestamp": start_time.isoformat(),
            "event_type": "gcp.storage.buckets.setIamPolicy",
            "action": "storage.buckets.setIamPolicy",
            "principal": self.attacker_principal,
            "resource": f"{self.target_bucket}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "high",
            "mitre_techniques": ["T1070"],
            "metadata": {
                "bucket": self.target_bucket,
                "removed_bindings": [
                    {"role": "roles/storage.objectViewer", "member": "allUsers"}
                ],
                "public_access_enabled": False
            }
        })

        # Attempt to disable bucket logging
        events.append({
            "timestamp": (start_time + timedelta(minutes=5)).isoformat(),
            "event_type": "gcp.storage.buckets.update",
            "action": "storage.buckets.update",
            "principal": self.attacker_principal,
            "resource": f"{self.target_bucket}",
            "status": "failed",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1562.008"],
            "metadata": {
                "bucket": self.target_bucket,
                "attempted_change": "disable_logging",
                "error": "PERMISSION_DENIED",
                "error_message": "Caller does not have storage.buckets.update permission"
            }
        })

        # Delete service account key
        events.append({
            "timestamp": (start_time + timedelta(minutes=10)).isoformat(),
            "event_type": "gcp.iam.serviceAccountKeys.delete",
            "action": "google.iam.admin.v1.DeleteServiceAccountKey",
            "principal": self.attacker_principal,
            "resource": f"projects/{self.project_id}/serviceAccounts/{self.attacker_principal}/keys/exfil-key-12345",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "medium",
            "mitre_techniques": ["T1070.004"],
            "metadata": {
                "key_id": "exfil-key-12345",
                "service_account": self.attacker_principal
            }
        })

        # Attempt to delete audit logs sink
        events.append({
            "timestamp": (start_time + timedelta(minutes=15)).isoformat(),
            "event_type": "gcp.logging.sinks.delete",
            "action": "google.logging.v2.ConfigServiceV2.DeleteSink",
            "principal": self.attacker_principal,
            "resource": f"projects/{self.project_id}/sinks/audit-logs-sink",
            "status": "failed",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1562.008"],
            "metadata": {
                "sink_name": "audit-logs-sink",
                "error": "PERMISSION_DENIED",
                "required_permission": "logging.sinks.delete"
            }
        })

        return events
