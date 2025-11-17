"""GCP attack scenarios for multi-cloud support."""
from .gcp_iam_escalation import GCPIAMEscalationGenerator
from .gcp_storage_exfiltration import GCPStorageExfiltrationGenerator
from .gcp_gke_escape import GCPGKEEscapeGenerator

__all__ = [
    'GCPIAMEscalationGenerator',
    'GCPStorageExfiltrationGenerator',
    'GCPGKEEscapeGenerator'
]
