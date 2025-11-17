"""Azure attack scenarios for multi-cloud support."""
from .azure_iam_escalation import AzureIAMEscalationGenerator
from .azure_storage_exfiltration import AzureStorageExfiltrationGenerator
from .azure_compute_persistence import AzureComputePersistenceGenerator

__all__ = [
    'AzureIAMEscalationGenerator',
    'AzureStorageExfiltrationGenerator',
    'AzureComputePersistenceGenerator'
]
