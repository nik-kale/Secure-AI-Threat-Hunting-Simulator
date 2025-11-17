"""Multi-tenancy support for enterprise."""
from typing import Dict, List, Set
from dataclasses import dataclass

@dataclass
class Tenant:
    """Multi-tenant organization."""
    tenant_id: str
    name: str
    users: Set[str]
    quota_events_per_day: int
    enabled_features: Set[str]

class TenantManager:
    """Manage multi-tenant deployments."""
    
    def __init__(self):
        self.tenants: Dict[str, Tenant] = {}
    
    def create_tenant(self, tenant_id: str, name: str) -> Tenant:
        """Create new tenant."""
        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            users=set(),
            quota_events_per_day=100000,
            enabled_features={'anomaly_detection', 'threat_hunting'}
        )
        self.tenants[tenant_id] = tenant
        return tenant
    
    def get_tenant(self, tenant_id: str) -> Tenant:
        """Get tenant by ID."""
        return self.tenants.get(tenant_id)
    
    def check_quota(self, tenant_id: str, event_count: int) -> bool:
        """Check if tenant within quota."""
        tenant = self.tenants.get(tenant_id)
        return tenant and event_count <= tenant.quota_events_per_day
