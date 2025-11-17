"""GCP IAM privilege escalation scenario - v4.0 Multi-Cloud Support."""
from typing import List, Dict, Any
from datetime import datetime, timedelta
import random

class GCPIAMEscalationGenerator:
    """Generates GCP IAM privilege escalation telemetry."""
    
    def __init__(self, project_id: str = "gcp-project-001"):
        self.project_id = project_id
    
    def generate(self, duration_hours: int = 2) -> List[Dict[str, Any]]:
        """Generate GCP attack telemetry."""
        events = []
        base_time = datetime.now()
        
        # Phase 1: Reconnaissance
        events.append({
            "timestamp": base_time.isoformat(),
            "event_type": "gcp.iam.listServiceAccounts",
            "action": "list",
            "principal": "user@example.com",
            "resource": f"projects/{self.project_id}/serviceAccounts",
            "status": "success",
            "cloud_provider": "gcp",
            "metadata": {
                "mitre_techniques": ["T1087.004"],
                "kill_chain_stage": "reconnaissance"
            }
        })
        
        # Phase 2: Privilege escalation  
        base_time += timedelta(minutes=20)
        events.append({
            "timestamp": base_time.isoformat(),
            "event_type": "gcp.iam.setIamPolicy",
            "action": "setIamPolicy",
            "principal": "user@example.com",
            "resource": f"projects/{self.project_id}",
            "status": "success",
            "cloud_provider": "gcp",
            "metadata": {
                "suspicious": True,
                "mitre_techniques": ["T1078.004", "T1098"],
                "kill_chain_stage": "privilege_escalation"
            }
        })
        
        # Phase 3: Lateral movement
        base_time += timedelta(minutes=10)
        events.append({
            "timestamp": base_time.isoformat(),
            "event_type": "gcp.compute.instances.get",
            "action": "get",
            "principal": "user@example.com",
            "resource": f"projects/{self.project_id}/zones/us-central1-a/instances/prod-instance",
            "status": "success",
            "cloud_provider": "gcp",
            "metadata": {
                "suspicious": True,
                "mitre_techniques": ["T1078"],
                "kill_chain_stage": "lateral_movement"
            }
        })
        
        return events

if __name__ == "__main__":
    generator = GCPIAMEscalationGenerator()
    events = generator.generate()
    print(f"Generated {len(events)} GCP events")
