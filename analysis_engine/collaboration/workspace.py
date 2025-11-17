"""Collaboration workspace for team exercises."""
from typing import Dict, List, Set
from dataclasses import dataclass
from enum import Enum

class UserRole(str, Enum):
    """User roles in collaboration."""
    RED_TEAM = "red_team"
    BLUE_TEAM = "blue_team"
    PURPLE_TEAM = "purple_team"
    OBSERVER = "observer"

@dataclass
class CollaborationWorkspace:
    """Shared workspace for team collaboration."""
    workspace_id: str
    name: str
    members: Dict[str, UserRole]
    scenarios: List[str]
    shared_annotations: List[Dict]
    
    def add_member(self, user_id: str, role: UserRole):
        """Add team member."""
        self.members[user_id] = role
    
    def add_annotation(self, user_id: str, event_id: str, note: str):
        """Add annotation to event."""
        self.shared_annotations.append({
            "user_id": user_id,
            "event_id": event_id,
            "note": note,
            "timestamp": datetime.now().isoformat()
        })
