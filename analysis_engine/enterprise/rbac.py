"""Advanced Role-Based Access Control (RBAC) for enterprise."""
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

class Permission(str, Enum):
    """Granular system permissions."""
    # Event permissions
    VIEW_EVENTS = "view_events"
    EXPORT_EVENTS = "export_events"
    DELETE_EVENTS = "delete_events"

    # Detection permissions
    VIEW_DETECTIONS = "view_detections"
    CREATE_DETECTIONS = "create_detections"
    MODIFY_DETECTIONS = "modify_detections"
    DELETE_DETECTIONS = "delete_detections"

    # User management
    VIEW_USERS = "view_users"
    CREATE_USERS = "create_users"
    MODIFY_USERS = "modify_users"
    DELETE_USERS = "delete_users"

    # Role management
    VIEW_ROLES = "view_roles"
    ASSIGN_ROLES = "assign_roles"
    CREATE_ROLES = "create_roles"
    MODIFY_ROLES = "modify_roles"

    # Exercise permissions
    VIEW_EXERCISES = "view_exercises"
    CREATE_EXERCISES = "create_exercises"
    PARTICIPATE_EXERCISES = "participate_exercises"
    MANAGE_EXERCISES = "manage_exercises"

    # Tenant management
    VIEW_TENANTS = "view_tenants"
    CREATE_TENANTS = "create_tenants"
    MODIFY_TENANTS = "modify_tenants"
    DELETE_TENANTS = "delete_tenants"

    # Audit permissions
    VIEW_AUDIT_LOGS = "view_audit_logs"
    EXPORT_AUDIT_LOGS = "export_audit_logs"

    # Compliance permissions
    VIEW_COMPLIANCE = "view_compliance"
    ASSESS_COMPLIANCE = "assess_compliance"

    # SIEM integration
    CONFIGURE_SIEM = "configure_siem"
    EXPORT_TO_SIEM = "export_to_siem"

    # System configuration
    CONFIGURE_SYSTEM = "configure_system"
    VIEW_SYSTEM_HEALTH = "view_system_health"

@dataclass
class Role:
    """Role with assigned permissions."""
    role_id: str
    name: str
    description: str
    permissions: Set[Permission]
    is_system_role: bool = False  # System roles can't be deleted
    created_at: datetime = field(default_factory=datetime.now)
    modified_at: datetime = field(default_factory=datetime.now)

@dataclass
class RoleAssignment:
    """Assignment of role to user."""
    assignment_id: str
    user_id: str
    role_id: str
    tenant_id: Optional[str] = None  # Scope assignment to tenant
    assigned_by: str = ""
    assigned_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None

class RBACManager:
    """Advanced Role-Based Access Control manager."""

    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self.assignments: List[RoleAssignment] = []
        self._load_system_roles()

    def _load_system_roles(self):
        """Load predefined system roles."""
        system_roles = [
            Role(
                role_id="super_admin",
                name="Super Administrator",
                description="Full system access across all tenants",
                permissions=set(Permission),  # All permissions
                is_system_role=True
            ),
            Role(
                role_id="tenant_admin",
                name="Tenant Administrator",
                description="Full access within assigned tenant",
                permissions={
                    Permission.VIEW_EVENTS,
                    Permission.EXPORT_EVENTS,
                    Permission.VIEW_DETECTIONS,
                    Permission.CREATE_DETECTIONS,
                    Permission.MODIFY_DETECTIONS,
                    Permission.DELETE_DETECTIONS,
                    Permission.VIEW_USERS,
                    Permission.CREATE_USERS,
                    Permission.MODIFY_USERS,
                    Permission.VIEW_ROLES,
                    Permission.ASSIGN_ROLES,
                    Permission.VIEW_EXERCISES,
                    Permission.CREATE_EXERCISES,
                    Permission.PARTICIPATE_EXERCISES,
                    Permission.MANAGE_EXERCISES,
                    Permission.VIEW_AUDIT_LOGS,
                    Permission.EXPORT_AUDIT_LOGS,
                    Permission.VIEW_COMPLIANCE,
                    Permission.CONFIGURE_SIEM,
                    Permission.EXPORT_TO_SIEM
                },
                is_system_role=True
            ),
            Role(
                role_id="security_analyst",
                name="Security Analyst",
                description="Analyze threats and create detections",
                permissions={
                    Permission.VIEW_EVENTS,
                    Permission.EXPORT_EVENTS,
                    Permission.VIEW_DETECTIONS,
                    Permission.CREATE_DETECTIONS,
                    Permission.VIEW_EXERCISES,
                    Permission.PARTICIPATE_EXERCISES,
                    Permission.VIEW_AUDIT_LOGS,
                    Permission.VIEW_COMPLIANCE
                },
                is_system_role=True
            ),
            Role(
                role_id="soc_operator",
                name="SOC Operator",
                description="Monitor and respond to security events",
                permissions={
                    Permission.VIEW_EVENTS,
                    Permission.VIEW_DETECTIONS,
                    Permission.VIEW_EXERCISES,
                    Permission.PARTICIPATE_EXERCISES,
                    Permission.VIEW_SYSTEM_HEALTH
                },
                is_system_role=True
            ),
            Role(
                role_id="red_team",
                name="Red Team Member",
                description="Participate in offensive security exercises",
                permissions={
                    Permission.VIEW_EVENTS,
                    Permission.VIEW_EXERCISES,
                    Permission.PARTICIPATE_EXERCISES
                },
                is_system_role=True
            ),
            Role(
                role_id="blue_team",
                name="Blue Team Member",
                description="Participate in defensive security exercises",
                permissions={
                    Permission.VIEW_EVENTS,
                    Permission.VIEW_DETECTIONS,
                    Permission.VIEW_EXERCISES,
                    Permission.PARTICIPATE_EXERCISES
                },
                is_system_role=True
            ),
            Role(
                role_id="purple_team",
                name="Purple Team Lead",
                description="Coordinate purple team exercises",
                permissions={
                    Permission.VIEW_EVENTS,
                    Permission.EXPORT_EVENTS,
                    Permission.VIEW_DETECTIONS,
                    Permission.CREATE_DETECTIONS,
                    Permission.VIEW_EXERCISES,
                    Permission.CREATE_EXERCISES,
                    Permission.PARTICIPATE_EXERCISES,
                    Permission.MANAGE_EXERCISES
                },
                is_system_role=True
            ),
            Role(
                role_id="compliance_auditor",
                name="Compliance Auditor",
                description="Review compliance and audit logs",
                permissions={
                    Permission.VIEW_AUDIT_LOGS,
                    Permission.EXPORT_AUDIT_LOGS,
                    Permission.VIEW_COMPLIANCE,
                    Permission.ASSESS_COMPLIANCE
                },
                is_system_role=True
            ),
            Role(
                role_id="read_only",
                name="Read-Only User",
                description="View-only access to events and detections",
                permissions={
                    Permission.VIEW_EVENTS,
                    Permission.VIEW_DETECTIONS,
                    Permission.VIEW_EXERCISES
                },
                is_system_role=True
            )
        ]

        for role in system_roles:
            self.roles[role.role_id] = role

    def create_role(
        self,
        role_id: str,
        name: str,
        description: str,
        permissions: Set[Permission]
    ) -> Role:
        """Create custom role.

        Args:
            role_id: Unique role identifier
            name: Role name
            description: Role description
            permissions: Set of permissions

        Returns:
            Created role

        Raises:
            ValueError: If role ID already exists
        """
        if role_id in self.roles:
            raise ValueError(f"Role already exists: {role_id}")

        role = Role(
            role_id=role_id,
            name=name,
            description=description,
            permissions=permissions,
            is_system_role=False
        )

        self.roles[role_id] = role
        return role

    def assign_role(
        self,
        user_id: str,
        role_id: str,
        assigned_by: str,
        tenant_id: Optional[str] = None,
        expires_in_days: Optional[int] = None
    ) -> RoleAssignment:
        """Assign role to user.

        Args:
            user_id: User to assign role to
            role_id: Role to assign
            assigned_by: User making the assignment
            tenant_id: Scope to specific tenant
            expires_in_days: Role expiration in days

        Returns:
            Role assignment

        Raises:
            ValueError: If role doesn't exist
        """
        if role_id not in self.roles:
            raise ValueError(f"Role not found: {role_id}")

        expires_at = None
        if expires_in_days:
            expires_at = datetime.now() + timedelta(days=expires_in_days)

        assignment = RoleAssignment(
            assignment_id=f"assign-{len(self.assignments):06d}",
            user_id=user_id,
            role_id=role_id,
            tenant_id=tenant_id,
            assigned_by=assigned_by,
            expires_at=expires_at
        )

        self.assignments.append(assignment)
        return assignment

    def revoke_role(self, assignment_id: str) -> bool:
        """Revoke role assignment.

        Args:
            assignment_id: Assignment to revoke

        Returns:
            True if revoked successfully
        """
        for i, assignment in enumerate(self.assignments):
            if assignment.assignment_id == assignment_id:
                self.assignments.pop(i)
                return True
        return False

    def check_permission(
        self,
        user_id: str,
        permission: Permission,
        tenant_id: Optional[str] = None
    ) -> bool:
        """Check if user has permission.

        Args:
            user_id: User to check
            permission: Permission to verify
            tenant_id: Optional tenant scope

        Returns:
            True if user has permission
        """
        user_roles = self.get_user_roles(user_id, tenant_id)

        for role_id in user_roles:
            role = self.roles.get(role_id)
            if role and permission in role.permissions:
                return True

        return False

    def get_user_roles(
        self,
        user_id: str,
        tenant_id: Optional[str] = None
    ) -> List[str]:
        """Get all active roles for user.

        Args:
            user_id: User ID
            tenant_id: Optional tenant filter

        Returns:
            List of role IDs
        """
        now = datetime.now()
        active_roles = []

        for assignment in self.assignments:
            if assignment.user_id != user_id:
                continue

            # Check tenant scope
            if tenant_id and assignment.tenant_id and assignment.tenant_id != tenant_id:
                continue

            # Check expiration
            if assignment.expires_at and assignment.expires_at < now:
                continue

            active_roles.append(assignment.role_id)

        return active_roles

    def get_user_permissions(
        self,
        user_id: str,
        tenant_id: Optional[str] = None
    ) -> Set[Permission]:
        """Get all permissions for user.

        Args:
            user_id: User ID
            tenant_id: Optional tenant filter

        Returns:
            Set of permissions
        """
        permissions = set()
        role_ids = self.get_user_roles(user_id, tenant_id)

        for role_id in role_ids:
            role = self.roles.get(role_id)
            if role:
                permissions.update(role.permissions)

        return permissions

    def list_roles(self, include_system: bool = True) -> List[Role]:
        """List all available roles.

        Args:
            include_system: Include system roles

        Returns:
            List of roles
        """
        if include_system:
            return list(self.roles.values())
        else:
            return [r for r in self.roles.values() if not r.is_system_role]

    def get_role_assignments(
        self,
        user_id: Optional[str] = None,
        role_id: Optional[str] = None,
        tenant_id: Optional[str] = None
    ) -> List[RoleAssignment]:
        """Get role assignments with filters.

        Args:
            user_id: Filter by user
            role_id: Filter by role
            tenant_id: Filter by tenant

        Returns:
            Filtered assignments
        """
        assignments = self.assignments.copy()

        if user_id:
            assignments = [a for a in assignments if a.user_id == user_id]

        if role_id:
            assignments = [a for a in assignments if a.role_id == role_id]

        if tenant_id:
            assignments = [a for a in assignments if a.tenant_id == tenant_id]

        # Remove expired assignments
        now = datetime.now()
        assignments = [
            a for a in assignments
            if not a.expires_at or a.expires_at > now
        ]

        return assignments

    def get_access_summary(self, user_id: str) -> Dict[str, Any]:
        """Get comprehensive access summary for user.

        Args:
            user_id: User to summarize

        Returns:
            Access summary with roles and permissions
        """
        assignments = self.get_role_assignments(user_id=user_id)
        permissions = self.get_user_permissions(user_id)

        role_details = []
        for assignment in assignments:
            role = self.roles.get(assignment.role_id)
            if role:
                role_details.append({
                    "role_id": role.role_id,
                    "role_name": role.name,
                    "tenant_id": assignment.tenant_id,
                    "assigned_at": assignment.assigned_at.isoformat(),
                    "expires_at": assignment.expires_at.isoformat() if assignment.expires_at else None
                })

        return {
            "user_id": user_id,
            "total_roles": len(assignments),
            "total_permissions": len(permissions),
            "roles": role_details,
            "permissions": [p.value for p in sorted(permissions, key=lambda x: x.value)]
        }


@dataclass
class License:
    """Enterprise license."""
    license_id: str
    license_key: str
    tenant_id: str
    tier: str  # starter, professional, enterprise
    max_users: int
    max_events_per_day: int
    enabled_features: Set[str]
    issued_at: datetime
    expires_at: datetime
    is_active: bool = True

class LicenseManager:
    """Enterprise license management."""

    def __init__(self):
        self.licenses: Dict[str, License] = {}

    def create_license(
        self,
        tenant_id: str,
        tier: str,
        max_users: int,
        max_events_per_day: int,
        validity_days: int = 365
    ) -> License:
        """Create new license.

        Args:
            tenant_id: Tenant for license
            tier: License tier
            max_users: Maximum concurrent users
            max_events_per_day: Event processing quota
            validity_days: License validity period

        Returns:
            Created license
        """
        import secrets

        license_id = f"lic-{len(self.licenses):06d}"
        license_key = secrets.token_hex(16)

        # Feature sets by tier
        feature_sets = {
            "starter": {"basic_detection", "event_analysis"},
            "professional": {
                "basic_detection", "event_analysis", "ml_anomaly_detection",
                "threat_hunting", "graph_analysis", "ctf_mode"
            },
            "enterprise": {
                "basic_detection", "event_analysis", "ml_anomaly_detection",
                "threat_hunting", "graph_analysis", "ctf_mode",
                "purple_team", "siem_integration", "multi_tenancy",
                "sso_saml", "audit_logging", "compliance_reporting"
            }
        }

        license = License(
            license_id=license_id,
            license_key=license_key,
            tenant_id=tenant_id,
            tier=tier,
            max_users=max_users,
            max_events_per_day=max_events_per_day,
            enabled_features=feature_sets.get(tier, set()),
            issued_at=datetime.now(),
            expires_at=datetime.now() + timedelta(days=validity_days)
        )

        self.licenses[license_id] = license
        return license

    def validate_license(self, license_key: str) -> Optional[License]:
        """Validate license key.

        Args:
            license_key: License key to validate

        Returns:
            License if valid, None otherwise
        """
        for license in self.licenses.values():
            if license.license_key == license_key:
                # Check if active and not expired
                if license.is_active and license.expires_at > datetime.now():
                    return license
        return None

    def check_feature_access(self, tenant_id: str, feature: str) -> bool:
        """Check if tenant has access to feature.

        Args:
            tenant_id: Tenant ID
            feature: Feature name

        Returns:
            True if feature is enabled
        """
        for license in self.licenses.values():
            if license.tenant_id == tenant_id and license.is_active:
                if license.expires_at > datetime.now():
                    return feature in license.enabled_features
        return False

    def get_license_usage(self, tenant_id: str) -> Dict[str, Any]:
        """Get license usage statistics.

        Args:
            tenant_id: Tenant ID

        Returns:
            Usage statistics
        """
        license = None
        for lic in self.licenses.values():
            if lic.tenant_id == tenant_id and lic.is_active:
                license = lic
                break

        if not license:
            return {"error": "No active license found"}

        days_remaining = (license.expires_at - datetime.now()).days

        return {
            "license_id": license.license_id,
            "tier": license.tier,
            "max_users": license.max_users,
            "max_events_per_day": license.max_events_per_day,
            "enabled_features": list(license.enabled_features),
            "issued_at": license.issued_at.isoformat(),
            "expires_at": license.expires_at.isoformat(),
            "days_remaining": days_remaining,
            "status": "active" if days_remaining > 30 else "expiring_soon" if days_remaining > 0 else "expired"
        }
