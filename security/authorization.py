"""Role-based access control (RBAC) with permissions."""

from enum import Enum
from dataclasses import dataclass
from typing import Set, Optional


class Permission(Enum):
    """Available permissions in NexHunter."""

    # Read-only access
    READ = "read"

    # Tool management
    TOOLS_LIST = "tools:list"

    # Scanning permissions by risk level
    SCAN_PASSIVE = "scan:passive"
    SCAN_ACTIVE = "scan:active"
    SCAN_INTRUSIVE = "scan:intrusive"

    # Process management
    PROCESS_READ = "process:read"
    PROCESS_TERMINATE = "process:terminate"

    # Results access
    FINDINGS_READ = "findings:read"

    # Engagement management
    ENGAGEMENTS_MANAGE = "engagements:manage"

    # Administrative access
    ADMIN = "admin"

    @staticmethod
    def from_string(value: str) -> Optional["Permission"]:
        """Convert string to Permission enum."""
        try:
            return Permission(value)
        except ValueError:
            return None


@dataclass(frozen=True)
class Role:
    """Role with associated permissions."""

    name: str
    description: str
    permissions: frozenset[Permission]

    def has_permission(self, permission: Permission) -> bool:
        """Check if role has permission."""
        if Permission.ADMIN in self.permissions:
            return True  # Admin has all permissions
        return permission in self.permissions


# Predefined roles
ROLES = {
    "viewer": Role(
        name="viewer",
        description="Read-only access to findings and tools list",
        permissions=frozenset([Permission.READ, Permission.TOOLS_LIST, Permission.FINDINGS_READ]),
    ),
    "scanner": Role(
        name="scanner",
        description="Passive and active scanning permissions",
        permissions=frozenset([
            Permission.READ,
            Permission.TOOLS_LIST,
            Permission.SCAN_PASSIVE,
            Permission.SCAN_ACTIVE,
            Permission.PROCESS_READ,
            Permission.FINDINGS_READ,
        ]),
    ),
    "tester": Role(
        name="tester",
        description="Full testing including intrusive tools",
        permissions=frozenset([
            Permission.READ,
            Permission.TOOLS_LIST,
            Permission.SCAN_PASSIVE,
            Permission.SCAN_ACTIVE,
            Permission.SCAN_INTRUSIVE,
            Permission.PROCESS_READ,
            Permission.PROCESS_TERMINATE,
            Permission.FINDINGS_READ,
            Permission.ENGAGEMENTS_MANAGE,
        ]),
    ),
    "operator": Role(
        name="operator",
        description="Full operational access including destructive tools",
        permissions=frozenset([p for p in Permission]),  # All permissions except ADMIN
    ),
    "admin": Role(
        name="admin",
        description="Full administrative access",
        permissions=frozenset([Permission.ADMIN]),
    ),
}


@dataclass
class AuthContext:
    """Authentication context for a request."""

    identity: str  # User identifier or service name
    role: Role
    source_ip: str
    request_id: str

    def has_permission(self, permission: Permission) -> bool:
        """Check if context has permission."""
        return self.role.has_permission(permission)

    def has_any_permission(self, *permissions: Permission) -> bool:
        """Check if context has any of the permissions."""
        return any(self.has_permission(p) for p in permissions)

    def has_all_permissions(self, *permissions: Permission) -> bool:
        """Check if context has all permissions."""
        return all(self.has_permission(p) for p in permissions)


class AuthorizationError(Exception):
    """Authorization check failed."""

    pass


class Authorizer:
    """Check authorization decisions."""

    def __init__(self, default_role: Role = ROLES["viewer"]):
        """Initialize authorizer with default role for unauthenticated users."""
        self.default_role = default_role

    def check_permission(self, context: Optional[AuthContext], permission: Permission) -> bool:
        """Check if context has permission. Return True/False."""
        if context is None:
            return self.default_role.has_permission(permission)
        return context.has_permission(permission)

    def check_permission_or_raise(self, context: Optional[AuthContext], permission: Permission) -> None:
        """Check permission, raise AuthorizationError if denied."""
        if not self.check_permission(context, permission):
            identity = context.identity if context else "anonymous"
            raise AuthorizationError(f"Permission denied: {identity} lacks {permission.value}")

    def check_any_permission(self, context: Optional[AuthContext], *permissions: Permission) -> bool:
        """Check if context has any of the permissions."""
        if context is None:
            return self.default_role.has_any_permission(*permissions)
        return context.has_any_permission(*permissions)

    def check_all_permissions(self, context: Optional[AuthContext], *permissions: Permission) -> bool:
        """Check if context has all permissions."""
        if context is None:
            return self.default_role.has_all_permissions(*permissions)
        return context.has_all_permissions(*permissions)
