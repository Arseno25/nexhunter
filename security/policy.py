"""Deterministic policy engine for execution decisions."""

from dataclasses import dataclass
from typing import Optional
from enum import Enum

from nexhunter.security.authentication import AuthenticationError
from nexhunter.security.authorization import AuthContext, Permission, AuthorizationError
from nexhunter.security.engagement import Engagement, RiskLevel, ScopeEnforcer


class PolicyDecision(Enum):
    """Policy decision outcomes."""
    ALLOWED = "allowed"
    DENIED = "denied"


@dataclass(frozen=True)
class ExecutionPolicy:
    """Execution authorization decision."""

    decision: PolicyDecision
    reason: str
    required_permission: Optional[Permission] = None
    requires_approval: bool = False
    policy_code: Optional[str] = None

    @property
    def is_allowed(self) -> bool:
        """Check if execution is allowed."""
        return self.decision == PolicyDecision.ALLOWED


class PolicyEngine:
    """Deterministic execution policy enforcement."""

    # Tools that require explicit approval
    DANGEROUS_TOOLS = {
        # Credential attacks
        "hydra", "john", "hashcat", "medusa", "ncrack",
        # Brute force
        "hashcat", "john",
        # Payload generation
        "msfvenom", "msfconsole",
        # Exploitation
        "exploit", "metasploit", "empire", "cobalt-strike", "sliver",
        # Persistence
        "persistence",
        # Data modification/deletion
        "rm", "del", "drop", "truncate", "delete", "wipe",
        # DoS
        "dos", "ddos", "slowhttptest", "hping",
        # Wireless deauth
        "aireplay-ng",
        # Destructive cloud
        "terraform-destroy", "cloudformation-delete",
    }

    def __init__(self, scope_enforcer: Optional[ScopeEnforcer] = None):
        """Initialize policy engine."""
        self.scope_enforcer = scope_enforcer or ScopeEnforcer()

    def check_execution(
        self,
        auth_context: Optional[AuthContext],
        engagement: Optional[Engagement],
        tool_name: str,
        target: str,
        risk_level: RiskLevel,
    ) -> ExecutionPolicy:
        """
        Determine if execution is allowed.

        Policy evaluation order:
        1. Authentication (required)
        2. Authorization (permissions)
        3. Engagement scope (target must be in scope)
        4. Risk level (must be allowed for engagement)
        5. Tool-specific restrictions (dangerous tools need approval)
        """

        # Rule 1: Authentication required
        if auth_context is None:
            return ExecutionPolicy(
                decision=PolicyDecision.DENIED,
                reason="Authentication required",
                policy_code="AUTH_REQUIRED",
            )

        # Rule 2: Authorization checks based on risk level
        required_permission = self._get_required_permission(risk_level)
        if not auth_context.has_permission(required_permission):
            return ExecutionPolicy(
                decision=PolicyDecision.DENIED,
                reason=f"Permission denied: {required_permission.value} required for {risk_level.value} tools",
                required_permission=required_permission,
                policy_code="PERMISSION_DENIED",
            )

        # Rule 3: Engagement scope enforcement
        if engagement is None:
            return ExecutionPolicy(
                decision=PolicyDecision.DENIED,
                reason="Engagement context required",
                policy_code="ENGAGEMENT_REQUIRED",
            )

        if not engagement.is_active():
            return ExecutionPolicy(
                decision=PolicyDecision.DENIED,
                reason="Engagement is not active",
                policy_code="ENGAGEMENT_INACTIVE",
            )

        # Check target is in scope
        is_in_scope, scope_reason = self.scope_enforcer.check_execution(
            engagement, target, risk_level
        )
        if not is_in_scope:
            return ExecutionPolicy(
                decision=PolicyDecision.DENIED,
                reason=f"Scope violation: {scope_reason}",
                policy_code="SCOPE_VIOLATION",
            )

        # Rule 4: Dangerous tools require approval
        if self._is_dangerous_tool(tool_name):
            return ExecutionPolicy(
                decision=PolicyDecision.DENIED,
                reason=f"Tool '{tool_name}' requires explicit approval (dangerous category)",
                requires_approval=True,
                policy_code="APPROVAL_REQUIRED",
            )

        # Rule 5: Destructive tools only with admin + explicit flag
        if risk_level == RiskLevel.DESTRUCTIVE:
            if not auth_context.has_permission(Permission.ADMIN):
                return ExecutionPolicy(
                    decision=PolicyDecision.DENIED,
                    reason="Destructive tools require admin permission",
                    required_permission=Permission.ADMIN,
                    policy_code="ADMIN_REQUIRED",
                )

        # All checks passed
        return ExecutionPolicy(
            decision=PolicyDecision.ALLOWED,
            reason="Execution authorized",
            policy_code="ALLOWED",
        )

    def check_execution_or_raise(
        self,
        auth_context: Optional[AuthContext],
        engagement: Optional[Engagement],
        tool_name: str,
        target: str,
        risk_level: RiskLevel,
    ) -> ExecutionPolicy:
        """
        Check execution and raise if denied.

        Raises:
            AuthenticationError - authentication failed
            AuthorizationError - authorization failed
            PermissionError - scope or engagement failed
        """
        policy = self.check_execution(auth_context, engagement, tool_name, target, risk_level)

        if not policy.is_allowed:
            if "Authentication" in policy.reason:
                raise AuthenticationError(policy.reason)
            elif "Permission denied" in policy.reason:
                raise AuthorizationError(policy.reason)
            else:
                raise PermissionError(policy.reason)

        return policy

    @staticmethod
    def _get_required_permission(risk_level: RiskLevel) -> Permission:
        """Get required permission for risk level."""
        mapping = {
            RiskLevel.PASSIVE: Permission.SCAN_PASSIVE,
            RiskLevel.ACTIVE: Permission.SCAN_ACTIVE,
            RiskLevel.INTRUSIVE: Permission.SCAN_INTRUSIVE,
            RiskLevel.DESTRUCTIVE: Permission.ADMIN,
        }
        return mapping.get(risk_level, Permission.SCAN_PASSIVE)

    @staticmethod
    def _is_dangerous_tool(tool_name: str) -> bool:
        """Check if tool is in dangerous/requires-approval list."""
        tool_lower = tool_name.lower()
        for dangerous in PolicyEngine.DANGEROUS_TOOLS:
            if dangerous.lower() in tool_lower:
                return True
        return False
