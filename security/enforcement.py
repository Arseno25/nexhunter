"""Security gate: single entry point tying auth, policy, and audit together.

The HTTP/MCP layers call `SecurityGate.authorize_tool()` before running any
tool. It resolves the caller's identity, evaluates the deterministic policy
engine, and writes an audit record for every decision.

Two modes, selected by the NEXHUNTER_ENFORCE environment variable:

  enforce=off (default): development mode. Authentication is still honored
    (see TokenValidator), the raw-command hole is still closed at the API
    layer, and every execution is still audited -- but scope/policy checks are
    skipped because no engagement is configured. Suitable for local use.

  enforce=on: production mode. A valid token, a matching role permission, an
    active engagement, and an in-scope target are all required. Missing any of
    them denies the execution. This is the "secure by default" posture; it is
    opt-in only because engagement management has no API yet (Phase 2 backlog).
"""

import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from nexhunter.security.authentication import TokenValidator
from nexhunter.security.authorization import AuthContext, ROLES, Role
from nexhunter.security.audit import AuditLogger
from nexhunter.security.engagement import (
    Engagement,
    EngagementScope,
    RiskLevel,
)
from nexhunter.security.policy import PolicyEngine, ExecutionPolicy, PolicyDecision


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _load_engagement(path: Optional[str]) -> Optional[Engagement]:
    """Load a single active engagement from a JSON file, if configured.

    Expected shape:
        {
          "id": "...", "name": "...", "status": "active",
          "starts_at": "2026-08-05T00:00:00", "expires_at": "2026-09-05T00:00:00",
          "scope": {
            "allowed_targets": ["10.0.0.0/24", "*.example.com"],
            "denied_targets": [], "allowed_ports": [], "allowed_protocols": [],
            "allowed_risk_levels": ["passive", "active"]
          }
        }
    """
    if not path:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    from datetime import datetime

    scope_raw = data.get("scope", {})
    scope = EngagementScope(
        allowed_targets=scope_raw.get("allowed_targets", []),
        denied_targets=scope_raw.get("denied_targets", []),
        allowed_ports=scope_raw.get("allowed_ports", []),
        allowed_protocols=scope_raw.get("allowed_protocols", []),
        allowed_risk_levels=[
            RiskLevel(r) for r in scope_raw.get("allowed_risk_levels", ["passive", "active"])
        ],
    )
    return Engagement(
        id=data["id"],
        name=data.get("name", data["id"]),
        status=data.get("status", "active"),
        scope=scope,
        starts_at=datetime.fromisoformat(data["starts_at"]),
        expires_at=datetime.fromisoformat(data["expires_at"]),
    )


@dataclass
class GateResult:
    """Outcome of a security gate check."""

    allowed: bool
    policy: ExecutionPolicy
    auth_context: Optional[AuthContext]
    request_id: str


class SecurityGate:
    """Resolve identity, evaluate policy, and audit every tool execution."""

    def __init__(
        self,
        token_validator: Optional[TokenValidator] = None,
        policy_engine: Optional[PolicyEngine] = None,
        audit_logger: Optional[AuditLogger] = None,
        enforce: Optional[bool] = None,
    ):
        self.token_validator = token_validator or TokenValidator()
        self.policy_engine = policy_engine or PolicyEngine()
        self.audit = audit_logger or AuditLogger()
        self.enforce = _env_flag("NEXHUNTER_ENFORCE") if enforce is None else enforce
        # Role granted to an authenticated caller when no per-user store exists.
        role_name = os.environ.get("NEXHUNTER_DEFAULT_ROLE", "operator")
        self.default_role: Role = ROLES.get(role_name, ROLES["operator"])
        self.engagement = _load_engagement(os.environ.get("NEXHUNTER_ENGAGEMENT"))

    def _auth_context(self, auth_header: Optional[str], source_ip: str, request_id: str) -> Optional[AuthContext]:
        """Build an AuthContext for a validated caller, else None."""
        is_valid, _ = self.token_validator.validate(auth_header)
        if not is_valid:
            return None
        identity = "token" if self.token_validator.enabled else "anonymous"
        return AuthContext(
            identity=identity,
            role=self.default_role,
            source_ip=source_ip,
            request_id=request_id,
        )

    def authorize_tool(
        self,
        auth_header: Optional[str],
        tool_name: str,
        target: str,
        risk_level: RiskLevel,
        source_ip: str = "unknown",
        request_id: Optional[str] = None,
    ) -> GateResult:
        """Authorize one tool execution. Always writes an audit record."""
        request_id = request_id or uuid.uuid4().hex[:12]
        ctx = self._auth_context(auth_header, source_ip, request_id)

        if ctx is None:
            self.audit.log_auth_failure(source_ip, "invalid or missing token", request_id)
            policy = ExecutionPolicy(
                decision=PolicyDecision.DENIED,
                reason="Authentication required",
                policy_code="AUTH_REQUIRED",
            )
            return GateResult(False, policy, None, request_id)

        if self.enforce:
            policy = self.policy_engine.check_execution(
                ctx, self.engagement, tool_name, target, risk_level
            )
        else:
            # Dev mode: identity resolved, no engagement scope enforced.
            policy = ExecutionPolicy(
                decision=PolicyDecision.ALLOWED,
                reason="Execution authorized (enforcement disabled)",
                policy_code="DEV_ALLOWED",
            )

        self.audit.log_policy_decision(
            ctx, self.engagement, tool_name, target, risk_level, policy
        )
        return GateResult(policy.is_allowed, policy, ctx, request_id)


def risk_level_from_str(value: str) -> RiskLevel:
    """Map a tool's risk string to the RiskLevel enum (defaults to ACTIVE)."""
    try:
        return RiskLevel(value)
    except ValueError:
        return RiskLevel.ACTIVE
