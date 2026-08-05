"""Policy engine execution authorization tests."""

import sys
from pathlib import Path
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.security.policy import PolicyEngine, PolicyDecision
from nexhunter.security.authorization import AuthContext, ROLES, Permission
from nexhunter.security.engagement import Engagement, EngagementScope, RiskLevel
from nexhunter.security.authentication import AuthenticationError
from nexhunter.security.authorization import AuthorizationError


def test_policy_no_authentication():
    """Test policy denies unauthenticated execution."""
    print("[TEST] Policy requires authentication...")
    engine = PolicyEngine()

    engagement = Engagement(
        id="ENG-001",
        name="Test",
        status="active",
        scope=EngagementScope(allowed_targets=["example.com"]),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    policy = engine.check_execution(
        auth_context=None,  # No auth
        engagement=engagement,
        tool_name="nmap",
        target="example.com",
        risk_level=RiskLevel.PASSIVE,
    )

    assert not policy.is_allowed, "Should deny unauthenticated execution"
    assert "Authentication" in policy.reason
    print("  [OK] Authentication required")


def test_policy_insufficient_permission():
    """Test policy denies insufficient permissions."""
    print("[TEST] Policy requires sufficient permissions...")
    engine = PolicyEngine()

    engagement = Engagement(
        id="ENG-001",
        name="Test",
        status="active",
        scope=EngagementScope(
            allowed_targets=["example.com"],
            allowed_risk_levels=[RiskLevel.PASSIVE, RiskLevel.ACTIVE],
        ),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    # Viewer context (no intrusive permission)
    viewer_context = AuthContext(
        identity="viewer@example.com",
        role=ROLES["viewer"],
        source_ip="192.168.1.1",
        request_id="req-1",
    )

    policy = engine.check_execution(
        auth_context=viewer_context,
        engagement=engagement,
        tool_name="nmap",
        target="example.com",
        risk_level=RiskLevel.INTRUSIVE,
    )

    assert not policy.is_allowed, "Viewer should not have intrusive permission"
    assert "Permission denied" in policy.reason
    print("  [OK] Permission check enforced")


def test_policy_no_engagement():
    """Test policy requires engagement context."""
    print("[TEST] Policy requires engagement context...")
    engine = PolicyEngine()

    scanner_context = AuthContext(
        identity="scanner@example.com",
        role=ROLES["scanner"],
        source_ip="192.168.1.1",
        request_id="req-1",
    )

    policy = engine.check_execution(
        auth_context=scanner_context,
        engagement=None,  # No engagement
        tool_name="nmap",
        target="example.com",
        risk_level=RiskLevel.PASSIVE,
    )

    assert not policy.is_allowed, "Should require engagement"
    assert "Engagement" in policy.reason
    print("  [OK] Engagement required")


def test_policy_scope_violation():
    """Test policy enforces scope."""
    print("[TEST] Policy enforces scope...")
    engine = PolicyEngine()

    engagement = Engagement(
        id="ENG-001",
        name="Test",
        status="active",
        scope=EngagementScope(
            allowed_targets=["example.com"],
            allowed_risk_levels=[RiskLevel.PASSIVE, RiskLevel.ACTIVE],
        ),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    scanner_context = AuthContext(
        identity="scanner@example.com",
        role=ROLES["scanner"],
        source_ip="192.168.1.1",
        request_id="req-1",
    )

    policy = engine.check_execution(
        auth_context=scanner_context,
        engagement=engagement,
        tool_name="nmap",
        target="other.com",  # Not in scope
        risk_level=RiskLevel.PASSIVE,
    )

    assert not policy.is_allowed, "Should deny out-of-scope target"
    assert "Scope" in policy.reason
    print("  [OK] Scope enforced")


def test_policy_dangerous_tool():
    """Test policy requires approval for dangerous tools."""
    print("[TEST] Policy requires approval for dangerous tools...")
    engine = PolicyEngine()

    engagement = Engagement(
        id="ENG-001",
        name="Test",
        status="active",
        scope=EngagementScope(
            allowed_targets=["example.com"],
            allowed_risk_levels=[RiskLevel.PASSIVE, RiskLevel.ACTIVE, RiskLevel.INTRUSIVE],
        ),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    tester_context = AuthContext(
        identity="tester@example.com",
        role=ROLES["tester"],
        source_ip="192.168.1.1",
        request_id="req-1",
    )

    # Hydra is dangerous (brute force)
    policy = engine.check_execution(
        auth_context=tester_context,
        engagement=engagement,
        tool_name="hydra",
        target="example.com",
        risk_level=RiskLevel.INTRUSIVE,
    )

    assert not policy.is_allowed, "Dangerous tools should require approval"
    assert policy.requires_approval, "Should indicate approval needed"
    print("  [OK] Dangerous tools require approval")


def test_policy_destructive_requires_admin():
    """Test policy requires admin for destructive tools."""
    print("[TEST] Policy requires admin for destructive tools...")
    engine = PolicyEngine()

    engagement = Engagement(
        id="ENG-001",
        name="Test",
        status="active",
        scope=EngagementScope(
            allowed_targets=["example.com"],
            allowed_risk_levels=[RiskLevel.DESTRUCTIVE],
        ),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    operator_context = AuthContext(
        identity="operator@example.com",
        role=ROLES["operator"],  # Not admin
        source_ip="192.168.1.1",
        request_id="req-1",
    )

    policy = engine.check_execution(
        auth_context=operator_context,
        engagement=engagement,
        tool_name="terraform",
        target="example.com",
        risk_level=RiskLevel.DESTRUCTIVE,
    )

    assert not policy.is_allowed, "Destructive requires admin"
    assert policy.required_permission == Permission.ADMIN, f"Should require ADMIN, got {policy.required_permission}"
    print("  [OK] Destructive requires admin")


def test_policy_allowed():
    """Test policy allows valid execution."""
    print("[TEST] Policy allows valid execution...")
    engine = PolicyEngine()

    engagement = Engagement(
        id="ENG-001",
        name="Test",
        status="active",
        scope=EngagementScope(
            allowed_targets=["example.com"],
            allowed_risk_levels=[RiskLevel.PASSIVE, RiskLevel.ACTIVE],
        ),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    scanner_context = AuthContext(
        identity="scanner@example.com",
        role=ROLES["scanner"],
        source_ip="192.168.1.1",
        request_id="req-1",
    )

    policy = engine.check_execution(
        auth_context=scanner_context,
        engagement=engagement,
        tool_name="nmap",
        target="example.com",
        risk_level=RiskLevel.PASSIVE,
    )

    assert policy.is_allowed, "Should allow valid execution"
    assert policy.decision == PolicyDecision.ALLOWED
    print("  [OK] Valid execution allowed")


def test_policy_raises_on_denied():
    """Test policy raises exception when denied."""
    print("[TEST] Policy raises on denied...")
    engine = PolicyEngine()

    scanner_context = AuthContext(
        identity="scanner@example.com",
        role=ROLES["scanner"],
        source_ip="192.168.1.1",
        request_id="req-1",
    )

    # No authentication - should raise AuthenticationError
    try:
        engine.check_execution_or_raise(
            auth_context=None,
            engagement=None,
            tool_name="nmap",
            target="example.com",
            risk_level=RiskLevel.PASSIVE,
        )
        assert False, "Should raise on auth failure"
    except AuthenticationError:
        pass

    # No engagement - should raise PermissionError
    try:
        engine.check_execution_or_raise(
            auth_context=scanner_context,
            engagement=None,
            tool_name="nmap",
            target="example.com",
            risk_level=RiskLevel.PASSIVE,
        )
        assert False, "Should raise on engagement failure"
    except PermissionError:
        pass

    print("  [OK] Raises exceptions correctly")


def test_policy_engagement_inactive():
    """Test policy denies execution on inactive engagement."""
    print("[TEST] Policy denies on inactive engagement...")
    engine = PolicyEngine()

    engagement = Engagement(
        id="ENG-001",
        name="Test",
        status="paused",  # Not active
        scope=EngagementScope(allowed_targets=["example.com"]),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    scanner_context = AuthContext(
        identity="scanner@example.com",
        role=ROLES["scanner"],
        source_ip="192.168.1.1",
        request_id="req-1",
    )

    policy = engine.check_execution(
        auth_context=scanner_context,
        engagement=engagement,
        tool_name="nmap",
        target="example.com",
        risk_level=RiskLevel.PASSIVE,
    )

    assert not policy.is_allowed, "Should deny on inactive engagement"
    assert "not active" in policy.reason.lower()
    print("  [OK] Inactive engagement denied")


if __name__ == "__main__":
    print("\n=== Policy Engine Tests ===\n")
    test_policy_no_authentication()
    test_policy_insufficient_permission()
    test_policy_no_engagement()
    test_policy_scope_violation()
    test_policy_dangerous_tool()
    test_policy_destructive_requires_admin()
    test_policy_allowed()
    test_policy_raises_on_denied()
    test_policy_engagement_inactive()
    print("\n=== All Policy Engine Tests Passed ===\n")
