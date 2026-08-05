"""Engagement scope and target validation tests."""

import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.security.engagement import (
    Engagement,
    EngagementScope,
    RiskLevel,
    TargetValidator,
    ScopeEnforcer,
)


def test_target_validator_reserved_ips():
    """Test detection of reserved IP addresses."""
    print("[TEST] Reserved IP detection...")

    # Loopback
    is_reserved, reason = TargetValidator.is_reserved_ip("127.0.0.1")
    assert is_reserved, "127.0.0.1 should be reserved"

    is_reserved, reason = TargetValidator.is_reserved_ip("::1")
    assert is_reserved, "::1 (IPv6 loopback) should be reserved"

    # Cloud metadata
    is_reserved, reason = TargetValidator.is_reserved_ip("169.254.169.254")
    assert is_reserved, "169.254.169.254 (AWS metadata) should be reserved"

    # Private networks
    is_reserved, reason = TargetValidator.is_reserved_ip("10.0.0.1")
    assert is_reserved, "10.0.0.1 (private) should be reserved"

    is_reserved, reason = TargetValidator.is_reserved_ip("192.168.1.1")
    assert is_reserved, "192.168.1.1 (private) should be reserved"

    # Public IP should not be reserved
    is_reserved, reason = TargetValidator.is_reserved_ip("8.8.8.8")
    assert not is_reserved, "8.8.8.8 (public) should not be reserved"

    print("  [OK] Reserved IP detection working")


def test_target_validator_hostname():
    """Test hostname validation."""
    print("[TEST] Hostname validation...")

    assert TargetValidator.is_valid_hostname("example.com")
    assert TargetValidator.is_valid_hostname("sub.example.com")
    assert TargetValidator.is_valid_hostname("*.example.com")
    assert not TargetValidator.is_valid_hostname("")
    assert not TargetValidator.is_valid_hostname("invalid..com")

    print("  [OK] Hostname validation working")


def test_target_validator_cidr():
    """Test CIDR validation."""
    print("[TEST] CIDR validation...")

    assert TargetValidator.is_valid_cidr("192.168.0.0/16")
    assert TargetValidator.is_valid_cidr("10.0.0.0/8")
    assert TargetValidator.is_valid_cidr("2001:db8::/32")
    assert not TargetValidator.is_valid_cidr("192.168.0.0/33")
    assert not TargetValidator.is_valid_cidr("invalid/16")

    print("  [OK] CIDR validation working")


def test_target_validator_port():
    """Test port validation."""
    print("[TEST] Port validation...")

    assert TargetValidator.is_valid_port("80")
    assert TargetValidator.is_valid_port("443")
    assert TargetValidator.is_valid_port("80-443")
    assert TargetValidator.is_valid_port("8000-9000")
    assert not TargetValidator.is_valid_port("0")
    assert not TargetValidator.is_valid_port("65536")
    assert not TargetValidator.is_valid_port("443-80")  # range reversed

    print("  [OK] Port validation working")


def test_target_pattern_matching():
    """Test pattern matching logic."""
    print("[TEST] Pattern matching...")

    patterns = ["example.com", "*.example.com", "192.168.0.0/24", "10.0.0.1"]

    # Exact match
    assert TargetValidator._matches_any_pattern("example.com", patterns)

    # Wildcard match
    assert TargetValidator._matches_any_pattern("sub.example.com", patterns)
    assert not TargetValidator._matches_any_pattern("sub.sub.example.com", patterns)  # Only one level

    # CIDR match
    assert TargetValidator._matches_any_pattern("192.168.0.100", patterns)
    assert not TargetValidator._matches_any_pattern("192.168.1.100", patterns)

    # Exact IP match
    assert TargetValidator._matches_any_pattern("10.0.0.1", patterns)

    print("  [OK] Pattern matching working")


def test_denied_overrides_allowed():
    """Test that denied targets override allowed."""
    print("[TEST] Denied overrides allowed...")

    engagement = Engagement(
        id="ENG-001",
        name="Test",
        status="active",
        scope=EngagementScope(
            allowed_targets=["*.example.com"],
            denied_targets=["admin.example.com"],
            allowed_risk_levels=[RiskLevel.PASSIVE, RiskLevel.ACTIVE],
        ),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    # Allowed target should pass
    is_allowed, _ = TargetValidator.validate_target("app.example.com", engagement)
    assert is_allowed, "app.example.com should be allowed"

    # Denied target should fail
    is_allowed, reason = TargetValidator.validate_target("admin.example.com", engagement)
    assert not is_allowed, "admin.example.com should be denied"
    assert "denied" in reason.lower(), f"Reason should mention denied: {reason}"

    print("  [OK] Denied overrides allowed")


def test_engagement_expiry():
    """Test engagement expiry checking."""
    print("[TEST] Engagement expiry...")

    active_engagement = Engagement(
        id="ENG-001",
        name="Active",
        status="active",
        scope=EngagementScope(allowed_targets=["example.com"]),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    expired_engagement = Engagement(
        id="ENG-002",
        name="Expired",
        status="active",
        scope=EngagementScope(allowed_targets=["example.com"]),
        starts_at=datetime.utcnow() - timedelta(hours=2),
        expires_at=datetime.utcnow() - timedelta(hours=1),
    )

    assert active_engagement.is_active(), "Active engagement should be active"
    assert not expired_engagement.is_active(), "Expired engagement should not be active"
    assert expired_engagement.is_expired(), "Engagement should be marked as expired"

    print("  [OK] Engagement expiry working")


def test_scope_enforcer_check_execution():
    """Test scope enforcer checks."""
    print("[TEST] Scope enforcer...")

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

    enforcer = ScopeEnforcer()

    # Allowed target + passive risk should pass
    is_allowed, _ = enforcer.check_execution(engagement, "example.com", RiskLevel.PASSIVE)
    assert is_allowed, "Passive scan of allowed target should be allowed"

    # Intrusive risk should fail
    is_allowed, reason = enforcer.check_execution(engagement, "example.com", RiskLevel.INTRUSIVE)
    assert not is_allowed, "Intrusive scan should not be allowed"
    assert "Risk level" in reason, f"Reason should mention risk level: {reason}"

    # Disallowed target should fail
    is_allowed, reason = enforcer.check_execution(engagement, "other.com", RiskLevel.PASSIVE)
    assert not is_allowed, "Scan of disallowed target should fail"

    print("  [OK] Scope enforcer working")


def test_scope_enforcer_raises():
    """Test that scope enforcer raises PermissionError when denied."""
    print("[TEST] Scope enforcer raises...")

    engagement = Engagement(
        id="ENG-001",
        name="Test",
        status="active",
        scope=EngagementScope(
            allowed_targets=["example.com"],
            allowed_risk_levels=[RiskLevel.PASSIVE],
        ),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    enforcer = ScopeEnforcer()

    # Should not raise for allowed
    try:
        enforcer.check_execution_or_raise(engagement, "example.com", RiskLevel.PASSIVE)
    except PermissionError:
        assert False, "Should not raise for allowed execution"

    # Should raise for denied
    try:
        enforcer.check_execution_or_raise(engagement, "example.com", RiskLevel.INTRUSIVE)
        assert False, "Should raise PermissionError for denied execution"
    except PermissionError as e:
        assert "Risk level" in str(e)

    print("  [OK] Scope enforcer raises correctly")


def test_loopback_blocked_by_default():
    """Test that loopback is blocked unless explicitly allowed."""
    print("[TEST] Loopback blocked by default...")

    engagement = Engagement(
        id="ENG-001",
        name="Test",
        status="active",
        scope=EngagementScope(
            allowed_targets=["example.com"],  # No loopback
        ),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    is_allowed, reason = TargetValidator.validate_target("127.0.0.1", engagement)
    assert not is_allowed, "Loopback should be blocked by default"
    assert reason is not None, "Should have a reason for rejection"

    # Should be allowed if explicitly in allowed_targets
    engagement_with_loopback = Engagement(
        id="ENG-002",
        name="Test",
        status="active",
        scope=EngagementScope(
            allowed_targets=["127.0.0.1", "example.com"],
        ),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )

    is_allowed, reason = TargetValidator.validate_target("127.0.0.1", engagement_with_loopback)
    assert is_allowed, "Loopback should be allowed when explicitly scoped"

    print("  [OK] Loopback protection working")


if __name__ == "__main__":
    print("\n=== Engagement Scope Tests ===\n")
    test_target_validator_reserved_ips()
    test_target_validator_hostname()
    test_target_validator_cidr()
    test_target_validator_port()
    test_target_pattern_matching()
    test_denied_overrides_allowed()
    test_engagement_expiry()
    test_scope_enforcer_check_execution()
    test_scope_enforcer_raises()
    test_loopback_blocked_by_default()
    print("\n=== All Engagement Scope Tests Passed ===\n")
