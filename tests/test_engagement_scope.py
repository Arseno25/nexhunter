"""Engagement scope and target validation tests."""

import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import ipaddress

from nexhunter.security.engagement import (
    Engagement,
    EngagementScope,
    RiskLevel,
    TargetValidator,
    ScopeEnforcer,
)

# Stub DNS so scope tests never touch the network. Anything not listed here
# resolves to a public address; add entries to model rebinding scenarios.
FAKE_DNS = {
    "example.com": ["93.184.216.34"],
    "app.example.com": ["93.184.216.35"],
    "admin.example.com": ["93.184.216.36"],
    "other.com": ["8.8.8.8"],
    "evil-example.com": ["45.33.32.156"],
    "rebind.example.com": ["169.254.169.254"],
    "internal.example.com": ["10.0.0.5"],
    "mapped.example.com": ["::ffff:169.254.169.254"],
}


def _fake_resolver(host):
    addrs = FAKE_DNS.get(host.lower())
    if addrs is None:
        raise OSError(f"no fake DNS entry for {host}")
    return [ipaddress.ip_address(a) for a in addrs]


TargetValidator.resolver = staticmethod(_fake_resolver)


def _engagement(allowed, denied=None, risk_levels=None, status="active"):
    """Build an active engagement with the given scope."""
    return Engagement(
        id="ENG-TEST",
        name="Test",
        status=status,
        scope=EngagementScope(
            allowed_targets=allowed,
            denied_targets=denied or [],
            allowed_risk_levels=risk_levels or [RiskLevel.PASSIVE, RiskLevel.ACTIVE],
        ),
        starts_at=datetime.utcnow() - timedelta(hours=1),
        expires_at=datetime.utcnow() + timedelta(hours=1),
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


def test_wildcard_does_not_match_sibling_domain():
    """*.example.com must not match evil-example.com (dot boundary required)."""
    print("[TEST] Wildcard requires a dot boundary...")

    assert not TargetValidator._matches_any_pattern("evil-example.com", ["*.example.com"])
    assert not TargetValidator._matches_any_pattern("notexample.com", ["*.example.com"])
    assert TargetValidator._matches_any_pattern("app.example.com", ["*.example.com"])

    engagement = _engagement(["*.example.com"])
    is_allowed, reason = TargetValidator.validate_target("evil-example.com", engagement)
    assert not is_allowed, "evil-example.com must not fall inside *.example.com"
    assert "not in allowed list" in reason

    print("  [OK] Sibling domain rejected")


def test_no_engagement_fails_closed():
    """A missing engagement denies rather than allows."""
    print("[TEST] Missing engagement fails closed...")

    is_allowed, reason = TargetValidator.validate_target("example.com", None)
    assert not is_allowed, "No engagement must deny"
    assert "No engagement" in reason

    print("  [OK] Missing engagement denied")


def test_empty_allowlist_fails_closed():
    """An empty allow-list authorizes nothing."""
    print("[TEST] Empty allow-list fails closed...")

    engagement = _engagement([])
    is_allowed, reason = TargetValidator.validate_target("example.com", engagement)
    assert not is_allowed, "Empty allow-list must deny"
    assert "empty allowed-target list" in reason

    print("  [OK] Empty allow-list denied")


def test_dns_rebinding_to_metadata_blocked():
    """A permitted name resolving to the metadata IP is still denied."""
    print("[TEST] DNS rebinding to metadata blocked...")

    engagement = _engagement(["*.example.com"])
    is_allowed, reason = TargetValidator.validate_target("rebind.example.com", engagement)
    assert not is_allowed, "Name resolving to metadata IP must be denied"
    assert "metadata" in reason.lower()

    print("  [OK] Rebinding to metadata denied")


def test_ipv4_mapped_ipv6_metadata_blocked():
    """::ffff:169.254.169.254 is the metadata IP and must be treated as such."""
    print("[TEST] IPv4-mapped IPv6 metadata blocked...")

    assert TargetValidator.is_metadata_ip("::ffff:169.254.169.254")

    engagement = _engagement(["*.example.com"])
    is_allowed, reason = TargetValidator.validate_target("mapped.example.com", engagement)
    assert not is_allowed, "IPv4-mapped metadata address must be denied"
    assert "metadata" in reason.lower()

    print("  [OK] IPv4-mapped metadata denied")


def test_wildcard_does_not_authorize_internal_address():
    """A wildcard allow must not pull private space into scope."""
    print("[TEST] Wildcard does not authorize private space...")

    engagement = _engagement(["*.example.com"])
    is_allowed, reason = TargetValidator.validate_target("internal.example.com", engagement)
    assert not is_allowed, "Name resolving to RFC1918 must be denied under a wildcard"
    assert "private" in reason.lower()

    # Naming it literally is an explicit, auditable authorization.
    literal = _engagement(["internal.example.com"])
    is_allowed, reason = TargetValidator.validate_target("internal.example.com", literal)
    assert is_allowed, f"Literal allow should authorize internal host, got: {reason}"

    print("  [OK] Private space needs a literal allow")


def test_unresolvable_target_denied():
    """A name we cannot resolve is a name whose scope we cannot verify."""
    print("[TEST] Unresolvable target denied...")

    engagement = _engagement(["*.example.com"])
    is_allowed, reason = TargetValidator.validate_target("ghost.example.com", engagement)
    assert not is_allowed, "Unresolvable target must be denied"
    assert "DNS resolution failed" in reason

    print("  [OK] Unresolvable target denied")


def test_url_target_is_reduced_to_host():
    """URL and host:port forms are validated by their host."""
    print("[TEST] URL target reduced to host...")

    assert TargetValidator._extract_host("https://app.example.com/admin?x=1") == "app.example.com"
    assert TargetValidator._extract_host("example.com:8443") == "example.com"
    assert TargetValidator._extract_host("[2001:db8::1]:443") == "2001:db8::1"

    engagement = _engagement(["*.example.com"], denied=["admin.example.com"])
    is_allowed, _ = TargetValidator.validate_target("https://app.example.com/x", engagement)
    assert is_allowed, "URL against an allowed host should pass"

    is_allowed, reason = TargetValidator.validate_target("https://admin.example.com/x", engagement)
    assert not is_allowed, "URL against a denied host must fail"
    assert "denied" in reason.lower()

    print("  [OK] URL reduced to host before scope check")


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
    test_wildcard_does_not_match_sibling_domain()
    test_no_engagement_fails_closed()
    test_empty_allowlist_fails_closed()
    test_dns_rebinding_to_metadata_blocked()
    test_ipv4_mapped_ipv6_metadata_blocked()
    test_wildcard_does_not_authorize_internal_address()
    test_unresolvable_target_denied()
    test_url_target_is_reduced_to_host()
    print("\n=== All Engagement Scope Tests Passed ===\n")
