"""Authorization and permission tests."""

import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.security.authorization import (
    Permission,
    Role,
    AuthContext,
    Authorizer,
    AuthorizationError,
    ROLES,
)


def test_permission_enum():
    """Test Permission enum."""
    print("[TEST] Permission enum...")
    assert Permission.READ.value == "read"
    assert Permission.SCAN_PASSIVE.value == "scan:passive"
    assert Permission.ADMIN.value == "admin"

    # Test from_string
    assert Permission.from_string("read") == Permission.READ
    assert Permission.from_string("scan:active") == Permission.SCAN_ACTIVE
    assert Permission.from_string("invalid") is None

    print("  [OK] Permission enum working")


def test_role_permissions():
    """Test Role permission checking."""
    print("[TEST] Role permissions...")

    viewer_role = ROLES["viewer"]
    assert viewer_role.has_permission(Permission.READ)
    assert viewer_role.has_permission(Permission.TOOLS_LIST)
    assert not viewer_role.has_permission(Permission.SCAN_ACTIVE)

    scanner_role = ROLES["scanner"]
    assert scanner_role.has_permission(Permission.SCAN_PASSIVE)
    assert scanner_role.has_permission(Permission.SCAN_ACTIVE)
    assert not scanner_role.has_permission(Permission.SCAN_INTRUSIVE)

    admin_role = ROLES["admin"]
    assert admin_role.has_permission(Permission.ADMIN)
    assert admin_role.has_permission(Permission.READ)  # Admin has everything
    assert admin_role.has_permission(Permission.SCAN_INTRUSIVE)

    print("  [OK] Role permissions working")


def test_predefined_roles():
    """Test that predefined roles exist and are valid."""
    print("[TEST] Predefined roles...")

    role_names = ["viewer", "scanner", "tester", "operator", "admin"]
    for name in role_names:
        assert name in ROLES, f"Missing role: {name}"
        role = ROLES[name]
        assert role.name == name
        assert len(role.permissions) > 0

    print(f"  [OK] {len(ROLES)} predefined roles loaded")


def test_auth_context():
    """Test AuthContext."""
    print("[TEST] AuthContext...")

    context = AuthContext(
        identity="user@example.com",
        role=ROLES["scanner"],
        source_ip="192.168.1.100",
        request_id="req-12345",
    )

    assert context.identity == "user@example.com"
    assert context.has_permission(Permission.SCAN_PASSIVE)
    assert context.has_permission(Permission.SCAN_ACTIVE)
    assert not context.has_permission(Permission.SCAN_INTRUSIVE)

    assert context.has_any_permission(Permission.READ, Permission.SCAN_PASSIVE)
    assert context.has_all_permissions(Permission.READ, Permission.SCAN_PASSIVE)
    assert not context.has_all_permissions(Permission.READ, Permission.SCAN_INTRUSIVE)

    print("  [OK] AuthContext working")


def test_authorizer_check_permission():
    """Test Authorizer permission checking."""
    print("[TEST] Authorizer check_permission...")

    authorizer = Authorizer(default_role=ROLES["viewer"])

    viewer_context = AuthContext(
        identity="viewer@example.com",
        role=ROLES["viewer"],
        source_ip="192.168.1.100",
        request_id="req-1",
    )

    # Viewer should have read permission
    assert authorizer.check_permission(viewer_context, Permission.READ)
    assert not authorizer.check_permission(viewer_context, Permission.SCAN_ACTIVE)

    # Default role (no context) should be viewer
    assert authorizer.check_permission(None, Permission.READ)
    assert not authorizer.check_permission(None, Permission.SCAN_ACTIVE)

    print("  [OK] Authorizer check_permission working")


def test_authorizer_raise_on_denied():
    """Test Authorizer raises AuthorizationError on denied permission."""
    print("[TEST] Authorizer raise on denied...")

    authorizer = Authorizer()

    viewer_context = AuthContext(
        identity="viewer@example.com",
        role=ROLES["viewer"],
        source_ip="192.168.1.100",
        request_id="req-1",
    )

    # Should not raise for allowed permission
    try:
        authorizer.check_permission_or_raise(viewer_context, Permission.READ)
    except AuthorizationError:
        assert False, "Should not raise for allowed permission"

    # Should raise for denied permission
    try:
        authorizer.check_permission_or_raise(viewer_context, Permission.SCAN_INTRUSIVE)
        assert False, "Should raise AuthorizationError for denied permission"
    except AuthorizationError as e:
        assert "Permission denied" in str(e)

    print("  [OK] Authorizer raise on denied working")


def test_authorizer_any_permission():
    """Test Authorizer check_any_permission."""
    print("[TEST] Authorizer check_any_permission...")

    authorizer = Authorizer()

    scanner_context = AuthContext(
        identity="scanner@example.com",
        role=ROLES["scanner"],
        source_ip="192.168.1.100",
        request_id="req-1",
    )

    # Should return True if any permission is granted
    assert authorizer.check_any_permission(
        scanner_context,
        Permission.SCAN_INTRUSIVE,  # Not granted
        Permission.SCAN_ACTIVE,  # Granted
    )

    # Should return False if no permissions are granted
    assert not authorizer.check_any_permission(
        scanner_context,
        Permission.SCAN_INTRUSIVE,  # Not granted
        Permission.PROCESS_TERMINATE,  # Not granted
    )

    print("  [OK] Authorizer check_any_permission working")


def test_authorizer_all_permissions():
    """Test Authorizer check_all_permissions."""
    print("[TEST] Authorizer check_all_permissions...")

    authorizer = Authorizer()

    tester_context = AuthContext(
        identity="tester@example.com",
        role=ROLES["tester"],
        source_ip="192.168.1.100",
        request_id="req-1",
    )

    # Should return True if all permissions are granted
    assert authorizer.check_all_permissions(
        tester_context,
        Permission.SCAN_PASSIVE,
        Permission.SCAN_ACTIVE,
        Permission.SCAN_INTRUSIVE,
    )

    # Should return False if any permission is not granted
    assert not authorizer.check_all_permissions(
        tester_context,
        Permission.SCAN_PASSIVE,
        Permission.SCAN_ACTIVE,
        Permission.ADMIN,  # Tester doesn't have ADMIN
    )

    print("  [OK] Authorizer check_all_permissions working")


if __name__ == "__main__":
    print("\n=== Authorization Tests ===\n")
    test_permission_enum()
    test_role_permissions()
    test_predefined_roles()
    test_auth_context()
    test_authorizer_check_permission()
    test_authorizer_raise_on_denied()
    test_authorizer_any_permission()
    test_authorizer_all_permissions()
    print("\n=== All Authorization Tests Passed ===\n")
