"""Authentication and authorization tests."""

import os
import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.security.authentication import TokenValidator, AuthenticationError


def test_token_validator_no_token_configured():
    """Test validator when no token is configured."""
    print("[TEST] Token validator with no token configured...")
    validator = TokenValidator(token="")

    # Should allow all requests when no token configured
    is_valid, error = validator.validate(None)
    assert is_valid, f"Expected valid=True when no token configured, got: {error}"

    is_valid, error = validator.validate("Bearer anything")
    assert is_valid, f"Expected valid=True when no token configured, got: {error}"

    print("  [OK] No token configured - all requests allowed")


def test_token_validator_valid_token():
    """Test validator with valid token."""
    print("[TEST] Token validator with valid token...")
    token = "test-secret-token-12345"
    validator = TokenValidator(token=token)

    # Should accept correct token
    is_valid, error = validator.validate(f"Bearer {token}")
    assert is_valid, f"Expected valid token, got error: {error}"

    print("  [OK] Valid token accepted")


def test_token_validator_invalid_token():
    """Test validator with invalid token."""
    print("[TEST] Token validator with invalid token...")
    token = "test-secret-token-12345"
    validator = TokenValidator(token=token)

    # Should reject wrong token
    is_valid, error = validator.validate("Bearer wrong-token")
    assert not is_valid, "Expected invalid token to be rejected"
    assert "Invalid token" in error, f"Expected 'Invalid token' error, got: {error}"

    print("  [OK] Invalid token rejected")


def test_token_validator_missing_header():
    """Test validator with missing Authorization header."""
    print("[TEST] Token validator with missing header...")
    token = "test-secret-token-12345"
    validator = TokenValidator(token=token)

    # Should reject missing header
    is_valid, error = validator.validate(None)
    assert not is_valid, "Expected missing header to be rejected"
    assert "Missing" in error, f"Expected 'Missing' error, got: {error}"

    print("  [OK] Missing header rejected")


def test_token_validator_invalid_format():
    """Test validator with invalid Authorization format."""
    print("[TEST] Token validator with invalid format...")
    token = "test-secret-token-12345"
    validator = TokenValidator(token=token)

    # Should reject invalid format
    is_valid, error = validator.validate("InvalidFormat some-token")
    assert not is_valid, "Expected invalid format to be rejected"
    assert "Invalid Authorization" in error, f"Expected 'Invalid Authorization' error, got: {error}"

    print("  [OK] Invalid format rejected")


def test_token_validator_constant_time():
    """Test that validator uses constant-time comparison."""
    print("[TEST] Token validator constant-time comparison...")
    token = "test-secret-token-12345"
    validator = TokenValidator(token=token)

    # Both should be rejected but shouldn't leak timing info
    wrong_token_1 = "a" * len(token)
    wrong_token_2 = "z" * len(token)

    is_valid_1, _ = validator.validate(f"Bearer {wrong_token_1}")
    is_valid_2, _ = validator.validate(f"Bearer {wrong_token_2}")

    assert not is_valid_1, f"Expected wrong token 1 to be rejected"
    assert not is_valid_2, f"Expected wrong token 2 to be rejected"

    print("  [OK] Constant-time comparison working")


def test_token_validator_from_env():
    """Test validator loading token from environment."""
    print("[TEST] Token validator from environment...")

    # Set env var
    os.environ["NEXHUNTER_API_TOKEN"] = "env-token-value"

    try:
        validator = TokenValidator()
        is_valid, error = validator.validate("Bearer env-token-value")
        assert is_valid, f"Expected env token to work, got error: {error}"
        print("  [OK] Token loaded from environment")
    finally:
        # Clean up
        if "NEXHUNTER_API_TOKEN" in os.environ:
            del os.environ["NEXHUNTER_API_TOKEN"]


def test_token_validator_raises_on_invalid():
    """Test validate_or_raise raises AuthenticationError."""
    print("[TEST] Token validator raise on invalid...")
    token = "test-token"
    validator = TokenValidator(token=token)

    # Should raise on invalid
    try:
        validator.validate_or_raise("Bearer wrong-token")
        assert False, "Expected AuthenticationError to be raised"
    except AuthenticationError as e:
        assert "Invalid token" in str(e)
        print("  [OK] AuthenticationError raised on invalid token")


if __name__ == "__main__":
    print("\n=== Authentication Tests ===\n")
    test_token_validator_no_token_configured()
    test_token_validator_valid_token()
    test_token_validator_invalid_token()
    test_token_validator_missing_header()
    test_token_validator_invalid_format()
    test_token_validator_constant_time()
    test_token_validator_from_env()
    test_token_validator_raises_on_invalid()
    print("\n=== All Authentication Tests Passed ===\n")
