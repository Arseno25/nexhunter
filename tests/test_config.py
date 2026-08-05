"""Typed configuration validation."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.config import Config, ConfigError

# Every variable the loader reads, so a test starts from a known state rather
# than inheriting whatever the developer's shell happens to have set.
_MANAGED = [
    "NEXHUNTER_ENVIRONMENT", "NEXHUNTER_BIND_HOST",
    "NEXHUNTER_BIND_PORT", "NEXHUNTER_EXTERNAL_BIND_ALLOWED", "NEXHUNTER_DATA_DIR",
    "NEXHUNTER_LOG_LEVEL", "NEXHUNTER_MAX_REQUEST_BYTES",
    "NEXHUNTER_MAX_OUTPUT_BYTES", "NEXHUNTER_DEFAULT_TIMEOUT",
    "NEXHUNTER_PROCESS_TERMINATION_GRACE", "NEXHUNTER_CACHE_ENABLED",
    "NEXHUNTER_CACHE_TTL", "NEXHUNTER_CACHE_MAX_ENTRIES", "NEXHUNTER_MCP_PROFILE",
    "NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED", "NEXHUNTER_INTRUSIVE_TOOLS_ENABLED",
    "NEXHUNTER_ALLOWED_PATHS",
]


class _CleanEnv:
    """Run with only the variables a test sets."""

    def __init__(self, **values):
        self.values = values
        self.saved = {}

    def __enter__(self) -> Config:
        for key in _MANAGED:
            self.saved[key] = os.environ.pop(key, None)
        for key, value in self.values.items():
            os.environ[key] = str(value)
        return Config.from_env()

    def __exit__(self, *exc):
        for key in _MANAGED:
            os.environ.pop(key, None)
        for key, value in self.saved.items():
            if value is not None:
                os.environ[key] = value


def _expect_error(message_fragment: str, **env):
    """Assert that loading this environment raises, and return the message."""
    try:
        with _CleanEnv(**env):
            pass
    except ConfigError as exc:
        assert message_fragment in str(exc), f"unexpected message: {exc}"
        return str(exc)
    raise AssertionError(f"expected ConfigError for {env}")


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def test_defaults():
    """An empty environment produces the defaults."""
    print("[TEST] Defaults...")
    with _CleanEnv() as config:
        assert config.bind_host == "127.0.0.1", "must default to loopback"
        assert config.external_bind_allowed is False
        assert config.destructive_tools_enabled is False
        assert config.intrusive_tools_enabled is False
        assert config.environment == "development"
    print("  [OK] Defaults are the safe ones")


def test_boolean_parsing():
    """Booleans accept the usual spellings and reject nonsense."""
    print("[TEST] Boolean parsing...")
    for value in ("true", "1", "yes", "on", "TRUE"):
        with _CleanEnv(NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED=value) as config:
            assert config.destructive_tools_enabled is True, f"{value!r} should be true"
    for value in ("false", "0", "no", "off"):
        with _CleanEnv(NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED=value) as config:
            assert config.destructive_tools_enabled is False, f"{value!r} should be false"

    # A typo must not quietly become a default.
    _expect_error("not a boolean", NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED="maybe")
    print("  [OK] Booleans parsed, typos rejected")


def test_integer_bounds_enforced():
    """Out-of-range numbers are refused rather than clamped."""
    print("[TEST] Integer bounds...")
    with _CleanEnv(NEXHUNTER_BIND_PORT="9000") as config:
        assert config.bind_port == 9000

    _expect_error("not an integer", NEXHUNTER_BIND_PORT="http")
    _expect_error("above the maximum", NEXHUNTER_BIND_PORT="70000")
    _expect_error("below the minimum", NEXHUNTER_BIND_PORT="0")
    _expect_error("above the maximum", NEXHUNTER_DEFAULT_TIMEOUT="999999")
    print("  [OK] Bounds enforced")


def test_choice_validation():
    """Enumerated settings reject values outside their set."""
    print("[TEST] Choice validation...")
    with _CleanEnv(NEXHUNTER_ENVIRONMENT="production") as config:
        assert config.is_production

    _expect_error("must be one of", NEXHUNTER_ENVIRONMENT="prod")
    _expect_error("must be one of", NEXHUNTER_LOG_LEVEL="VERBOSE")
    print("  [OK] Choices validated")


# --------------------------------------------------------------------------
# Validation rules
# --------------------------------------------------------------------------

def test_external_bind_requires_opt_in():
    """Binding off loopback without opting in is a startup error."""
    print("[TEST] External bind requires opt-in...")
    with _CleanEnv(NEXHUNTER_BIND_HOST="0.0.0.0") as config:
        errors = config.validate()
        assert any("EXTERNAL_BIND_ALLOWED" in e for e in errors), errors

    with _CleanEnv(
        NEXHUNTER_BIND_HOST="0.0.0.0",
        NEXHUNTER_EXTERNAL_BIND_ALLOWED="true",
    ) as config:
        assert config.validate() == [], "an opted-in external bind is allowed"
    print("  [OK] External bind must be explicit")


def test_production_refuses_destructive_tools():
    """Production refuses destructive tools."""
    print("[TEST] Production refuses destructive tools...")
    with _CleanEnv(
        NEXHUNTER_ENVIRONMENT="production",
        NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED="true",
    ) as config:
        assert any("DESTRUCTIVE" in e for e in config.validate())

    with _CleanEnv(NEXHUNTER_ENVIRONMENT="production") as config:
        assert config.validate() == [], "plain production should validate"
    print("  [OK] Unsafe production settings refused")


def test_missing_referenced_paths_reported():
    """A path setting pointing at nothing is a startup error."""
    print("[TEST] Missing referenced paths reported...")
    with _CleanEnv(NEXHUNTER_ALLOWED_PATHS="/nope/not-a-real-directory") as config:
        assert any("does not exist" in e for e in config.validate())
    print("  [OK] Missing paths reported")


def test_validate_or_raise_reports_every_problem():
    """All problems are reported at once, not one per restart."""
    print("[TEST] All problems reported together...")
    with _CleanEnv(
        NEXHUNTER_ENVIRONMENT="production",
        NEXHUNTER_BIND_HOST="0.0.0.0",
        NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED="true",
    ) as config:
        try:
            config.validate_or_raise()
            assert False, "expected ConfigError"
        except ConfigError as exc:
            message = str(exc)
            assert message.count("-") >= 2, f"expected several problems listed:\n{message}"
    print("  [OK] Problems reported together")


# --------------------------------------------------------------------------
# Warnings and serialization
# --------------------------------------------------------------------------

def test_warnings_flag_loose_settings():
    """Non-fatal but risky settings are surfaced."""
    print("[TEST] Warnings for loose settings...")
    with _CleanEnv() as config:
        assert config.warnings() == [], "defaults should not warn"

    with _CleanEnv(
        NEXHUNTER_INTRUSIVE_TOOLS_ENABLED="true",
    ) as config:
        assert any("Intrusive tools are ENABLED" in n for n in config.warnings())
    print("  [OK] Risky settings warned about")


def test_serialization_has_no_secrets():
    """The serialized config carries no secrets at all."""
    print("[TEST] Serialization clean...")
    with _CleanEnv() as config:
        payload = config.to_dict()
        assert "api_token" not in payload
        assert "enforce" not in payload
        assert "engagement" not in payload
        assert "audit" not in payload
    print("  [OK] No auth/scope/audit settings serialized")


def test_existing_paths_accepted(tmp: Path):
    """Paths that exist validate cleanly."""
    print("[TEST] Existing paths accepted...")
    with _CleanEnv(
        NEXHUNTER_ALLOWED_PATHS=str(tmp),
    ) as config:
        assert config.validate() == [], "existing paths should validate"
        assert tmp in config.allowed_paths
    print("  [OK] Existing paths accepted")


if __name__ == "__main__":
    print("\n=== Configuration Tests ===\n")
    test_defaults()
    test_boolean_parsing()
    test_integer_bounds_enforced()
    test_choice_validation()
    test_external_bind_requires_opt_in()
    test_production_refuses_destructive_tools()
    test_missing_referenced_paths_reported()
    test_validate_or_raise_reports_every_problem()
    test_warnings_flag_loose_settings()
    test_serialization_has_no_secrets()
    with tempfile.TemporaryDirectory() as raw:
        test_existing_paths_accepted(Path(raw))
    print("\n=== All Configuration Tests Passed ===\n")
