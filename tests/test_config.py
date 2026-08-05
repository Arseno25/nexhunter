"""Typed configuration validation."""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.config import Config, ConfigError, generate_token

# Every variable the loader reads, so a test starts from a known state rather
# than inheriting whatever the developer's shell happens to have set.
_MANAGED = [
    "NEXHUNTER_ENVIRONMENT", "NEXHUNTER_API_TOKEN", "NEXHUNTER_BIND_HOST",
    "NEXHUNTER_BIND_PORT", "NEXHUNTER_EXTERNAL_BIND_ALLOWED", "NEXHUNTER_DATA_DIR",
    "NEXHUNTER_AUDIT_LOG_PATH", "NEXHUNTER_LOG_LEVEL", "NEXHUNTER_MAX_REQUEST_BYTES",
    "NEXHUNTER_MAX_OUTPUT_BYTES", "NEXHUNTER_DEFAULT_TIMEOUT",
    "NEXHUNTER_PROCESS_TERMINATION_GRACE", "NEXHUNTER_CACHE_ENABLED",
    "NEXHUNTER_CACHE_TTL", "NEXHUNTER_CACHE_MAX_ENTRIES", "NEXHUNTER_ENFORCE",
    "NEXHUNTER_ENGAGEMENT", "NEXHUNTER_DEFAULT_ROLE", "NEXHUNTER_MCP_PROFILE",
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

def test_defaults_are_secure():
    """An empty environment produces a safe configuration."""
    print("[TEST] Secure defaults...")
    with _CleanEnv() as config:
        assert config.bind_host == "127.0.0.1", "must default to loopback"
        assert config.external_bind_allowed is False
        assert config.enforce is True, "scope enforcement must default on"
        assert config.destructive_tools_enabled is False
        assert config.intrusive_tools_enabled is False
        assert config.environment == "development"
    print("  [OK] Defaults are the safe ones")


def test_boolean_parsing():
    """Booleans accept the usual spellings and reject nonsense."""
    print("[TEST] Boolean parsing...")
    for value in ("true", "1", "yes", "on", "TRUE"):
        with _CleanEnv(NEXHUNTER_ENFORCE=value) as config:
            assert config.enforce is True, f"{value!r} should be true"
    for value in ("false", "0", "no", "off"):
        with _CleanEnv(NEXHUNTER_ENFORCE=value) as config:
            assert config.enforce is False, f"{value!r} should be false"

    # A typo must not quietly become a default.
    _expect_error("not a boolean", NEXHUNTER_ENFORCE="maybe")
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
    with _CleanEnv(NEXHUNTER_ENVIRONMENT="production", NEXHUNTER_API_TOKEN="x" * 20) as config:
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
    print("  [OK] External bind must be explicit")


def test_external_bind_requires_a_token():
    """Binding externally without a token would expose an open API."""
    print("[TEST] External bind requires a token...")
    with _CleanEnv(
        NEXHUNTER_BIND_HOST="0.0.0.0",
        NEXHUNTER_EXTERNAL_BIND_ALLOWED="true",
    ) as config:
        errors = config.validate()
        assert any("unauthenticated API" in e for e in errors), errors

    with _CleanEnv(
        NEXHUNTER_BIND_HOST="0.0.0.0",
        NEXHUNTER_EXTERNAL_BIND_ALLOWED="true",
        NEXHUNTER_API_TOKEN="a-sufficiently-long-token",
    ) as config:
        assert config.validate() == [], "an external bind with a token is allowed"
    print("  [OK] Token required to bind externally")


def test_production_requires_a_strong_token():
    """Production will not start without a real token."""
    print("[TEST] Production token rules...")
    with _CleanEnv(NEXHUNTER_ENVIRONMENT="production") as config:
        assert any("required in production" in e for e in config.validate())

    with _CleanEnv(NEXHUNTER_ENVIRONMENT="production", NEXHUNTER_API_TOKEN="short") as config:
        assert any("too short" in e for e in config.validate())

    with _CleanEnv(
        NEXHUNTER_ENVIRONMENT="production",
        NEXHUNTER_API_TOKEN=generate_token(),
    ) as config:
        assert config.validate() == [], "a generated token should satisfy production"
    print("  [OK] Production token enforced")


def test_production_refuses_unsafe_combinations():
    """Production refuses disabled enforcement and destructive tools."""
    print("[TEST] Production refuses unsafe settings...")
    token = generate_token()

    with _CleanEnv(
        NEXHUNTER_ENVIRONMENT="production",
        NEXHUNTER_API_TOKEN=token,
        NEXHUNTER_ENFORCE="false",
    ) as config:
        assert any("must not be disabled in production" in e for e in config.validate())

    with _CleanEnv(
        NEXHUNTER_ENVIRONMENT="production",
        NEXHUNTER_API_TOKEN=token,
        NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED="true",
    ) as config:
        assert any("DESTRUCTIVE" in e for e in config.validate())
    print("  [OK] Unsafe production combinations refused")


def test_missing_referenced_files_reported():
    """A path setting pointing at nothing is a startup error."""
    print("[TEST] Missing referenced files reported...")
    with _CleanEnv(NEXHUNTER_ENGAGEMENT="/nope/missing-engagement.json") as config:
        assert any("missing file" in e for e in config.validate())

    with _CleanEnv(NEXHUNTER_ALLOWED_PATHS="/nope/not-a-real-directory") as config:
        assert any("does not exist" in e for e in config.validate())
    print("  [OK] Missing paths reported")


def test_validate_or_raise_reports_every_problem():
    """All problems are reported at once, not one per restart."""
    print("[TEST] All problems reported together...")
    with _CleanEnv(
        NEXHUNTER_ENVIRONMENT="production",
        NEXHUNTER_BIND_HOST="0.0.0.0",
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
    with _CleanEnv(NEXHUNTER_ENFORCE="false") as config:
        notes = config.warnings()
        assert any("No API token" in n for n in notes)
        assert any("enforcement is disabled" in n for n in notes)

    with _CleanEnv(
        NEXHUNTER_API_TOKEN=generate_token(),
        NEXHUNTER_INTRUSIVE_TOOLS_ENABLED="true",
    ) as config:
        assert any("Intrusive tools are ENABLED" in n for n in config.warnings())
    print("  [OK] Risky settings warned about")


def test_token_masked_in_serialization():
    """The token is never emitted by default."""
    print("[TEST] Token masked...")
    with _CleanEnv(NEXHUNTER_API_TOKEN="super-secret-token-value") as config:
        payload = config.to_dict()
        assert payload["api_token"] == "[SET]"
        assert "super-secret-token-value" not in str(payload)

        assert config.to_dict(include_secrets=True)["api_token"] == "super-secret-token-value"
    print("  [OK] Token masked unless explicitly requested")


def test_generated_token_is_strong():
    """Generated tokens satisfy the production length rule."""
    print("[TEST] Generated token strength...")
    token = generate_token()
    assert len(token) >= 32
    assert generate_token() != token, "tokens must not repeat"
    print("  [OK] Tokens strong and unique")


def test_existing_paths_accepted(tmp: Path):
    """Paths that exist validate cleanly."""
    print("[TEST] Existing paths accepted...")
    engagement = tmp / "engagement.json"
    engagement.write_text("{}", encoding="utf-8")

    with _CleanEnv(
        NEXHUNTER_ENGAGEMENT=str(engagement),
        NEXHUNTER_ALLOWED_PATHS=str(tmp),
    ) as config:
        assert config.validate() == [], "existing paths should validate"
        assert config.engagement_file == engagement
        assert tmp in config.allowed_paths
    print("  [OK] Existing paths accepted")


if __name__ == "__main__":
    print("\n=== Configuration Tests ===\n")
    test_defaults_are_secure()
    test_boolean_parsing()
    test_integer_bounds_enforced()
    test_choice_validation()
    test_external_bind_requires_opt_in()
    test_external_bind_requires_a_token()
    test_production_requires_a_strong_token()
    test_production_refuses_unsafe_combinations()
    test_missing_referenced_files_reported()
    test_validate_or_raise_reports_every_problem()
    test_warnings_flag_loose_settings()
    test_token_masked_in_serialization()
    test_generated_token_is_strong()
    with tempfile.TemporaryDirectory() as raw:
        test_existing_paths_accepted(Path(raw))
    print("\n=== All Configuration Tests Passed ===\n")
