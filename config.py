"""Typed configuration, validated at startup.

Settings were read ad hoc with os.environ.get() across a dozen modules, which
meant a typo in a variable name silently produced a default, and an invalid
value only surfaced when something tried to use it. Both failure modes are bad
here: the defaults being silently reinstated are security settings.

Nothing falls back to a less safe value. A malformed setting raises, because
running with an unintended security posture is worse than not starting.
"""

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", ""}

VALID_ENVIRONMENTS = ("development", "staging", "production")
VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


class ConfigError(Exception):
    """Configuration is invalid. Raised at startup, never swallowed."""


def _get(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _flag(name: str, default: bool) -> bool:
    raw = _get(name).lower()
    if not raw:
        return default
    if raw in TRUE_VALUES:
        return True
    if raw in FALSE_VALUES:
        return False
    raise ConfigError(
        f"{name}={raw!r} is not a boolean (use true/false)"
    )


def _integer(name: str, default: int, minimum: int = 0, maximum: Optional[int] = None) -> int:
    raw = _get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name}={raw!r} is not an integer") from None
    if value < minimum:
        raise ConfigError(f"{name}={value} is below the minimum of {minimum}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{name}={value} is above the maximum of {maximum}")
    return value


def _choice(name: str, default: str, choices: tuple) -> str:
    raw = _get(name) or default
    if raw.lower() not in {c.lower() for c in choices}:
        raise ConfigError(f"{name}={raw!r} must be one of: {', '.join(choices)}")
    return raw


@dataclass(frozen=True)
class Config:
    """Validated runtime configuration."""

    environment: str = "development"
    api_token: str = ""
    bind_host: str = "127.0.0.1"
    bind_port: int = 8888
    external_bind_allowed: bool = False

    data_dir: Path = field(default_factory=lambda: Path.cwd() / "nexhunter_data")
    audit_log_path: Optional[Path] = None
    log_level: str = "INFO"

    max_request_bytes: int = 1_048_576
    max_output_bytes: int = 10_485_760
    default_timeout: int = 300
    process_termination_grace: int = 5

    cache_enabled: bool = True
    cache_ttl: int = 600
    cache_max_entries: int = 1000

    enforce: bool = True
    engagement_file: Optional[Path] = None
    default_role: str = "operator"
    mcp_profile: str = "nexhunter-core"

    destructive_tools_enabled: bool = False
    intrusive_tools_enabled: bool = False
    allowed_paths: tuple = ()

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def binds_externally(self) -> bool:
        return self.bind_host not in LOOPBACK_HOSTS

    @classmethod
    def from_env(cls) -> "Config":
        """Build configuration from the environment, validating as it goes."""
        data_dir_raw = _get("NEXHUNTER_DATA_DIR")
        audit_raw = _get("NEXHUNTER_AUDIT_LOG_PATH")
        engagement_raw = _get("NEXHUNTER_ENGAGEMENT")
        paths_raw = _get("NEXHUNTER_ALLOWED_PATHS")

        return cls(
            environment=_choice("NEXHUNTER_ENVIRONMENT", "development", VALID_ENVIRONMENTS).lower(),
            api_token=_get("NEXHUNTER_API_TOKEN"),
            bind_host=_get("NEXHUNTER_BIND_HOST", "127.0.0.1"),
            bind_port=_integer("NEXHUNTER_BIND_PORT", 8888, minimum=1, maximum=65535),
            external_bind_allowed=_flag("NEXHUNTER_EXTERNAL_BIND_ALLOWED", False),

            data_dir=Path(data_dir_raw).expanduser() if data_dir_raw else Path.cwd() / "nexhunter_data",
            audit_log_path=Path(audit_raw).expanduser() if audit_raw else None,
            log_level=_choice("NEXHUNTER_LOG_LEVEL", "INFO", VALID_LOG_LEVELS).upper(),

            max_request_bytes=_integer("NEXHUNTER_MAX_REQUEST_BYTES", 1_048_576, minimum=1024),
            max_output_bytes=_integer("NEXHUNTER_MAX_OUTPUT_BYTES", 10_485_760, minimum=1024),
            default_timeout=_integer("NEXHUNTER_DEFAULT_TIMEOUT", 300, minimum=1, maximum=86400),
            process_termination_grace=_integer("NEXHUNTER_PROCESS_TERMINATION_GRACE", 5, minimum=0, maximum=300),

            cache_enabled=_flag("NEXHUNTER_CACHE_ENABLED", True),
            cache_ttl=_integer("NEXHUNTER_CACHE_TTL", 600, minimum=0),
            cache_max_entries=_integer("NEXHUNTER_CACHE_MAX_ENTRIES", 1000, minimum=0),

            enforce=_flag("NEXHUNTER_ENFORCE", True),
            engagement_file=Path(engagement_raw).expanduser() if engagement_raw else None,
            default_role=_get("NEXHUNTER_DEFAULT_ROLE", "operator"),
            mcp_profile=_get("NEXHUNTER_MCP_PROFILE", "nexhunter-core"),

            destructive_tools_enabled=_flag("NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED", False),
            intrusive_tools_enabled=_flag("NEXHUNTER_INTRUSIVE_TOOLS_ENABLED", False),
            allowed_paths=tuple(
                Path(entry.strip()).expanduser()
                for entry in paths_raw.split(os.pathsep) if entry.strip()
            ),
        )

    def validate(self) -> List[str]:
        """Return configuration errors that must stop startup.

        The production rules are stricter because the failure modes differ: a
        missing token on a laptop is an inconvenience, and on a reachable host
        it is an open API.
        """
        errors: List[str] = []

        if self.binds_externally and not self.external_bind_allowed:
            errors.append(
                f"NEXHUNTER_BIND_HOST={self.bind_host} is not loopback but "
                "NEXHUNTER_EXTERNAL_BIND_ALLOWED is not set"
            )

        if self.binds_externally and not self.api_token:
            errors.append(
                "binding outside loopback without NEXHUNTER_API_TOKEN would expose "
                "an unauthenticated API"
            )

        if self.is_production:
            if not self.api_token:
                errors.append("NEXHUNTER_API_TOKEN is required in production")
            elif len(self.api_token) < 16:
                errors.append("NEXHUNTER_API_TOKEN is too short (use at least 16 characters)")
            if not self.enforce:
                errors.append("NEXHUNTER_ENFORCE must not be disabled in production")
            if self.destructive_tools_enabled:
                errors.append("NEXHUNTER_DESTRUCTIVE_TOOLS_ENABLED must not be set in production")

        if self.engagement_file is not None and not self.engagement_file.is_file():
            errors.append(f"NEXHUNTER_ENGAGEMENT points at a missing file: {self.engagement_file}")

        for path in self.allowed_paths:
            if not path.exists():
                errors.append(f"NEXHUNTER_ALLOWED_PATHS entry does not exist: {path}")

        return errors

    def warnings(self) -> List[str]:
        """Non-fatal issues worth printing at startup."""
        notes: List[str] = []

        if not self.api_token:
            notes.append("No API token set; the API will accept any caller on this host")
        if not self.enforce:
            notes.append("Scope enforcement is disabled; no engagement scope will be applied")
        if self.binds_externally:
            notes.append(f"Server binds to {self.bind_host}, which is reachable from other hosts")
        if self.destructive_tools_enabled:
            notes.append("Destructive tools are ENABLED")
        if self.intrusive_tools_enabled:
            notes.append("Intrusive tools are ENABLED")

        return notes

    def validate_or_raise(self) -> "Config":
        """Validate, raising ConfigError with every problem at once."""
        errors = self.validate()
        if errors:
            raise ConfigError(
                "invalid configuration:\n  - " + "\n  - ".join(errors)
            )
        return self

    def to_dict(self, include_secrets: bool = False) -> dict:
        """Serializable view. The token is masked unless explicitly requested."""
        return {
            "environment": self.environment,
            "api_token": (self.api_token if include_secrets else
                          ("[SET]" if self.api_token else "[UNSET]")),
            "bind_host": self.bind_host,
            "bind_port": self.bind_port,
            "external_bind_allowed": self.external_bind_allowed,
            "data_dir": str(self.data_dir),
            "audit_log_path": str(self.audit_log_path) if self.audit_log_path else None,
            "log_level": self.log_level,
            "max_request_bytes": self.max_request_bytes,
            "max_output_bytes": self.max_output_bytes,
            "default_timeout": self.default_timeout,
            "process_termination_grace": self.process_termination_grace,
            "cache_enabled": self.cache_enabled,
            "cache_ttl": self.cache_ttl,
            "cache_max_entries": self.cache_max_entries,
            "enforce": self.enforce,
            "engagement_file": str(self.engagement_file) if self.engagement_file else None,
            "default_role": self.default_role,
            "mcp_profile": self.mcp_profile,
            "destructive_tools_enabled": self.destructive_tools_enabled,
            "intrusive_tools_enabled": self.intrusive_tools_enabled,
            "allowed_paths": [str(p) for p in self.allowed_paths],
        }


def generate_token(length: int = 32) -> str:
    """A token suitable for NEXHUNTER_API_TOKEN."""
    return secrets.token_urlsafe(length)


_cached: Optional[Config] = None


def load(refresh: bool = False) -> Config:
    """Load and cache configuration from the environment."""
    global _cached
    if _cached is None or refresh:
        _cached = Config.from_env()
    return _cached
