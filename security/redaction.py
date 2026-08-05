"""Secret detection and redaction for logs and output."""

import re
from typing import Any, Dict, List, Optional
from dataclasses import dataclass


@dataclass
class RedactionPattern:
    """Pattern for detecting secrets."""

    name: str
    patterns: List[str]  # Regex patterns to match
    mask: str = "[REDACTED]"

    def matches(self, value: str) -> bool:
        """Check if value matches this pattern."""
        for pattern in self.patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False


class SecretRedactor:
    """Detect and redact secrets from text and data structures."""

    # Patterns for common secrets
    PATTERNS = [
        RedactionPattern(
            name="API_KEY",
            patterns=[
                r"api[_-]?key\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
                r"apikey\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?",
                r"\bapi[_-]?key\b",
            ],
        ),
        RedactionPattern(
            name="AWS_KEY",
            patterns=[
                r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
                r"aws_access_key_id\s*[:=]",
                r"aws_secret_access_key\s*[:=]",
            ],
        ),
        RedactionPattern(
            name="GITHUB_TOKEN",
            patterns=[
                r"ghp_[a-zA-Z0-9_]{36}",
                r"github[_-]?token\s*[:=]",
                r"ghs_[a-zA-Z0-9_]{36}",
            ],
        ),
        RedactionPattern(
            name="PASSWORD",
            patterns=[
                r"password\s*[:=]\s*['\"]?([^\s'\"]+)['\"]?",
                r"passwd\s*[:=]",
                r"pwd\s*[:=]",
            ],
        ),
        RedactionPattern(
            name="PRIVATE_KEY",
            patterns=[
                r"-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY",
                r"private[_-]?key\s*[:=]",
                r"privatekey\s*[:=]",
            ],
        ),
        RedactionPattern(
            name="BEARER_TOKEN",
            patterns=[
                r"bearer\s+[a-zA-Z0-9\-._~+/]+=*",
                r"authorization\s*[:=]\s*bearer",
            ],
        ),
        RedactionPattern(
            name="JWT_TOKEN",
            patterns=[
                r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
            ],
        ),
        RedactionPattern(
            name="DATABASE_CONNECTION",
            patterns=[
                r"(mysql|postgres|postgresql|mongodb|redis|amqp)(\+[a-z0-9_]+)?://[^\s:/]+:[^\s@]+@",
            ],
        ),
        RedactionPattern(
            name="CREDIT_CARD",
            patterns=[
                r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
            ],
        ),
        RedactionPattern(
            name="EMAIL",
            patterns=[
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            ],
        ),
        RedactionPattern(
            name="SLACK_TOKEN",
            patterns=[
                r"xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",
            ],
        ),
    ]

    # Key names whose value is a secret regardless of the value's own shape.
    SECRET_KEY_NAMES = (
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "api-key", "access_key", "secret_key", "private_key", "privatekey",
        "auth", "authorization", "credential", "session", "cookie",
    )

    def __init__(self, patterns: List[RedactionPattern] = None):
        """Initialize with patterns."""
        self.patterns = patterns or self.PATTERNS

    def is_secret_key(self, key: str) -> bool:
        """Check if a field name marks its value as secret."""
        normalized = str(key).lower().replace("-", "_")
        return any(name.replace("-", "_") in normalized for name in self.SECRET_KEY_NAMES)

    def redact_string(self, value: str) -> str:
        """Redact secrets from string."""
        if not isinstance(value, str):
            return value

        result = value
        for pattern in self.patterns:
            for regex in pattern.patterns:
                result = re.sub(regex, pattern.mask, result, flags=re.IGNORECASE)

        return result

    def redact_dict(self, data: Dict[str, Any], recursive: bool = True) -> Dict[str, Any]:
        """Redact secrets from dictionary (keys and values)."""
        if not isinstance(data, dict):
            return data

        redacted = {}
        for key, value in data.items():
            # Check key for secrets
            redacted_key = self.redact_string(str(key))

            # A secret-named key masks its value whatever the value looks like
            if self.is_secret_key(key) and not isinstance(value, (dict, list, tuple)):
                redacted[redacted_key] = "[REDACTED]"
                continue

            # Check value for secrets
            if isinstance(value, str):
                redacted[redacted_key] = self.redact_string(value)
            elif isinstance(value, dict) and recursive:
                redacted[redacted_key] = self.redact_dict(value, recursive=True)
            elif isinstance(value, (list, tuple)) and recursive:
                redacted[redacted_key] = self.redact_list(value, recursive=True)
            else:
                redacted[redacted_key] = value

        return redacted

    def redact_list(self, data: List[Any], recursive: bool = True) -> List[Any]:
        """Redact secrets from list."""
        if not isinstance(data, (list, tuple)):
            return data

        redacted = []
        for item in data:
            if isinstance(item, str):
                redacted.append(self.redact_string(item))
            elif isinstance(item, dict) and recursive:
                redacted.append(self.redact_dict(item, recursive=True))
            elif isinstance(item, (list, tuple)) and recursive:
                redacted.append(self.redact_list(item, recursive=True))
            else:
                redacted.append(item)

        return redacted

    def contains_secret(self, value: str) -> bool:
        """Check if string contains any detected secrets."""
        if not isinstance(value, str):
            return False

        for pattern in self.patterns:
            if pattern.matches(value):
                return True

        return False

    # Single-letter flags mean different things per tool: -p is a password to
    # hydra but a port list to nmap. Treating it as secret everywhere would
    # mask nmap's ports in every record; treating it as safe everywhere
    # would write hydra's password to disk. So it is resolved per binary.
    # ponytail: hand-maintained map. The real fix is a per-parameter secret
    # marker on ToolSpec, which lands with typed parameters.
    SHORT_SECRET_FLAGS_BY_TOOL = {
        "hydra": {"-p", "-P"},
        "medusa": {"-p"},
        "ncrack": {"-p"},
        "patator": {"-p"},
        "smbmap": {"-p"},
        "crackmapexec": {"-p"},
        "netexec": {"-p"},
        "nxc": {"-p"},
        "evil-winrm": {"-p"},
        "mysql": {"-p"},
        "psql": {"-p"},
        "redis-cli": {"-a"},
        "curl": {"-u"},
        "wget": {"-p"},
    }

    @classmethod
    def _short_secret_flags(cls, argv: List[str]) -> set:
        """Short flags that carry a secret for the binary being invoked."""
        if not argv:
            return set()
        binary = str(argv[0]).replace("\\", "/").rsplit("/", 1)[-1].lower()
        if binary.endswith(".exe"):
            binary = binary[:-4]
        return cls.SHORT_SECRET_FLAGS_BY_TOOL.get(binary, set())

    def is_secret_flag(self, arg: str, short_flags: Optional[set] = None) -> bool:
        """Check if a command-line flag introduces a secret value.

        Long flags match on their name rather than an exact list, so
        --api-token, --auth-token, and --password-file are all covered; an
        exact-membership check silently leaked every flag nobody thought of.
        """
        if not arg.startswith("-"):
            return False
        if short_flags and arg in short_flags:
            return True
        name = arg.lstrip("-")
        if len(name) < 2:
            return False
        return self.is_secret_key(name)

    def redact_command(
        self,
        cmd_args: List[str],
        secret_values: Optional[List[str]] = None,
    ) -> List[str]:
        """Redact secret values from an argument list.

        `secret_values` are the exact values a tool's schema declared secret.
        Masking those is precise, where matching on flag names could only
        guess; the name and pattern heuristics below stay as a backstop for
        callers that have no schema to hand.
        """
        redacted: List[str] = []
        skip_next = False
        short_flags = self._short_secret_flags(cmd_args)
        known_secrets = {str(v) for v in (secret_values or []) if str(v)}

        for arg in cmd_args:
            arg = str(arg)

            # An exact value the schema marked secret, wherever it appears.
            if known_secrets and arg in known_secrets:
                redacted.append("[REDACTED]")
                skip_next = False
                continue
            if known_secrets and "=" in arg:
                flag, _, value = arg.partition("=")
                if value in known_secrets:
                    redacted.append(f"{flag}=[REDACTED]")
                    skip_next = False
                    continue

            if skip_next:
                redacted.append("[REDACTED]")
                skip_next = False
                continue

            # --token=VALUE. Checked first: the whole "--token=VALUE" string
            # also looks like a secret flag, and treating it as one would mask
            # the following argument while leaking this one.
            if arg.startswith("-") and "=" in arg:
                flag, _ = arg.split("=", 1)
                if self.is_secret_flag(flag, short_flags):
                    redacted.append(f"{flag}=[REDACTED]")
                    continue

            # --token VALUE
            if self.is_secret_flag(arg, short_flags):
                redacted.append(arg)
                skip_next = True
                continue

            # A bare argument that looks like a credential on its own.
            if self.contains_secret(arg):
                redacted.append(self.redact_string(arg))
            else:
                redacted.append(arg)

        return redacted
