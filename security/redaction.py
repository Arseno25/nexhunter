"""Secret detection and redaction for logs and output."""

import re
from typing import Any, Dict, List
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

    def redact_command(self, cmd_args: List[str]) -> List[str]:
        """
        Redact secrets from command arguments.

        Redact values that follow known secret flags.
        """
        secret_flags = {
            "-p",
            "--password",
            "--api-key",
            "-k",
            "--key",
            "-t",
            "--token",
            "--secret",
            "-s",
            "--auth",
            "--authorization",
        }

        redacted = []
        skip_next = False

        for i, arg in enumerate(cmd_args):
            if skip_next:
                redacted.append("[REDACTED]")
                skip_next = False
                continue

            arg_lower = arg.lower()

            # Check if this arg is a secret flag
            if arg_lower in secret_flags:
                redacted.append(arg)
                skip_next = True
                continue

            # Check if arg contains secret in value form (--key=value)
            if "=" in arg:
                key, value = arg.split("=", 1)
                if any(flag.replace("-", "") in key.lower() for flag in secret_flags):
                    redacted.append(f"{key}=[REDACTED]")
                    continue

            # Redact if contains detectable secret
            if self.contains_secret(arg):
                redacted.append("[REDACTED]")
            else:
                redacted.append(arg)

        return redacted
