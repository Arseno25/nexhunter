"""Typed parameter validation for tool arguments.

Every value a caller supplies is checked against a declared type before it
reaches a command builder. This is the layer that turns "a model said something"
into "a validated hostname", and it is where option injection, path traversal,
and null bytes are stopped.

Validation is total: a parameter either produces a normalized value or an
error. There is no pass-through case, because a value nobody checked is a value
an attacker chose.
"""

import ipaddress
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Sequence, Tuple
from urllib.parse import urlparse, urlunparse


class ParamType(Enum):
    """Declared type of a tool parameter."""

    STRING = "string"
    BOOLEAN = "boolean"
    INTEGER = "integer"
    ENUM = "enum"
    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    TARGET = "target"  # hostname, IP, CIDR, or URL
    URL = "url"
    PORT = "port"
    PORT_RANGE = "port_range"
    FILE = "file"
    DIRECTORY = "directory"
    WORDLIST = "wordlist"
    DURATION = "duration"


class ValidationError(Exception):
    """A parameter value was rejected."""


MAX_VALUE_LENGTH = 2048
SAFE_URL_SCHEMES = frozenset({"http", "https"})

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_HAS_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
_DURATION = re.compile(r"^(\d+)([smhd]?)$", re.IGNORECASE)
_DURATION_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def _reject_control_characters(value: str) -> None:
    """Reject null bytes and anything else that could split an argument.

    argv is passed to the OS without a shell, so a newline is not a command
    separator here -- but it corrupts logs and output parsers, and a null byte
    truncates the string inside C-level APIs.
    """
    if "\x00" in value:
        raise ValidationError("value contains a null byte")
    if any(ord(character) < 32 for character in value if character not in "\t"):
        raise ValidationError("value contains a control character")


def _reject_option_injection(value: str) -> None:
    """Reject values that would be read as another command-line option.

    A target of "--script=http-shellshock" is a value that turns into a flag.
    Because arguments are positional in the builders, a leading dash lets a
    caller inject options into a tool they were only meant to point at a host.
    """
    if value.startswith("-"):
        raise ValidationError(f"value may not begin with '-' (looks like an option): {value!r}")


@dataclass(frozen=True)
class ParamSpec:
    """Declared type and constraints for one tool parameter."""

    name: str
    type: ParamType = ParamType.STRING
    required: bool = False
    default: Any = None
    description: str = ""
    choices: Tuple[str, ...] = ()
    minimum: Optional[int] = None
    maximum: Optional[int] = None
    max_length: int = MAX_VALUE_LENGTH
    # Marks a value as a credential, so redaction masks it wherever it appears.
    secret: bool = False

    def describe(self) -> dict:
        payload = {
            "name": self.name,
            "type": self.type.value,
            "required": self.required,
            "default": self.default,
            "description": self.description,
            "secret": self.secret,
        }
        if self.choices:
            payload["choices"] = list(self.choices)
        if self.minimum is not None:
            payload["minimum"] = self.minimum
        if self.maximum is not None:
            payload["maximum"] = self.maximum
        return payload

    def validate(self, value: Any) -> Any:
        """Validate and normalize one value. Raises ValidationError."""
        if value is None or value == "":
            if self.required:
                raise ValidationError(f"{self.name} is required")
            return self.default

        if isinstance(value, str):
            if len(value) > self.max_length:
                raise ValidationError(
                    f"{self.name} exceeds {self.max_length} characters"
                )
            _reject_control_characters(value)

        try:
            return _VALIDATORS[self.type](self, value)
        except ValidationError as exc:
            raise ValidationError(f"{self.name}: {exc}") from None


# ---------------------------------------------------------------------------
# Per-type validators
# ---------------------------------------------------------------------------

def _validate_string(spec: ParamSpec, value: Any) -> str:
    text = str(value).strip()
    _reject_option_injection(text)
    return text


def _validate_boolean(spec: ParamSpec, value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "on"}:
        return True
    if text in {"false", "0", "no", "off"}:
        return False
    raise ValidationError(f"not a boolean: {value!r}")


def _validate_integer(spec: ParamSpec, value: Any) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValidationError(f"not an integer: {value!r}") from None
    if spec.minimum is not None and number < spec.minimum:
        raise ValidationError(f"must be at least {spec.minimum}")
    if spec.maximum is not None and number > spec.maximum:
        raise ValidationError(f"must be at most {spec.maximum}")
    return number


def _validate_enum(spec: ParamSpec, value: Any) -> str:
    text = str(value).strip()
    if text not in spec.choices:
        raise ValidationError(f"must be one of: {', '.join(spec.choices)}")
    return text


def _validate_hostname(spec: ParamSpec, value: Any) -> str:
    text = str(value).strip().rstrip(".").lower()
    _reject_option_injection(text)
    if not text:
        raise ValidationError("hostname is empty")
    if not _HOSTNAME.match(text):
        raise ValidationError(f"not a valid hostname: {value!r}")
    return text


def _validate_ip(spec: ParamSpec, value: Any) -> str:
    text = str(value).strip()
    _reject_option_injection(text)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise ValidationError(f"not a valid IP address: {value!r}") from None


def _validate_cidr(spec: ParamSpec, value: Any) -> str:
    text = str(value).strip()
    _reject_option_injection(text)
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        raise ValidationError(f"not a valid CIDR block: {value!r}") from None


def _validate_url(spec: ParamSpec, value: Any) -> str:
    text = str(value).strip()
    _reject_option_injection(text)

    # Only add a scheme when there is genuinely none. Prepending "https://" to
    # "javascript:alert(1)" would turn a rejected scheme into a host named
    # "javascript" with a garbage port, hiding the thing worth rejecting.
    if _HAS_SCHEME.match(text):
        parsed = urlparse(text)
    else:
        parsed = urlparse(f"https://{text}")

    if parsed.scheme not in SAFE_URL_SCHEMES:
        raise ValidationError(
            f"unsupported URL scheme {parsed.scheme!r}; allowed: {', '.join(sorted(SAFE_URL_SCHEMES))}"
        )

    # urlparse defers parsing the netloc, so a malformed authority only raises
    # when hostname or port is read.
    try:
        hostname, port = parsed.hostname, parsed.port
    except ValueError as exc:
        raise ValidationError(f"malformed URL authority: {exc}") from None

    if not hostname:
        raise ValidationError(f"URL has no host: {value!r}")

    # Credentials in a URL end up in logs and process listings. Reject rather
    # than silently strip, so the caller knows they were dropped.
    if parsed.username or parsed.password:
        raise ValidationError("URL must not embed credentials")

    if port is not None and not (1 <= port <= 65535):
        raise ValidationError(f"invalid port in URL: {port}")

    return urlunparse(parsed._replace(netloc=parsed.netloc.lower()))


def _validate_target(spec: ParamSpec, value: Any) -> str:
    """A scan target: hostname, IP, CIDR, or URL.

    Kept deliberately permissive about *form* -- the operator decides what is
    worth scanning. What this rejects is anything that is not a target at all.
    """
    text = str(value).strip()
    _reject_option_injection(text)
    if not text:
        raise ValidationError("target is empty")

    if "://" in text:
        return _validate_url(spec, text)
    if "/" in text:
        return _validate_cidr(spec, text)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    return _validate_hostname(spec, text)


def _validate_port(spec: ParamSpec, value: Any) -> str:
    text = str(value).strip()
    try:
        port = int(text)
    except ValueError:
        raise ValidationError(f"not a port number: {value!r}") from None
    if not 1 <= port <= 65535:
        raise ValidationError(f"port out of range: {port}")
    return str(port)


def _validate_port_range(spec: ParamSpec, value: Any) -> str:
    """A port list or range, as tools like nmap accept: "80,443,8000-9000"."""
    text = str(value).strip()
    _reject_option_injection(text)
    if not text:
        raise ValidationError("port specification is empty")

    for part in text.split(","):
        part = part.strip()
        if not part:
            raise ValidationError(f"empty entry in port list: {value!r}")
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2:
                raise ValidationError(f"malformed port range: {part!r}")
            try:
                start, end = int(bounds[0]), int(bounds[1])
            except ValueError:
                raise ValidationError(f"malformed port range: {part!r}") from None
            if not (1 <= start <= end <= 65535):
                raise ValidationError(f"port range out of order or out of range: {part!r}")
        else:
            try:
                port = int(part)
            except ValueError:
                raise ValidationError(f"not a port number: {part!r}") from None
            if not 1 <= port <= 65535:
                raise ValidationError(f"port out of range: {port}")
    return text


def _resolve_path(spec: ParamSpec, value: Any, must_be: str) -> str:
    """Resolve a filesystem path, rejecting traversal and symlink escape."""
    text = str(value).strip()
    _reject_option_injection(text)
    if not text:
        raise ValidationError("path is empty")

    candidate = Path(os.path.expanduser(text))
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValidationError(f"path does not exist: {text}") from None

    if must_be == "file" and not resolved.is_file():
        raise ValidationError(f"not a file: {text}")
    if must_be == "directory" and not resolved.is_dir():
        raise ValidationError(f"not a directory: {text}")

    allowed_roots = _allowed_path_roots()
    if allowed_roots and not any(_is_within(resolved, root) for root in allowed_roots):
        raise ValidationError(
            f"path is outside the permitted roots: {text} "
            f"(set NEXHUNTER_ALLOWED_PATHS to widen)"
        )
    return str(resolved)


def _allowed_path_roots() -> Sequence[Path]:
    """Roots that file parameters may point at.

    Empty means unrestricted, which is the default: a local operator scanning
    their own filesystem should not have to configure this. Setting
    NEXHUNTER_ALLOWED_PATHS confines file inputs, which matters when the caller
    is a model or a remote client.
    """
    raw = os.environ.get("NEXHUNTER_ALLOWED_PATHS", "").strip()
    if not raw:
        return ()
    roots = []
    for entry in raw.split(os.pathsep):
        entry = entry.strip()
        if entry:
            try:
                roots.append(Path(entry).expanduser().resolve())
            except (OSError, RuntimeError):
                continue
    return tuple(roots)


def _is_within(candidate: Path, parent: Path) -> bool:
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _validate_file(spec: ParamSpec, value: Any) -> str:
    return _resolve_path(spec, value, "file")


def _validate_directory(spec: ParamSpec, value: Any) -> str:
    return _resolve_path(spec, value, "directory")


def _validate_wordlist(spec: ParamSpec, value: Any) -> str:
    return _resolve_path(spec, value, "file")


def _validate_duration(spec: ParamSpec, value: Any) -> str:
    """A duration like "30", "30s", "5m", "2h"."""
    text = str(value).strip()
    match = _DURATION.match(text)
    if not match:
        raise ValidationError(f"not a duration: {value!r} (try 30s, 5m, 2h)")
    amount, unit = int(match.group(1)), match.group(2).lower()
    seconds = amount * _DURATION_UNITS[unit]
    if spec.minimum is not None and seconds < spec.minimum:
        raise ValidationError(f"must be at least {spec.minimum}s")
    if spec.maximum is not None and seconds > spec.maximum:
        raise ValidationError(f"must be at most {spec.maximum}s")
    return text


_VALIDATORS = {
    ParamType.STRING: _validate_string,
    ParamType.BOOLEAN: _validate_boolean,
    ParamType.INTEGER: _validate_integer,
    ParamType.ENUM: _validate_enum,
    ParamType.HOSTNAME: _validate_hostname,
    ParamType.IP_ADDRESS: _validate_ip,
    ParamType.CIDR: _validate_cidr,
    ParamType.TARGET: _validate_target,
    ParamType.URL: _validate_url,
    ParamType.PORT: _validate_port,
    ParamType.PORT_RANGE: _validate_port_range,
    ParamType.FILE: _validate_file,
    ParamType.DIRECTORY: _validate_directory,
    ParamType.WORDLIST: _validate_wordlist,
    ParamType.DURATION: _validate_duration,
}


# ---------------------------------------------------------------------------
# Inference, so the existing untyped registry gains types without a rewrite
# ---------------------------------------------------------------------------

# Parameter names map to types by convention. Explicit ParamSpecs on a tool
# always win; this is the fallback for the several hundred entries that were
# declared as a plain {name: default} dict.
_NAME_TYPES = (
    (("target",), ParamType.TARGET),
    (("url", "endpoint"), ParamType.URL),
    (("domain",), ParamType.HOSTNAME),
    (("host", "hostname"), ParamType.HOSTNAME),
    (("ip", "address"), ParamType.IP_ADDRESS),
    (("cidr", "network", "subnet", "range"), ParamType.CIDR),
    (("ports",), ParamType.PORT_RANGE),
    (("port",), ParamType.PORT),
    (("wordlist",), ParamType.WORDLIST),
    (("directory", "dir", "path", "folder"), ParamType.STRING),
    (("file", "apk", "binary", "image_file", "pcap", "dump"), ParamType.FILE),
    (("timeout", "duration", "delay"), ParamType.DURATION),
    (("threads", "concurrency", "rate", "depth", "limit"), ParamType.INTEGER),
)

# Names whose value is a credential, wherever they appear.
_SECRET_NAMES = (
    "password", "passwd", "pwd", "secret", "token", "api_token", "api_key",
    "apikey", "auth", "credential", "cookie", "session", "private_key",
)


def is_secret_name(name: str) -> bool:
    """True when a parameter name marks its value as a credential."""
    normalized = name.strip().lower().replace("-", "_")
    return any(candidate in normalized for candidate in _SECRET_NAMES)


def infer_type(name: str) -> ParamType:
    """Guess a parameter's type from its name."""
    normalized = name.strip().lower()
    for candidates, param_type in _NAME_TYPES:
        if normalized in candidates:
            return param_type
    for candidates, param_type in _NAME_TYPES:
        if any(candidate in normalized for candidate in candidates):
            return param_type
    return ParamType.STRING


def spec_from_legacy(name: str, default: Any) -> ParamSpec:
    """Build a ParamSpec for a legacy {name: default} registry entry.

    A None default means the parameter is required, which is the convention the
    original registry used.
    """
    return ParamSpec(
        name=name,
        type=infer_type(name),
        required=default is None,
        default=default,
        secret=is_secret_name(name),
    )


def validate_params(
    specs: Sequence[ParamSpec],
    supplied: dict,
    reject_unknown: bool = True,
) -> Tuple[Optional[dict], Optional[str]]:
    """Validate a whole parameter set.

    Returns (normalized values, None) or (None, error message). Unknown
    parameters are rejected by default: silently dropping one hides a typo that
    would otherwise change what a tool does.
    """
    known = {spec.name for spec in specs}

    if reject_unknown:
        unexpected = sorted(set(supplied) - known)
        if unexpected:
            return None, f"unknown parameter(s): {', '.join(unexpected)}"

    normalized = {}
    for spec in specs:
        try:
            normalized[spec.name] = spec.validate(supplied.get(spec.name))
        except ValidationError as exc:
            return None, str(exc)

    return normalized, None
