"""Tool availability and version detection.

NexHunter never installs binaries. It reports what is present so an operator
knows which tools will actually run before they plan an assessment, rather
than discovering a gap mid-run.
"""

import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional

# Per-binary version probe. Most tools answer --version; the exceptions are
# listed rather than guessed at.
_VERSION_ARGS: Dict[str, List[str]] = {
    "nmap": ["--version"],
    "httpx": ["-version"],
    "nuclei": ["-version"],
    "subfinder": ["-version"],
    "naabu": ["-version"],
    "dnsx": ["-version"],
    "katana": ["-version"],
    "ffuf": ["-V"],
    "gobuster": ["version"],
    "nikto": ["-Version"],
    "sqlmap": ["--version"],
    "amass": ["-version"],
    "masscan": ["--version"],
    "whatweb": ["--version"],
    "wpscan": ["--version"],
    "semgrep": ["--version"],
    "trivy": ["--version"],
    "gitleaks": ["version"],
    "curl": ["--version"],
    "dig": ["-v"],
    "whois": ["--version"],
    "docker": ["--version"],
    "kubectl": ["version", "--client=true", "--output=yaml"],
    "aws": ["--version"],
    "gcloud": ["--version"],
    "az": ["--version"],
}

_DEFAULT_VERSION_ARGS = ["--version"]
_VERSION_TIMEOUT = 8

# Binaries with no useful version output. Probing them returns noise (nslookup
# prints the resolver's IP address, which is not a version).
_NO_VERSION = {"nslookup", "host"}

_VERSION_NUMBER = r"\d+\.\d+(?:\.\d+)?(?:[-\w.]*)?"

# Tried in order. A labelled or v-prefixed version beats a bare number, which
# is what stops kubectl's YAML from yielding a build date fragment.
_VERSION_PATTERNS = (
    re.compile(rf"\bgitVersion:\s*v?({_VERSION_NUMBER})", re.IGNORECASE),
    re.compile(rf"\bversion[:\s]+v?({_VERSION_NUMBER})", re.IGNORECASE),
    re.compile(rf"\bv({_VERSION_NUMBER})\b"),
    re.compile(rf"({_VERSION_NUMBER})"),
)

# An IPv4 address also looks like a dotted version; "192.168.0.1" would
# otherwise be read as version 192.168.0.
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _parse_version(output: str) -> Optional[str]:
    """Pull a version number out of a tool's version output."""
    # Blank out anything that is an IP address before looking for a version.
    cleaned = _IPV4.sub(" ", output)

    for pattern in _VERSION_PATTERNS:
        match = pattern.search(cleaned)
        if match:
            return match.group(1).rstrip(".,;)")
    return None


@dataclass(frozen=True)
class BinaryStatus:
    """Whether a tool's binary is installed, and which version."""

    binary: str
    installed: bool
    path: Optional[str] = None
    version: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "binary": self.binary,
            "installed": self.installed,
            "path": self.path,
            "version": self.version,
            "error": self.error,
        }


def detect_version(binary: str) -> Optional[str]:
    """Probe a binary for its version. Returns None when it cannot be read.

    Version probes are run with a short timeout and no shell. A tool that
    hangs or refuses to report simply has an unknown version; that is not an
    error worth failing a health check over.
    """
    path = shutil.which(binary)
    if not path or binary in _NO_VERSION:
        return None

    args = _VERSION_ARGS.get(binary, _DEFAULT_VERSION_ARGS)
    try:
        completed = subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=_VERSION_TIMEOUT,
            stdin=subprocess.DEVNULL,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None

    # Some tools report their version on stderr, some exit non-zero doing it.
    output = f"{completed.stdout}\n{completed.stderr}".strip()
    if not output:
        return None

    return _parse_version(output)


def check_binary(binary: str, with_version: bool = True) -> BinaryStatus:
    """Report whether one binary is installed, and its version."""
    path = shutil.which(binary)
    if not path:
        return BinaryStatus(binary=binary, installed=False, error="not found on PATH")

    version = detect_version(binary) if with_version else None
    return BinaryStatus(binary=binary, installed=True, path=path, version=version)


def check_tools(specs, with_version: bool = True) -> Dict[str, BinaryStatus]:
    """Check every distinct binary used by the given tool specs."""
    statuses: Dict[str, BinaryStatus] = {}
    for spec in specs:
        if spec.binary not in statuses:
            statuses[spec.binary] = check_binary(spec.binary, with_version=with_version)
    return statuses
