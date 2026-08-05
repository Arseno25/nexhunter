"""Visual components for NexHunter - Vulnerability cards, progress, dashboards."""

import json
import time
from typing import Dict, Any, List, Optional


class VulnerabilityCard:
    """Formatted vulnerability display card."""

    def __init__(
        self,
        title: str,
        severity: str,
        endpoint: str,
        impact: str,
        remediation: str,
        vuln_type: str = "Unknown",
        cvss_score: Optional[float] = None,
        poc: str = "",
    ):
        self.id = f"vuln_{int(time.time() * 1000)}"
        self.title = title
        self.type = vuln_type
        self.severity = severity
        self.endpoint = endpoint
        self.impact = impact
        self.remediation = remediation
        self.cvss_score = cvss_score
        self.poc = poc
        self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "type": self.type,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "impact": self.impact,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "poc": self.poc,
            "timestamp": self.timestamp,
        }

    def to_cli(self) -> str:
        """Format for CLI display."""
        sev_colors = {
            "critical": "\033[91m",  # Red
            "high": "\033[91m",
            "medium": "\033[93m",  # Yellow
            "low": "\033[94m",  # Blue
            "info": "\033[90m",  # Gray
        }
        reset = "\033[0m"
        color = sev_colors.get(self.severity, reset)

        lines = [
            f"{color}[{self.severity.upper()}]{reset} {self.title}",
            f"  Type: {self.type}",
            f"  Endpoint: {self.endpoint}",
            f"  Impact: {self.impact}",
            f"  Fix: {self.remediation}",
        ]
        if self.cvss_score:
            lines.append(f"  CVSS: {self.cvss_score}")
        if self.poc:
            lines.append(f"  PoC: {self.poc[:50]}...")
        return "\n".join(lines)


class ProgressTracker:
    """Track assessment progress in real-time."""

    def __init__(self, total_steps: int = 100):
        self.total = total_steps
        self.current = 0
        self.step = ""
        self.started = time.time()

    def update(self, current: int, step: str = ""):
        """Update progress."""
        self.current = min(current, self.total)
        self.step = step

    def increment(self, delta: int = 1, step: str = ""):
        """Increment progress."""
        self.current = min(self.current + delta, self.total)
        if step:
            self.step = step

    def percent(self) -> int:
        """Get percentage."""
        return int((self.current / self.total) * 100) if self.total > 0 else 0

    def elapsed(self) -> float:
        """Seconds elapsed."""
        return time.time() - self.started

    def eta(self) -> float:
        """Estimated seconds remaining."""
        if self.current == 0:
            return 0
        rate = self.current / self.elapsed()
        remaining = self.total - self.current
        return remaining / rate if rate > 0 else 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "current": self.current,
            "total": self.total,
            "percent": self.percent(),
            "step": self.step,
            "elapsed": self.elapsed(),
            "eta": self.eta(),
        }


class DashboardMetrics:
    """Dashboard metrics and system info."""

    def __init__(self):
        self.timestamp = time.time()
        self.requests = 0
        self.findings = 0
        self.processes = 0
        self.cache_hits = 0
        self.vulnerabilities_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "requests": self.requests,
            "findings": self.findings,
            "processes": self.processes,
            "cache_hits": self.cache_hits,
            "vulnerabilities": self.vulnerabilities_by_severity,
        }


def format_vulnerability_table(vulns: List[VulnerabilityCard]) -> str:
    """Format vulnerabilities as table."""
    if not vulns:
        return "No vulnerabilities found"

    lines = [
        "\nVulnerability Summary",
        "=" * 100,
        f"{'ID':<8} {'Type':<20} {'Severity':<10} {'Endpoint':<40} {'Impact':<20}",
        "-" * 100,
    ]

    for v in vulns[:50]:
        sev_colors = {"critical": "[!]", "high": "[!]", "medium": "[*]", "low": "[+]", "info": "[i]"}
        badge = sev_colors.get(v.severity, "[ ]")
        lines.append(
            f"{v.id:<8} {v.type:<20} {badge} {v.severity:<7} {v.endpoint[:40]:<40} {v.impact[:20]:<20}"
        )

    if len(vulns) > 50:
        lines.append(f"\n... and {len(vulns) - 50} more vulnerabilities")

    return "\n".join(lines)


def severity_stats(vulns: List[VulnerabilityCard]) -> Dict[str, int]:
    """Get severity statistics."""
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        if v.severity in stats:
            stats[v.severity] += 1
    return stats
