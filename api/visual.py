"""Visual components for NexHunter - Vulnerability cards, progress, dashboards."""

import json
import os
import sys
import time
from typing import Dict, Any, List, Optional


# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------
# ANSI palette shared by the banner and the tool cards. Kept here so every
# visual surface pulls from one place instead of hard-coding escape codes.
COLORS = {
    "CYAN": "\033[38;5;51m",
    "BLUE": "\033[38;5;39m",
    "GREEN": "\033[38;5;46m",
    "YELLOW": "\033[38;5;226m",
    "ORANGE": "\033[38;5;208m",
    "RED": "\033[38;5;196m",
    "PURPLE": "\033[38;5;129m",
    "GRAY": "\033[38;5;240m",
    "WHITE": "\033[97m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "RESET": "\033[0m",
}


def supports_color(stream=None) -> bool:
    """True when it is safe to emit ANSI color to the given stream."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def _paint(text: str, *names: str, color: bool = True) -> str:
    """Wrap text in the named ANSI colors, or return it plain when disabled."""
    if not color or not names:
        return text
    prefix = "".join(COLORS.get(n, "") for n in names)
    return f"{prefix}{text}{COLORS['RESET']}"


NEXHUNTER_ART = r"""
 _   _ ________   ___    _ _    _ _   _ _______ ______ _____
| \ | |  ____\ \ / / |  | | |  | | \ | |__   __|  ____|  __ \
|  \| | |__   \ V /| |__| | |  | |  \| |  | |  | |__  | |__) |
| . ` |  __|   > < |  __  | |  | | . ` |  | |  |  __| |  _  /
| |\  | |____ / . \| |  | | |__| | |\  |  | |  | |____| | \ \
|_| \_|______/_/ \_\_|  |_|\____/|_| \_|  |_|  |______|_|  \_\
"""


# ---------------------------------------------------------------------------
# Progress bar (sub-cell resolution)
# ---------------------------------------------------------------------------
# Eighth-block glyphs give each column 8 steps of fill, so a 28-wide bar has
# 224 visible increments -- smoother than a plain full/empty bar.
_PARTIALS = " ▏▎▍▌▋▊▉"


def render_progress_bar(
    current: float,
    total: Optional[float] = None,
    width: int = 28,
    color: Optional[bool] = None,
    show_percent: bool = True,
) -> str:
    """Render a smooth progress bar.

    Pass a 0..1 fraction, or a current/total pair. Returns just the bar (with
    caps and percentage) so callers can prepend their own label.
    """
    if color is None:
        color = supports_color()

    fraction = current if total is None else (current / total if total else 0.0)
    fraction = max(0.0, min(1.0, fraction))

    eighths = int(round(fraction * width * 8))
    full, rem = divmod(eighths, 8)
    if full >= width:
        bar = "█" * width
    else:
        bar = "█" * full
        if rem:
            bar += _PARTIALS[rem]
        bar += "░" * (width - full - (1 if rem else 0))
    bar = bar[:width].ljust(width, "░")

    fill = _paint(bar, "CYAN", color=color)
    caps_l = _paint("▐", "GRAY", color=color)
    caps_r = _paint("▌", "GRAY", color=color)
    out = f"{caps_l}{fill}{caps_r}"
    if show_percent:
        pct = _paint(f"{fraction * 100:5.1f}%", "BOLD", color=color)
        out = f"{out} {pct}"
    return out


def format_step(
    current: int,
    total: int,
    tool: str = "",
    target: str = "",
    phase: str = "",
    width: int = 28,
    color: Optional[bool] = None,
) -> str:
    """One neat step line: `STEP 03/20 ▐███░░▌ 40%  tool → target · phase`."""
    if color is None:
        color = supports_color()
    head = _paint(f"STEP {current:02d}/{total:02d}", "PURPLE", "BOLD", color=color)
    bar = render_progress_bar(current, total, width=width, color=color)
    tail = ""
    if tool:
        tail += "  " + _paint(tool, "WHITE", color=color)
    if target:
        tail += _paint(f" → {target}", "GRAY", color=color)
    if phase:
        tail += _paint(f"  · {phase}", "DIM", color=color)
    return f"◆ {head}  {bar}{tail}"


def create_banner(
    host: str = "127.0.0.1",
    port: int = 8888,
    mode: str = "unknown",
    version: str = "3.0.0",
    agents: int = 0,
    tools: int = 0,
    color: Optional[bool] = None,
) -> str:
    """Render the NexHunter startup banner with runtime details."""
    if color is None:
        color = supports_color()

    art = _paint(NEXHUNTER_ART.strip("\n"), "CYAN", "BOLD", color=color)
    line = _paint("─" * 63, "GRAY", color=color)

    def row(icon: str, label: str, value: str, value_color: str = "WHITE") -> str:
        label_txt = _paint(f"{icon} {label:<16}", "GRAY", color=color)
        value_txt = _paint(str(value), value_color, color=color)
        return f"  {label_txt}{value_txt}"

    mode_color = {"active": "GREEN", "degraded": "YELLOW"}.get(mode, "ORANGE")
    tagline = _paint(
        "AI-Orchestrated Recon · Exploitation · Assessment",
        "PURPLE", color=color,
    )

    return "\n".join([
        "",
        art,
        f"  {tagline}",
        line,
        row("🌐", "Listening", f"http://{host}:{port}", "CYAN"),
        row("🧭", "Mode", mode, mode_color),
        row("🤖", "Agents", agents, "WHITE"),
        row("🛠", "Tools", tools, "WHITE"),
        row("📦", "Version", version, "WHITE"),
        line,
        "",
    ])


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
