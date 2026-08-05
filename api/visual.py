"""Visual components for NexHunter - Vulnerability cards, progress, dashboards.

A single ANSI palette, one color gate (supports_color), and box-drawn surfaces
for terminal display: banners, progress bars, vulnerability cards, error
cards, tool status lines, and a live process dashboard.
"""

import os
import sys
import time
from typing import Any


# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------
# One palette for every visual surface. Kept here so nothing hard-codes
# escape codes. Honors NO_COLOR and FORCE_COLOR via supports_color().
COLORS = {
    # base
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
    # reddish theme
    "BLOOD_RED": "\033[38;5;124m",
    "CRIMSON": "\033[38;5;160m",
    "DARK_RED": "\033[38;5;88m",
    "FIRE_RED": "\033[38;5;202m",
    "ROSE_RED": "\033[38;5;167m",
    "SCARLET": "\033[38;5;197m",
    "RUBY": "\033[38;5;161m",
    # highlight backgrounds
    "HIGHLIGHT_RED": "\033[48;5;196m\033[38;5;15m",
    "HIGHLIGHT_YELLOW": "\033[48;5;226m\033[38;5;16m",
    "HIGHLIGHT_GREEN": "\033[48;5;46m\033[38;5;16m",
    "HIGHLIGHT_BLUE": "\033[48;5;51m\033[38;5;16m",
    "HIGHLIGHT_PURPLE": "\033[48;5;129m\033[38;5;15m",
    # status
    "SUCCESS": "\033[38;5;46m",
    "WARNING": "\033[38;5;208m",
    "ERROR": "\033[38;5;196m",
    "CRITICAL": "\033[48;5;196m\033[38;5;15m\033[1m",
    "INFO": "\033[38;5;51m",
    "DEBUG": "\033[38;5;240m",
    # vulnerability severity
    "VULN_CRITICAL": "\033[48;5;124m\033[38;5;15m\033[1m",
    "VULN_HIGH": "\033[38;5;196m\033[1m",
    "VULN_MEDIUM": "\033[38;5;208m\033[1m",
    "VULN_LOW": "\033[38;5;226m",
    "VULN_INFO": "\033[38;5;51m",
    # tool status
    "TOOL_RUNNING": "\033[38;5;46m\033[5m",
    "TOOL_SUCCESS": "\033[38;5;46m\033[1m",
    "TOOL_FAILED": "\033[38;5;196m\033[1m",
    "TOOL_TIMEOUT": "\033[38;5;208m\033[1m",
    "TOOL_RECOVERY": "\033[38;5;129m\033[1m",
    # progress
    "PROGRESS_BAR": "\033[38;5;46m",
    "PROGRESS_EMPTY": "\033[38;5;240m",
    "SPINNER": "\033[38;5;51m",
    "PULSE": "\033[38;5;196m\033[5m",
}

SEVERITY_COLORS = {
    "critical": "VULN_CRITICAL",
    "high": "VULN_HIGH",
    "medium": "VULN_MEDIUM",
    "low": "VULN_LOW",
    "info": "VULN_INFO",
}

STATUS_COLORS = {
    "running": "TOOL_RUNNING",
    "success": "TOOL_SUCCESS",
    "failed": "TOOL_FAILED",
    "timed_out": "TOOL_TIMEOUT",
    "timeout": "TOOL_TIMEOUT",
    "recovery": "TOOL_RECOVERY",
    "terminated": "TOOL_FAILED",
    "queued": "INFO",
    "completed": "TOOL_SUCCESS",
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


# Box-drawing glyphs degrade to ASCII on consoles that cannot encode them
# (e.g. cp1252 Windows terminals), so cards never crash a print().
def _box_chars() -> dict:
    glyphs = {
        "tl": "┌", "tr": "┐", "bl": "└", "br": "┘",
        "h": "─", "v": "│", "head": "┌─", "tail": "─┐",
    }
    try:
        "".join(glyphs.values()).encode(sys.stdout.encoding or "utf-8")
        return glyphs
    except (UnicodeEncodeError, LookupError, AttributeError):
        return {"tl": "+", "tr": "+", "bl": "+", "br": "+",
                "h": "-", "v": "|", "head": "+-", "tail": "-+"}


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
    total: float | None = None,
    width: int = 28,
    color: bool | None = None,
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
    color: bool | None = None,
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


def format_tool_status(
    tool: str,
    status: str,
    target: str = "",
    progress: float = 0.0,
    color: bool | None = None,
) -> str:
    """One-line tool execution status:
    `🔧 NMAP | RUNNING | 10.0.0.1 [███░░] 60.0%`"""
    if color is None:
        color = supports_color()
    sev = STATUS_COLORS.get(status.lower(), "INFO")
    bar = ""
    if progress > 0:
        bar = " " + render_progress_bar(progress, width=20, color=color)
    head = _paint(f"🔧 {tool.upper()}", "BOLD", color=color)
    status_txt = _paint(status.upper(), sev, color=color)
    target_txt = _paint(target, "WHITE", color=color) if target else ""
    return f"{head} | {status_txt} | {target_txt}{bar}"


def format_command_execution(
    command: str, status: str, duration: float = 0.0, color: bool | None = None
) -> str:
    """Command execution display:
    `▶ nmap -sV target | SUCCESS (12.34s)`"""
    if color is None:
        color = supports_color()
    sev = STATUS_COLORS.get(status.lower(), "INFO")
    short = command if len(command) <= 60 else command[:57] + "..."
    dur = f" ({duration:.2f}s)" if duration > 0 else ""
    head = _paint("▶", "INFO", color=color)
    cmd = _paint(short, "WHITE", color=color)
    status_txt = _paint(f"{status.upper()}{dur}", sev, color=color)
    return f"{head} {cmd} | {status_txt}"


def create_banner(
    host: str = "127.0.0.1",
    port: int = 8888,
    mode: str = "unknown",
    version: str = "1.0.0",
    agents: int = 0,
    tools: int = 0,
    color: bool | None = None,
) -> str:
    """Render the NexHunter startup banner with runtime details."""
    if color is None:
        color = supports_color()

    art = _paint(NEXHUNTER_ART.strip("\n"), "CYAN", "BOLD", color=color)
    accent = _paint("═" * 63, "CRIMSON", color=color)

    def row(icon: str, label: str, value: object, value_color: str = "WHITE") -> str:
        label_txt = _paint(f"{icon} {label:<16}", "GRAY", color=color)
        value_txt = _paint(str(value), value_color, color=color)
        return f"  {label_txt}{value_txt}"

    mode_color = {"active": "GREEN", "degraded": "YELLOW"}.get(mode, "ORANGE")
    tagline = _paint(
        "AI-Orchestrated Recon · Exploitation · Assessment",
        "CRIMSON", "BOLD", color=color,
    )

    return "\n".join([
        "",
        art,
        f"  {tagline}",
        accent,
        row("🌐", "Listening", f"http://{host}:{port}", "CYAN"),
        row("🧭", "Mode", mode, mode_color),
        row("🤖", "Agents", agents, "WHITE"),
        row("🛠", "Tools", tools, "WHITE"),
        row("📦", "Version", version, "WHITE"),
        accent,
        "",
    ])


def create_section_header(title: str, icon: str = "🔥", color: bool | None = None) -> str:
    """Section divider for multi-phase output:
    `══ 🔥 RECON ═══════════════════════════════════════════════`"""
    if color is None:
        color = supports_color()
    head = _paint(f"{icon} {title.upper()}", "CRIMSON", "BOLD", color=color)
    line = _paint("═" * (60 - len(title) - 3), "DARK_RED", color=color)
    return f"{head} {line}"


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
        cvss_score: float | None = None,
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

    def to_dict(self) -> dict[str, Any]:
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

    def to_cli(self, color: bool | None = None) -> str:
        """Format for CLI display as a box-drawn card with severity-colored border."""
        if color is None:
            color = supports_color()

        bx = _box_chars()
        sev = self.severity.lower() if isinstance(self.severity, str) else "info"
        border = _paint(bx["h"], SEVERITY_COLORS.get(sev, "VULN_INFO"), color=color)
        badge = _paint(f"[{sev.upper()}]", SEVERITY_COLORS.get(sev, "VULN_INFO"), "BOLD", color=color)
        label = _paint("VULNERABILITY", "CRIMSON", "BOLD", color=color)

        title_txt = _paint(self.title, "WHITE", "BOLD", color=color)
        meta = f"{badge}"
        if self.cvss_score is not None:
            meta += f"   CVSS: {_paint(str(self.cvss_score), 'BOLD', color=color)}"

        rows = [
            ("Type", self.type),
            ("Endpoint", self.endpoint),
            ("Impact", self.impact),
            ("Fix", self.remediation),
        ]
        if self.poc:
            rows.append(("PoC", self.poc[:80] + ("..." if len(self.poc) > 80 else "")))

        width = max(30, len(f"{label} DETECTED"), *(len(f"{k}: {v}") for k, v in rows))
        width = min(width, 90)
        top = f"{_paint(bx['tl'], 'CRIMSON', color=color)}{border * (width + 4)}{_paint(bx['tr'], 'CRIMSON', color=color)}"
        vbar = bx["v"]

        lines = [top, f"{vbar} {title_txt:<{width + 2}} {vbar}"]
        lines.append(f"{vbar} {meta:<{width + 2}} {vbar}")
        for k, v in rows:
            value = _paint(str(v)[: width - 14], "WHITE", color=color)
            lines.append(f"{vbar} {_paint(k + ':', 'GRAY', color=color):<14}{value:<{width - 11}} {vbar}")
        lines.append(f"{bx['bl']}{border * (width + 4)}{bx['br']}")

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

    def to_dict(self) -> dict[str, Any]:
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

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "requests": self.requests,
            "findings": self.findings,
            "processes": self.processes,
            "cache_hits": self.cache_hits,
            "vulnerabilities": self.vulnerabilities_by_severity,
        }


class SpinnerAnimation:
    """Cyclic animation frames for long-running operations."""

    STYLES = {
        "dots": ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
        "bars": ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"],
        "arrows": ["←", "↖", "↑", "↗", "→", "↘", "↓", "↙"],
        "pulse": ["●", "◐", "◑", "◒", "◓", "◔", "◕", "◖", "◗", "◘"],
    }

    def __init__(self, style: str = "dots", color: bool | None = None):
        if color is None:
            color = supports_color()
        self.color = color
        self.frames = self.STYLES.get(style, self.STYLES["dots"])
        self._i = 0

    def frame(self, label: str = "") -> str:
        """Next animation frame, optionally with a label."""
        char = self.frames[self._i % len(self.frames)]
        self._i += 1
        if label:
            return f"{_paint(char, 'SPINNER', color=self.color)} {label}"
        return _paint(char, "SPINNER", color=self.color)


def format_error_card(
    error_type: str,
    tool_name: str,
    error_message: str,
    recovery_action: str = "",
    color: bool | None = None,
) -> str:
    """Box-drawn error card with severity-colored border."""
    if color is None:
        color = supports_color()

    bx = _box_chars()
    sev = STATUS_COLORS.get(error_type.lower(), "TOOL_FAILED")
    border = _paint(bx["h"], sev, color=color)
    head = f"{_paint(bx['head'], sev, 'BOLD', color=color)}🔥 ERROR DETECTED {'─' * 12}{_paint(bx['tail'], sev, color=color)}"
    rows = [("Tool", tool_name), ("Type", error_type), ("Error", error_message[:60])]
    if recovery_action:
        rows.append(("Recovery", recovery_action[:60]))
    width = max(len("ERROR DETECTED"), *(len(f"{k}: {v}") for k, v in rows))
    width = min(width, 90)
    vbar = bx["v"]
    lines = [head]
    for k, v in rows:
        value = _paint(str(v)[: width - 10], "WHITE", color=color)
        lines.append(f"{vbar} {_paint(k + ':', 'GRAY', color=color):<10}{value:<{width - 7}} {vbar}")
    lines.append(f"{bx['bl']}{border * (width + 4)}{bx['br']}")
    return "\n".join(lines)


def create_live_dashboard(processes: list[dict[str, Any]], color: bool | None = None) -> str:
    """Live dashboard of running processes with box-drawn layout."""
    if color is None:
        color = supports_color()

    bx = _box_chars()
    border = _paint(bx["h"], "CRIMSON", color=color)
    head = f"{_paint(bx['head'], 'CRIMSON', 'BOLD', color=color)}📊 NEXHUNTER LIVE DASHBOARD {'─' * 16}{_paint(bx['tail'], 'CRIMSON', color=color)}"
    vbar = bx["v"]
    lines = [head]

    if not processes:
        lines.append(f"{vbar} {_paint('No active processes', 'GRAY', color=color):<64} {vbar}")
    else:
        for proc in processes[:15]:
            pid = proc.get("pid") or proc.get("execution_id", "?")
            status = proc.get("status", "unknown")
            command = (proc.get("tool") or proc.get("command") or "")[:40]
            duration = proc.get("duration", 0)
            sev = STATUS_COLORS.get(status.lower(), "INFO")
            row_txt = (f"PID {pid:<6} | {_paint(status.upper(), sev, color=color)} | "
                       f"{command:<40} | {duration}s")
            lines.append(f"{vbar} {row_txt:<64} {vbar}")

    lines.append(f"{bx['bl']}{border * 66}{bx['br']}")
    return "\n".join(lines)


def format_vulnerability_table(vulns: list[VulnerabilityCard]) -> str:
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


def severity_stats(vulns: list[VulnerabilityCard]) -> dict[str, int]:
    """Get severity statistics."""
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        if v.severity in stats:
            stats[v.severity] += 1
    return stats
