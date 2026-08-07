"""Visual components for NexHunter - Vulnerability cards, progress, dashboards.

A single ANSI palette, one color gate (supports_color), and box-drawn surfaces
for terminal display: banners, progress bars, vulnerability cards, error
cards, tool status lines, and a live process dashboard.
"""

import itertools
import math
import os
import sys
import threading
import time
from contextlib import contextmanager
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
    # vulnerability severity
    "VULN_CRITICAL": "\033[48;5;124m\033[38;5;15m\033[1m",
    "VULN_HIGH": "\033[38;5;196m\033[1m",
    "VULN_MEDIUM": "\033[38;5;208m\033[1m",
    "VULN_LOW": "\033[38;5;226m",
    "VULN_INFO": "\033[38;5;51m",
    "INFO": "\033[38;5;51m",
    # tool status (steady colors only; blink is terminal-hostile)
    "STATUS_PENDING": "\033[38;5;240m",
    "TOOL_RUNNING": "\033[38;5;51m\033[1m",
    "TOOL_SUCCESS": "\033[38;5;46m\033[1m",
    "TOOL_FAILED": "\033[38;5;196m\033[1m",
    "TOOL_TIMEOUT": "\033[38;5;208m\033[1m",
    "TOOL_TERMINATED": "\033[38;5;226m\033[1m",
    "TOOL_RECOVERY": "\033[38;5;129m\033[1m",
}

SEVERITY_COLORS = {
    "critical": "VULN_CRITICAL",
    "high": "VULN_HIGH",
    "medium": "VULN_MEDIUM",
    "low": "VULN_LOW",
    "info": "VULN_INFO",
}

# Status semantics: gray = waiting, cyan = active, green = done,
# red = failed, orange = timed out, yellow = stopped/blocked, purple = recovery.
STATUS_COLORS = {
    # waiting
    "queued": "STATUS_PENDING",
    "validating": "STATUS_PENDING",
    "authorized": "STATUS_PENDING",
    "pending": "STATUS_PENDING",
    # active
    "running": "TOOL_RUNNING",
    "in_progress": "TOOL_RUNNING",
    # done
    "completed": "TOOL_SUCCESS",
    "success": "TOOL_SUCCESS",
    "ok": "TOOL_SUCCESS",
    "done": "TOOL_SUCCESS",
    # stopped without success
    "timed_out": "TOOL_TIMEOUT",
    "timeout": "TOOL_TIMEOUT",
    "terminated": "TOOL_TERMINATED",
    "blocked": "TOOL_TERMINATED",
    # failed
    "failed": "TOOL_FAILED",
    "error": "TOOL_FAILED",
    # special
    "recovery": "TOOL_RECOVERY",
    "unknown": "GRAY",
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
        "tl": "┌",
        "tr": "┐",
        "bl": "└",
        "br": "┘",
        "h": "─",
        "v": "│",
        "head": "┌─",
        "tail": "─┐",
    }
    try:
        "".join(glyphs.values()).encode(sys.stdout.encoding or "utf-8")
        return glyphs
    except (UnicodeEncodeError, LookupError, AttributeError):
        return {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|", "head": "+-", "tail": "-+"}


def _box(
    title: str,
    rows: list[Any],
    border: str = "CRIMSON",
    color: bool | None = None,
    max_width: int = 96,
) -> str:
    """One aligned box surface: `┌─ TITLE ─...─┐` with labeled rows.

    rows are (label, value, color-key), (label, value), or a plain string.
    Width is computed from the content and every line is padded to exactly
    the same length, so top/rows/bottom always line up. Values longer than
    the box are truncated with an ellipsis instead of breaking the border.
    """
    if color is None:
        color = supports_color()
    bx = _box_chars()
    h, v = bx["h"], bx["v"]

    norm: list[tuple[str, str, str]] = []
    label_w = 0
    for row in rows:
        if isinstance(row, str):
            label, value, vc = "", row, "WHITE"
        elif len(row) == 2:
            label, value, vc = row[0], row[1], "WHITE"
        else:
            label, value, vc = row[0], row[1], row[2]
        norm.append((label, value, vc))
        label_w = max(label_w, len(label))

    inner = max(
        len(title) + 6,
        *((label_w + 2 + len(value) + 4 if label else len(value) + 4) for label, value, _ in norm),
    )
    inner = min(inner, max(len(title) + 6, max_width))
    text_w = inner - 4

    out = [
        f"{_paint(bx['head'], border, 'BOLD', color=color)}"
        f"{_paint(title, border, 'BOLD', color=color)} "
        f"{_paint(h * max(0, inner - len(title) - 5), border, color=color)}"
        f"{_paint(bx['tail'], border, 'BOLD', color=color)}"
    ]
    for label, value, vc in norm:
        label_txt = f"{label:<{label_w}}" if label else ""
        prefix = f"{label_txt}: " if label else ""
        plain = prefix + value
        if len(plain) > text_w:
            value = value[: max(0, text_w - len(prefix) - 1)] + "…"
            plain = prefix + value
        line = _paint(prefix, "GRAY", color=color) if label else ""
        line += _paint(value, vc, color=color)
        line += " " * max(0, text_w - len(plain))
        out.append(f"{_paint(v, border, color=color)} {line} {_paint(v, border, color=color)}")
    out.append(
        f"{_paint(bx['bl'], border, color=color)}"
        f"{_paint(h * max(0, inner - 2), border, color=color)}"
        f"{_paint(bx['br'], border, color=color)}"
    )
    return "\n".join(out)


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

# Shared minimum width for the tool-name column, so a plan-progress line
# (format_step) and the tool event lines it precedes (execution's RUNNING /
# COMPLETED) put the tool name in the same place and read as one aligned flow.
TOOL_COL = 16


def render_progress_bar(
    current: float,
    total: float | None = None,
    width: int = 28,
    color: bool | None = None,
    show_percent: bool = True,
    fill_color: str = "CYAN",
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

    fill = _paint(bar, fill_color, color=color)
    caps_l = _paint("▐", "GRAY", color=color)
    caps_r = _paint("▌", "GRAY", color=color)
    out = f"{caps_l}{fill}{caps_r}"
    if show_percent:
        pct = _paint(f"{fraction * 100:5.1f}%", "BOLD", color=color)
        out = f"{out} {pct}"
    return out


# HexStrike-style braille spinner; cycles while a tool runs.
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


@contextmanager
def live_progress(
    label: str,
    estimate: float = 20.0,
    stream=None,
    color: bool | None = None,
    enabled: bool | None = None,
    interval: float = 0.1,
):
    """Animate a spinner + activity bar in place while a block runs.

    A tool's duration is unknown up front, so this shows *activity*, not a
    completion percentage: the eased fill (``1 - exp(-t/τ)``) and spinner give
    motion while the real readout is elapsed seconds. Deliberately no percent --
    an eased number that never reaches 100 reads as a stuck bar, and the honest
    progress number belongs to the plan line (STEP n/total), not to one tool of
    unknown length. Drawn to stderr with ``\\r`` so it never pollutes stdout
    logs or a redirected pipe. A no-op unless the stream is an interactive
    color TTY.
    """
    stream = stream or sys.stderr
    if enabled is None:
        enabled = supports_color(stream) and getattr(stream, "isatty", lambda: False)()
    if not enabled:
        yield
        return

    stop = threading.Event()
    start = time.time()
    tau = max(estimate / 3.0, 0.5)
    frames = itertools.cycle(_SPINNER)

    def draw() -> None:
        while not stop.is_set():
            elapsed = time.time() - start
            frac = min(1.0 - math.exp(-elapsed / tau), 0.99)
            # Fill/percent shift blue -> cyan -> green as the run advances, so a
            # long-running tool never looks stuck on one flat color.
            tier = "BLUE" if frac < 0.34 else "CYAN" if frac < 0.67 else "GREEN"
            spin = _paint(next(frames), tier, "BOLD", color=bool(color))
            bar = render_progress_bar(frac, width=22, color=bool(color),
                                       show_percent=False, fill_color=tier)
            elapsed_txt = _paint(f"{elapsed:6.1f}s", "GRAY", color=bool(color))
            # Elapsed is the only number here (fixed width, stays aligned run to
            # run); the variable-length label trails so it never shifts it.
            stream.write(f"\r{spin} {bar} {elapsed_txt}  {label}\033[K")
            stream.flush()
            stop.wait(interval)

    worker = threading.Thread(target=draw, daemon=True)
    worker.start()
    try:
        yield
    finally:
        stop.set()
        worker.join(timeout=0.5)
        stream.write("\r\033[K")  # wipe the line so the final log prints clean
        stream.flush()


def format_step(
    current: int,
    total: int,
    tool: str = "",
    target: str = "",
    phase: str = "",
    width: int = 24,
    color: bool | None = None,
) -> str:
    """One plan-progress line: `◆ STEP 03/20 ▐███░░▌  nmap_scan  → target · recon`.

    The bar tracks progress through the plan (step count), so the percent is
    dropped -- ``STEP 03/20`` already states it, and leaving one number per
    concept keeps this from being read as a per-tool completion. The tool name
    sits in the shared TOOL_COL column so it lines up with the RUNNING /
    COMPLETED lines that follow.
    """
    if color is None:
        color = supports_color()
    head = _paint(f"STEP {current:02d}/{total:02d}", "PURPLE", "BOLD", color=color)
    bar = render_progress_bar(current, total, width=width, color=color, show_percent=False)
    tail = ""
    if tool:
        tail += "  " + _paint(f"{tool:<{TOOL_COL}}", "WHITE", color=color)
    if target:
        tail += _paint(f"→ {target}", "GRAY", color=color)
    if phase:
        tail += _paint(f" · {phase}", "DIM", color=color)
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
    sev = STATUS_COLORS.get(status.lower(), "GRAY")
    bar = ""
    if progress > 0:
        bar = " " + render_progress_bar(progress, width=20, color=color)
    head = _paint(f"🔧 {tool.upper()}", "BOLD", color=color)
    status_txt = _paint(status.upper(), sev, color=color)
    target_txt = _paint(target, "WHITE", color=color) if target else ""
    return f"{head} | {status_txt} | {target_txt}{bar}"


def format_command_execution(command: str, status: str, duration: float = 0.0, color: bool | None = None) -> str:
    """Command execution display:
    `▶ nmap -sV target | SUCCESS (12.34s)`"""
    if color is None:
        color = supports_color()
    sev = STATUS_COLORS.get(status.lower(), "GRAY")
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
        "CRIMSON",
        "BOLD",
        color=color,
    )

    return "\n".join(
        [
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
        ]
    )


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
        self.id = f"vuln_{time.time_ns()}"
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
        sev = self.severity.lower() if isinstance(self.severity, str) else "info"
        sev_key = SEVERITY_COLORS.get(sev, "VULN_INFO")
        rows: list[Any] = [
            ("Title", self.title, "BOLD"),
            ("Severity", sev.upper(), sev_key),
            ("Type", self.type),
            ("Endpoint", self.endpoint),
            ("Impact", self.impact),
            ("Fix", self.remediation),
        ]
        if self.cvss_score is not None:
            rows.append(("CVSS", str(self.cvss_score), "BOLD"))
        if self.poc:
            rows.append(("PoC", self.poc))
        return _box("🚨 VULNERABILITY DETECTED", rows, border=sev_key, color=color)


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


def format_error_card(
    error_type: str,
    tool_name: str,
    error_message: str,
    recovery_action: str = "",
    color: bool | None = None,
) -> str:
    """Box-drawn error card with a status-colored border."""
    border = STATUS_COLORS.get(str(error_type).lower(), "TOOL_FAILED")
    rows: list[Any] = [
        ("Tool", tool_name),
        ("Type", error_type),
        ("Error", error_message),
    ]
    if recovery_action:
        rows.append(("Recovery", recovery_action, "TOOL_RECOVERY"))
    return _box("🔥 ERROR DETECTED", rows, border=border, color=color)


def create_live_dashboard(processes: list[dict[str, Any]], color: bool | None = None) -> str:
    """Live dashboard of running processes with box-drawn layout."""
    rows: list[Any] = []
    if not processes:
        rows.append("No active processes")
    for proc in processes[:15]:
        pid = proc.get("pid") or proc.get("execution_id", "?")
        status = str(proc.get("status", "unknown"))
        tool = (proc.get("tool") or proc.get("command") or "?")[:32]
        duration = proc.get("duration") or proc.get("uptime_s") or 0
        sev = STATUS_COLORS.get(status.lower(), "GRAY")
        rows.append(("PID " + str(pid), f"{status.upper():<9} {tool}  {duration}s", sev))
    return _box("📊 LIVE DASHBOARD", rows, color=color)


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
        lines.append(f"{v.id:<8} {v.type:<20} {badge} {v.severity:<7} {v.endpoint[:40]:<40} {v.impact[:20]:<20}")

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


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences so visible width can be measured."""
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _pad_to(text: str, width: int) -> str:
    """Left-justify a multi-line string to a fixed visible width."""
    return "\n".join(line + " " * max(0, width - len(_strip_ansi(line))) for line in text.splitlines())


def merge_columns(left: str, right: str, gap: int = 4) -> str:
    """Place two multi-line strings side by side.

    Both columns keep their own box alignment; shorter ones are padded to the
    same height, so joined top/bottom borders stay straight.
    """
    left_lines = left.splitlines()
    right_lines = right.splitlines()
    height = max(len(left_lines), len(right_lines))
    left_lines += [""] * (height - len(left_lines))
    right_lines += [""] * (height - len(right_lines))
    left_w = len(_strip_ansi(left_lines[0])) + gap
    return "\n".join(
        f"{left.ljust(left_w)}{right}"
        for left, right in zip(left_lines, right_lines, strict=True)
    )


def create_console_dashboard(
    tools: list[dict[str, Any]],
    executions: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    metrics: dict[str, Any],
    color: bool | None = None,
) -> str:
    """HexStrike-style console frame: header strip, toolkit sidebar, and
    executions + findings panels side by side. Pure client-side render; every
    input is a JSON list/dict, so the server does not need a render path."""
    if color is None:
        color = supports_color()

    # Toolkit sidebar, grouped by risk level like a module list.
    groups: list[tuple[str, str, list[dict]]] = []
    for risk in ("passive", "active", "intrusive"):
        members = [t for t in tools if t.get("risk_level") == risk]
        if members:
            groups.append((risk.upper(), f"{len(members):>4} tools", members))

    sidebar_rows: list[Any] = []
    for risk, count, members in groups:
        sidebar_rows.append(("", f"[{risk}]   {count}", "BOLD"))
        for tool in members[:3]:
            mark = "+" if tool.get("available") else "."
            sidebar_rows.append(("", f"  {mark} {tool.get('name', '?')}", "WHITE" if tool.get("available") else "GRAY"))
        if len(members) > 3:
            sidebar_rows.append(("", f"  ... {len(members) - 3} more", "DIM"))
        sidebar_rows.append(("", "", ""))

    # Executions panel, newest first.
    exec_rows: list[Any] = []
    for exec_ in executions[:12]:
        status = str(exec_.get("status", "unknown"))
        sev = STATUS_COLORS.get(status.lower(), "GRAY")
        target = str(exec_.get("target") or "")
        duration = exec_.get("duration_s")
        tail = f" → {target}" if target else ""
        tail += f"  {duration:.1f}s" if isinstance(duration, (int, float)) else ""
        exec_rows.append((status.upper()[:10], f"{exec_.get('tool', '?')}{tail}", sev))
    if not exec_rows:
        exec_rows.append(("", "no executions yet", "GRAY"))

    # Findings panel: severity counts + top titles.
    sev_counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        level = str(finding.get("severity", "info")).lower()
        if level in sev_counts:
            sev_counts[level] += 1

    findings_rows: list[Any] = [
        (sev.upper(), str(sev_counts[sev]), SEVERITY_COLORS.get(sev, "VULN_INFO"))
        for sev in ("critical", "high", "medium", "low", "info")
        if sev_counts[sev]
    ]
    if not findings_rows:
        findings_rows.append(("", "no findings yet", "GRAY"))
    for finding in findings[:4]:
        title = str(finding.get("title", ""))[:44]
        findings_rows.append(("", title, "WHITE"))

    header_rows: list[Any] = [
        ("Requests", str(metrics.get("requests", 0))),
        ("Processes", str(metrics.get("processes", 0))),
        ("Findings", str(metrics.get("findings", 0))),
    ]
    if metrics.get("cache_hits"):
        header_rows.append(("Cache hits", str(metrics.get("cache_hits", 0))))

    header = _box("NEXHUNTER CONSOLE", header_rows, border="CRIMSON", color=color)
    sidebar = _box("⚔ TOOLKIT", sidebar_rows, border="CYAN", color=color)
    exec_box = _box("▶ EXECUTIONS", exec_rows, border="GREEN", color=color)
    findings_box = _box("🚨 FINDINGS", findings_rows, border="ORANGE", color=color)

    right = _pad_to(exec_box, max(len(_strip_ansi(line)) for line in exec_box.splitlines()))
    right = "\n".join([right, _pad_to(findings_box, len(_strip_ansi(right.splitlines()[0])))])
    return header + "\n" + merge_columns(sidebar, right, gap=2)


def _selfcheck() -> None:
    """Assert the box builder keeps every line the same visible width."""
    box = _box(
        "TEST",
        [
            ("PID 1", "RUNNING  nmap_scan  42s", "TOOL_RUNNING"),
            "plain line without a label",
            ("Long", "x" * 200, "WHITE"),
        ],
        color=False,
    )
    lines = box.splitlines()
    widths = {len(_strip_ansi(line)) for line in lines}
    assert len(widths) == 1, f"box lines not aligned: {widths}\n{box}"
    assert "x" * 40 + "…" in box or "…" in box, "long value not truncated"
    dash = create_live_dashboard([{"pid": 7, "status": "running", "tool": "nmap_scan", "uptime_s": 42}], color=False)
    assert len({len(line) for line in dash.splitlines()}) == 1, "dashboard misaligned"
    err = format_error_card("TIMEOUT", "nmap_scan", "305s exceeded limit", "retry")
    assert len({len(_strip_ansi(line)) for line in err.splitlines()}) == 1, "error card misaligned"
    merged = merge_columns("a\nbb", "x\n\nzzz")
    lines = merged.splitlines()
    assert len(lines) == 3 and lines[0].endswith("x") and lines[2].endswith("zzz"), "merge_columns height/width wrong"
    dash = create_console_dashboard(
        [{"name": "nmap_scan", "risk_level": "active", "available": True}] * 3,
        [{"tool": "nmap_scan", "status": "running", "target": "10.0.0.1", "duration_s": 42}],
        [{"severity": "critical", "title": "RCE in admin panel"}],
        {"requests": 10, "processes": 1, "findings": 1},
        color=False,
    )
    assert dash.count("╔") == 0 and "NEXHUNTER CONSOLE" in dash and "TOOLKIT" in dash, "console dashboard missing panels"
    assert len({len(_strip_ansi(line)) for line in dash.splitlines()}) <= 2, "console dashboard columns misaligned"
    # live_progress: no-op path yields cleanly; TTY path draws then wipes.
    import io
    with live_progress("nmap → 10.0.0.1", enabled=False):
        pass
    buf = io.StringIO()
    with live_progress("nmap → 10.0.0.1", estimate=2, stream=buf, color=False,
                       enabled=True, interval=0.01):
        time.sleep(0.05)
    drawn = buf.getvalue()
    assert "nmap" in drawn and "\r\033[K" in drawn, "live bar did not draw/clear"
    assert "s  nmap" in drawn, "live bar missing elapsed readout"
    for name, key in {**SEVERITY_COLORS, **STATUS_COLORS}.items():
        assert key in COLORS, f"{name} -> unknown palette key {key}"
    assert all("\033[5m" not in COLORS[key] for key in STATUS_COLORS.values()), "blink in status colors"
    print("box surfaces OK")


if __name__ == "__main__":
    _selfcheck()
