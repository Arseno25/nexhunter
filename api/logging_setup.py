"""Shared loguru pipeline for the API server and the MCP server.

All stdlib loggers (nexhunter.*, werkzeug, ...) are routed into loguru via
InterceptHandler, so call sites keep using plain `logging`.
"""

import inspect
import logging
import os
import re
import sys
from functools import partial
from typing import Any

from loguru import logger

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# One emoji anchor per level so every line is scannable at a glance.
_LEVEL_EMOJI = {
    "TRACE": "🔍",
    "DEBUG": "🐞",
    "INFO": "ℹ️",
    "SUCCESS": "✅",
    "WARNING": "⚠️",
    "ERROR": "❌",
    "CRITICAL": "🛑",
}

# SGR codes mirroring loguru's default level colors.
_LEVEL_STYLE = {
    "TRACE": ("38;5;250", "🔍"),
    "DEBUG": ("38;5;39", "🐞"),
    "INFO": ("38;5;46", "ℹ️"),
    "SUCCESS": ("38;5;46", "✅"),
    "WARNING": ("38;5;226", "⚠️"),
    "ERROR": ("38;5;196", "❌"),
    "CRITICAL": ("48;5;196;38;5;15", "🛑"),
}


class InterceptHandler(logging.Handler):
    """Route stdlib logging records into the loguru pipeline."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            level: int | str = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
        frame, depth = inspect.currentframe(), 0
        while frame and (depth == 0 or frame.f_code.co_filename == logging.__file__):
            frame = frame.f_back
            depth += 1
        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


def _level_emoji(record: Any) -> str:
    return _LEVEL_EMOJI.get(record["level"].name, "•")


def _console_format(record: Any, use_color: bool) -> str:
    """Console line: emoji level badge, name in cyan, message tinted by level."""
    lvl = record["level"].name
    sgr = _LEVEL_STYLE.get(lvl, ("97", "•"))[0]
    emoji = _level_emoji(record)
    badge, name, msg = f"{emoji} {lvl:<7}", record["name"], record["message"]
    if use_color:
        badge = f"\x1b[{sgr}m{badge}\x1b[0m"
        name = f"\x1b[38;5;51m{name}\x1b[0m"
        msg = f"\x1b[{sgr}m{msg}\x1b[0m"
    # Callable formatters must supply their own line break; loguru does not
    # append one (unlike string formats). Mirrors _file_format's trailing \n.
    return f"{record['time']:%H:%M:%S} | {badge} | {name} | {msg}\n"


def _file_format(record: Any) -> str:
    """Plain single-line file format: ANSI escapes stripped for greppability."""
    msg = _ANSI_RE.sub("", record["message"])
    return (
        f"{record['time']:%H:%M:%S} | {_level_emoji(record)} {record['level'].name:<7}"
        f" | {record['name']} | {msg}\n"
    )


def configure_logging(verbose: bool) -> None:
    """One pipeline: colored console, rotated plain file, stdlib intercepted."""
    level = "DEBUG" if verbose else "INFO"
    logger.remove()
    logger.add(
        sys.stdout,
        format=partial(
            _console_format,
            use_color=os.environ.get("NO_COLOR") is None,
        ),
        level=level,
    )
    try:
        logger.add(
            "nexhunter.log",
            format=_file_format,
            level=level,
            encoding="utf-8",
            rotation="10 MB",
            retention=5,
            colorize=False,
        )
    except OSError:
        # Read-only or restricted cwd: console-only logging is enough.
        pass
    logging.basicConfig(
        handlers=[InterceptHandler()],
        level=logging.DEBUG if verbose else logging.INFO,
        force=True,
    )
    # Access-log spam stays out of the pipeline; real errors still show.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
