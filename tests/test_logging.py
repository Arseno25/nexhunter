"""Loguru pipeline: file lines stay plain (ANSI stripped), UTF-8 intact."""

import io
import logging

from loguru import logger

from nexhunter.api.logging_setup import InterceptHandler, _file_format


def _with_sink() -> tuple[io.StringIO, int]:
    logger.remove()
    buf = io.StringIO()
    return buf, logger.add(buf, format=_file_format, colorize=False)


def test_ansi_stripped():
    buf, _ = _with_sink()
    try:
        logger.info("\x1b[38;5;46m\x1b[1mRUNNING\x1b[0m nmap_scan")
    finally:
        logger.remove()
    out = buf.getvalue()
    assert "\x1b[" not in out
    assert "RUNNING nmap_scan" in out


def test_unicode_preserved():
    buf, _ = _with_sink()
    try:
        logger.info("\U0001f680 AUTONOMOUS START \u2192 example.com")
    finally:
        logger.remove()
    out = buf.getvalue()
    assert "\U0001f680" in out
    assert "\u2192" in out


def test_stdlib_intercepted():
    buf, _ = _with_sink()
    try:
        lg = logging.getLogger("nexhunter.test.intercept")
        lg.setLevel(logging.DEBUG)
        lg.handlers = [InterceptHandler()]
        lg.propagate = False
        lg.info("via stdlib logger")
    finally:
        logger.remove()
    out = buf.getvalue()
    assert "via stdlib logger" in out
    assert "test_logging" in out
