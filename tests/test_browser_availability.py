"""browser_crawl availability reflects the real runtime, not just `python`."""

import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import nexhunter.core.tools as T


def test_available_needs_selenium_and_chrome():
    """Both Selenium and a Chrome/Chromium binary are required."""
    print("[TEST] browser_crawl needs selenium + chrome...")
    spec = T.get_tool_spec("browser_crawl")
    assert spec is not None
    assert spec.availability_check is T.browser_engine_available

    # Both present -> available.
    with mock.patch.object(T, "which", lambda b: "/usr/bin/" + b), \
         mock.patch("importlib.util.find_spec", lambda name: object()):
        assert spec.available is True

    # Selenium missing -> not available, even with a browser binary.
    with mock.patch.object(T, "which", lambda b: "/usr/bin/" + b), \
         mock.patch("importlib.util.find_spec", lambda name: None):
        assert spec.available is False

    # No browser binary -> not available, even with Selenium importable.
    with mock.patch.object(T, "which", lambda b: None), \
         mock.patch("importlib.util.find_spec", lambda name: object()):
        assert spec.available is False

    print("  [OK] Availability tracks Selenium and a Chrome binary")


def test_binary_python_alone_does_not_imply_available():
    """A bare `python` on PATH must not report the browser engine as ready."""
    print("[TEST] python alone is not enough...")
    spec = T.get_tool_spec("browser_crawl")
    # python present, but no selenium: the old behaviour would have said True.
    with mock.patch.object(T, "which", lambda b: "/usr/bin/python" if b == "python" else None), \
         mock.patch("importlib.util.find_spec", lambda name: None):
        assert spec.available is False
    print("  [OK] `which python` no longer implies a browser engine")


if __name__ == "__main__":
    print("\n=== Browser Availability Tests ===\n")
    test_available_needs_selenium_and_chrome()
    test_binary_python_alone_does_not_imply_available()
    print("\n=== All Browser Availability Tests Passed ===\n")
