"""MCP bridge registration smoke tests."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.api import mcp as M
from nexhunter.core import tools as T


def _tool_names():
    tools = asyncio.run(M.mcp.list_tools())
    return {t.name for t in tools}


def test_all_registry_tools_exposed():
    """Test every registry tool plus the core helpers register as MCP tools."""
    print("[TEST] MCP exposes all tools...")
    names = _tool_names()
    # Every registered scanner tool is present.
    for tool_name in T.TOOLS:
        assert tool_name in names, f"{tool_name} missing from MCP"
    # Core convenience tools are present.
    for helper in ("run_tool", "server_status", "assess", "probe", "recon"):
        assert helper in names, f"{helper} missing from MCP"
    print(f"  [OK] {len(names)} MCP tools registered")


def test_no_raw_command_tool():
    """Test the old raw-shell tool is gone."""
    print("[TEST] MCP has no raw command tool...")
    names = _tool_names()
    assert "run_command" not in names
    print("  [OK] run_command removed")


def test_token_forwarded(monkeypatch=None):
    """Test the Authorization header is attached when a token is set."""
    print("[TEST] MCP forwards bearer token...")
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["auth"] = req.headers.get("Authorization")
        raise RuntimeError("stop after header capture")

    import urllib.request

    old_token = M.API_TOKEN
    old_urlopen = urllib.request.urlopen
    M.API_TOKEN = "secret123"
    urllib.request.urlopen = fake_urlopen
    try:
        M.api("/health")
    finally:
        urllib.request.urlopen = old_urlopen
        M.API_TOKEN = old_token

    assert captured.get("auth") == "Bearer secret123"
    print("  [OK] Bearer token forwarded")


if __name__ == "__main__":
    test_all_registry_tools_exposed()
    test_no_raw_command_tool()
    test_token_forwarded()
    print("\nAll MCP registration tests passed")
