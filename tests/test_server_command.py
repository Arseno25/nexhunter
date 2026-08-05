"""End-to-end tests for the /api/command security posture."""

import json
import sys
import threading
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest
from http.server import ThreadingHTTPServer

from nexhunter.api import server


@pytest.fixture(scope="module")
def base_url():
    """Start the real API server on an ephemeral port for the test module."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _post(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_raw_command_rejected(base_url):
    """Test a raw 'cmd' string is refused (no OS command passthrough)."""
    print("[TEST] Raw command rejected...")
    status, body = _post(base_url + "/api/command", {"cmd": "whoami"})
    assert body["ok"] is False
    assert body["code"] == "TOOL_REQUIRED"
    print("  [OK] Raw cmd refused")


def test_unknown_tool_rejected(base_url):
    """Test an unregistered tool name is refused."""
    print("[TEST] Unknown tool rejected...")
    status, body = _post(base_url + "/api/command", {"tool": "definitely_not_a_tool"})
    assert body["ok"] is False
    assert body["code"] == "UNKNOWN_TOOL"
    print("  [OK] Unknown tool refused")


def test_missing_params_rejected(base_url):
    """Test a known tool with missing required params is refused before exec."""
    print("[TEST] Missing params rejected...")
    status, body = _post(base_url + "/api/command", {"tool": "nmap_scan", "params": {}})
    assert body["ok"] is False
    assert body["code"] == "INVALID_PARAMS"
    print("  [OK] Missing params refused")


def test_health_public(base_url):
    """Test /health remains reachable."""
    print("[TEST] Health is public...")
    with urllib.request.urlopen(base_url + "/health", timeout=10) as resp:
        body = json.loads(resp.read())
    assert body["ok"] is True
    print("  [OK] Health public")


def test_oversized_body_rejected(base_url):
    """An oversized request body is refused instead of exhausting memory."""
    print("[TEST] Oversized body rejected...")
    data = b"x" * (6 * 1024 * 1024)
    req = urllib.request.Request(
        base_url + "/api/command",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        status, body = e.code, json.loads(e.read())
    assert status == 500, f"expected a 500 for oversized body, got {status}"
    assert body.get("error") and "too large" in body["error"]
    print("  [OK] Oversized body refused with a JSON error")


def test_unknown_tool_endpoint_returns_json_error(base_url):
    """A GET for an unknown tool returns JSON, not a dropped connection."""
    print("[TEST] Unknown tool GET returns JSON error...")
    req = urllib.request.Request(base_url + "/api/tools/nope_not_a_tool")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            body = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        status, body = e.code, json.loads(e.read())
    assert status == 404
    assert body["ok"] is False and body["code"] == "UNKNOWN_TOOL"
    print("  [OK] JSON error returned")


if __name__ == "__main__":
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}"
    test_raw_command_rejected(url)
    test_unknown_tool_rejected(url)
    test_missing_params_rejected(url)
    test_health_public(url)
    test_oversized_body_rejected(url)
    test_unknown_tool_endpoint_returns_json_error(url)
    httpd.shutdown()
    print("\nAll server command tests passed")
