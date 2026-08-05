"""mcp.py - MCP bridge to the nexhunter HTTP server.

Architecture base: thin MCP layer proxying tool calls to the server.
Original code. All clients share one engine, one cache, and one process
manager on the server side.

Usage:
    python -m nexhunter.api.server --port 8888     # start server first
    python -m nexhunter.api.mcp --server http://127.0.0.1:8888
"""

import argparse
import inspect
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastmcp import FastMCP

from nexhunter.core import tools as T

SERVER = "http://127.0.0.1:8888"

mcp = FastMCP(
    "nexhunter",
    instructions=(
        "nexhunter AI-driven security assessment platform via MCP.\n\n"
        "Setup: python -m nexhunter.api.server --port 8888\n"
        "Web UI: http://localhost:8888/ or http://localhost:8888/ui\n"
        "Status: server_status() first to verify connectivity.\n\n"
        "Main flows:\n"
        "  - run_flow(flow='bugbounty', target=...) - phased assessment\n"
        "  - run_flow(flow='ctf', target=..., category='web|crypto|forensics|pwn|recon')\n"
        "  - assess(target) - quick assessment\n"
        "  - probe(target) - HTTP probe\n"
        "  - select_tools(target) - get recommended tools\n"
        "  - run_agent(name, params) - run specific agent\n\n"
        "IMPORTANT: Only test targets you have explicit authorization to assess."
    ),
)


def api(path, payload=None, timeout=600):
    url = SERVER + path
    req = urllib.request.Request(
        url,
        data=json.dumps(payload or {}).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception as e:
        return {"ok": False, "error": f"server unreachable at {SERVER}: {e}"}


@mcp.tool
def server_status() -> str:
    """Check nexhunter server health: mode, agents, installed tool binaries."""
    return json.dumps(api("/health"), indent=1)


@mcp.tool
def agents() -> str:
    """List all available AI agents (technology, decision, optimizer, rate_limit, cve, exploit, recovery, performance, degradation, correlator, bugbounty, ctf, browser)."""
    return json.dumps(api("/api/agents/list"), indent=1)


@mcp.tool
def run_agent(name: str, params: str = "{}") -> str:
    """Run an AI agent by name. params = JSON object string, e.g. '{"target": "https://x"}'."""
    try:
        p = json.loads(params or "{}")
    except json.JSONDecodeError:
        return json.dumps({"ok": False, "error": "params must be valid JSON"})
    return json.dumps(api(f"/api/agents/{name}", p), indent=1)


@mcp.tool
def run_flow(flow: str, target: str, category: str = "", file: str = "") -> str:
    """Run a workflow agent: 'bugbounty' (phased recon->report) or 'ctf' (category: web/crypto/forensics/pwn/recon)."""
    if flow == "bugbounty":
        return json.dumps(api("/api/flow/bugbounty", {"target": target}), indent=1)
    if flow == "ctf":
        return json.dumps(api("/api/flow/ctf", {"target": target, "category": category, "file": file}), indent=1)
    return json.dumps({"ok": False, "error": "flow must be 'bugbounty' or 'ctf'"})


@mcp.tool
def analyze_target(target: str) -> str:
    """AI analysis: tech fingerprint, recommended tools, CVE lookup, scan pace advice."""
    return json.dumps(api("/api/intelligence/analyze-target", {"target": target}), indent=1)


@mcp.tool
def select_tools(target: str, intent: str = "auto") -> str:
    """Pick tools for intent (recon/web/network/auto) given installed binaries + detected tech."""
    return json.dumps(api("/api/intelligence/select-tools", {"target": target, "intent": intent}), indent=1)


@mcp.tool
def optimize_parameters(tool: str) -> str:
    """Recommended parameters and timeout for a tool."""
    return json.dumps(api("/api/intelligence/optimize-parameters", {"tool": tool}), indent=1)


@mcp.tool
def run_command(cmd: str, async_run: bool = False) -> str:
    """Run a shell command on the server as a tracked process (async_run=True returns pid immediately)."""
    return json.dumps(api("/api/command", {"cmd": cmd, "async": async_run}), indent=1)


@mcp.tool
def processes() -> str:
    """List tracked server processes."""
    return json.dumps(api("/api/processes/list"), indent=1)


@mcp.tool
def process_status(pid: int) -> str:
    """Process status and recent output."""
    return json.dumps(api(f"/api/processes/status/{pid}"), indent=1)


@mcp.tool
def process_terminate(pid: int) -> str:
    """Kill a tracked process."""
    return json.dumps(api(f"/api/processes/terminate/{pid}", {}), indent=1)


@mcp.tool
def telemetry() -> str:
    """Server metrics: uptime, request count, avg response, cache, findings."""
    return json.dumps(api("/api/telemetry"), indent=1)


@mcp.tool
def cache_stats() -> str:
    """Cache entries, hits, evictions."""
    return json.dumps(api("/api/cache/stats"), indent=1)


@mcp.tool
def probe(target: str) -> str:
    """Quick HTTP probe: status, title, tech fingerprint (JSON)."""
    return json.dumps(api("/api/probe", {"target": target}), indent=1)


@mcp.tool
def portscan(target: str, ports: str = "") -> str:
    """Port/service scan, nmap -sV -T4 (JSON). ports='80,443' to limit."""
    return json.dumps(api("/api/portscan", {"target": target, "ports": ports}), indent=1)


@mcp.tool
def webscan(target: str) -> str:
    """Web vuln scan tuned to detected tech."""
    return json.dumps(api("/api/webscan", {"target": target}), indent=1)


@mcp.tool
def recon(domain: str) -> str:
    """Parallel passive recon: whois, dns, subdomain enumeration."""
    return json.dumps(api("/api/recon", {"domain": domain}), indent=1)


@mcp.tool
def assess(target: str) -> str:
    """Full pipeline: probe -> portscan -> conditional webscan, correlated findings."""
    return json.dumps(api("/api/assess", {"target": target}), indent=1)


@mcp.tool
def findings() -> str:
    """All recorded findings as JSON."""
    return json.dumps(api("/api/findings"), indent=1)


@mcp.tool
def report(fmt: str = "markdown") -> str:
    """Generate assessment report: 'markdown' or 'json'."""
    return json.dumps(api("/api/report", {"fmt": fmt}), indent=1)


def _register(name, spec):
    """Dynamically register tool as MCP tool."""
    def fn(**kwargs):
        params = {k: kwargs.get(k, spec.params.get(k)) for k in spec.params}
        return json.dumps(api("/api/command", {"tool": name, "params": params}), indent=1)

    fn.__name__ = name
    fn.__annotations__ = {k: str for k in spec.params}
    fn.__signature__ = inspect.Signature(
        [
            inspect.Parameter(
                k,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=str,
                default=(inspect.Parameter.empty if v is None else v),
            )
            for k, v in spec.params.items()
        ]
    )
    fn.__doc__ = f"{spec.description}\nParams: {', '.join(spec.params)}"
    mcp.tool()(fn)


for _name, _spec in T.TOOLS.items():
    _register(_name, _spec)


def main():
    global SERVER
    parser = argparse.ArgumentParser(description="nexhunter MCP bridge")
    parser.add_argument("--server", default="http://127.0.0.1:8888", help="nexhunter server URL")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    SERVER = args.server.rstrip("/")
    mcp.run()


if __name__ == "__main__":
    main()
