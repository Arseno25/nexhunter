"""mcp.py - FastMCP bridge to the nexhunter HTTP server.

A thin MCP layer that proxies every call to the server's REST API, so MCP and
REST share one execution path. The bridge holds no tool logic of its own.

Tools are generated from the central registry rather than hand-written, and
filtered by profile so a client is shown only the tools for its job. Listing a
tool is a usability decision; execution remains the server's.

Configuration: flags override NEXHUNTER_MCP_* environment variables, which
override defaults. Nothing else configures the bridge.

    Flag            Env var                     Default
    --server        (none)                      http://127.0.0.1:8888
    --profile       NEXHUNTER_MCP_PROFILE       nexhunter-full
    --tool-limit    NEXHUNTER_MCP_TOOL_LIMIT    (no cap)
    --max-output    NEXHUNTER_MCP_MAX_OUTPUT    4000

Usage:
    python -m nexhunter.api.server --port 8888          # start the server first
    python -m nexhunter.api.mcp --server http://127.0.0.1:8888
    python -m nexhunter.api.mcp --profile nexhunter-web --tool-limit 30
    python -m nexhunter.api.mcp --list-profiles
"""

import argparse
import inspect
import json
import logging
import os
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastmcp import FastMCP

from nexhunter.core import tools as T
from nexhunter.api import mcp_profiles

log = logging.getLogger("nexhunter.mcp")

SERVER = "http://127.0.0.1:8888"
# Which slice of the registry this bridge exposes. Overridden by --profile or
# NEXHUNTER_MCP_PROFILE before tools are registered.
PROFILE_NAME = os.environ.get("NEXHUNTER_MCP_PROFILE", mcp_profiles.DEFAULT_PROFILE)
# Optional cap on how many registry tools the bridge registers. AI clients
# (Claude Desktop, Cursor, etc.) impose their own tool limits; rather than
# bypassing them like some tools do, nexhunter lets the operator pick which
# slice of the registry fits. Overridden by --tool-limit.
TOOL_LIMIT = os.environ.get("NEXHUNTER_MCP_TOOL_LIMIT")

mcp = FastMCP(
    "nexhunter",
    instructions=(
        "nexhunter AI-driven security assessment platform via MCP.\n\n"
        "Setup: python -m nexhunter.api.server --port 8888\n"
        "Web UI: http://localhost:8888/ or http://localhost:8888/ui\n"
        "Status: server_status() first to verify connectivity.\n\n"
        "Main flows:\n"
        "  - recommend_plan(target) - senior-pentester methodology plan, nothing runs\n"
        "  - propose_plan(target, steps) - validate an AI-drafted plan\n"
        "  - autonomous_assess(target) - execute an adaptive assessment\n"
        "  - run_flow(flow='bugbounty', target=...) - phased assessment\n"
        "  - run_flow(flow='ctf', target=..., category='web|crypto|forensics|pwn|recon')\n"
        "  - assess(target) - quick assessment\n"
        "  - probe(target) - HTTP probe\n"
        "  - select_tools(target) - get recommended tools\n"
        "  - run_agent(name, params) - run specific agent\n\n"
        "For a new target: call recommend_plan() first to get the methodology\n"
        "phases, review them, then run autonomous_assess()."
    ),
)


def api(path, payload=None, timeout=600):
    url = SERVER + path
    headers = {"Content-Type": "application/json"}
    req = urllib.request.Request(
        url,
        data=json.dumps(payload or {}).encode() if payload is not None else None,
        headers=headers,
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception as e:
        return {"ok": False, "error": f"server unreachable at {SERVER}: {e}"}


# ---------------------------------------------------------------------------
# Token economy: results are trimmed inside the JSON structure before they
# reach the client, so large tool output (nmap dumps, crawls) cannot flood an
# LLM context window. Trimming is structure-aware - the JSON stays valid, so
# a client never has to repair a broken payload. This is the same outcome
# FastMCP's ResponseLimitingMiddleware gives on newer versions, done at the
# handler layer to work on fastmcp 2.x with per-field control.
# ---------------------------------------------------------------------------

MAX_OUTPUT = int(os.environ.get("NEXHUNTER_MCP_MAX_OUTPUT", "4000"))
MAX_ITEMS = 200


def _cut(text: str, limit: int) -> str:
    """Cut a string at a UTF-8-safe boundary so the result is always decodable."""
    raw = text.encode("utf-8", "replace")
    head = raw[:limit]
    while head and head[-1] & 0xC0 == 0x80:
        head = head[:-1]
    return head.decode("utf-8", "replace")


def _trim_json(data, max_field=None, max_items=MAX_ITEMS):
    """Trim large strings and lists inside arbitrary JSON, keeping it valid."""
    if max_field is None:
        max_field = MAX_OUTPUT
    if isinstance(data, str):
        if len(data) <= max_field:
            return data
        kept = _cut(data, max_field)
        return f"{kept}\n[... {len(data) - len(kept)} chars omitted; raise with --max-output]"
    if isinstance(data, list):
        if len(data) <= max_items:
            return [_trim_json(i, max_field, max_items) for i in data]
        kept = [_trim_json(i, max_field, max_items) for i in data[:max_items]]
        kept.append(f"[... {len(data) - max_items} items omitted]")
        return kept
    if isinstance(data, dict):
        return {k: _trim_json(v, max_field, max_items) for k, v in data.items()}
    return data


def _render(data) -> str:
    """Serialize an API response with token-economy trimming applied."""
    return json.dumps(_trim_json(data), indent=1)


@mcp.tool()
def server_status() -> str:
    """Check nexhunter server health: mode, agents, installed tool binaries."""
    return _render(api("/health"), indent=1)


@mcp.tool()
def agents() -> str:
    """List all available AI agents (technology, decision, optimizer, rate_limit, cve, exploit, recovery, performance, degradation, correlator, bugbounty, ctf, browser)."""
    return _render(api("/api/agents/list"), indent=1)


@mcp.tool()
def run_agent(name: str, params: str = "{}") -> str:
    """Run an AI agent by name. params = JSON object string, e.g. '{"target": "https://x"}'."""
    try:
        p = json.loads(params or "{}")
    except json.JSONDecodeError:
        return json.dumps({"ok": False, "error": "params must be valid JSON"})
    return _render(api(f"/api/agents/{name}", p), indent=1)


@mcp.tool()
def run_flow(flow: str, target: str, category: str = "", file: str = "") -> str:
    """Run a workflow agent: 'bugbounty' (phased recon->report) or 'ctf' (category: web/crypto/forensics/pwn/recon)."""
    if flow == "bugbounty":
        return _render(api("/api/flow/bugbounty", {"target": target}), indent=1)
    if flow == "ctf":
        return _render(api("/api/flow/ctf", {"target": target, "category": category, "file": file}), indent=1)
    return json.dumps({"ok": False, "error": "flow must be 'bugbounty' or 'ctf'"})


@mcp.tool()
def analyze_target(target: str) -> str:
    """AI analysis: tech fingerprint, recommended tools, CVE lookup, scan pace advice."""
    return _render(api("/api/intelligence/analyze-target", {"target": target}), indent=1)


@mcp.tool()
def select_tools(target: str, intent: str = "auto") -> str:
    """Pick tools for intent (recon/web/network/auto) given installed binaries + detected tech."""
    return _render(api("/api/intelligence/select-tools", {"target": target, "intent": intent}), indent=1)


@mcp.tool()
def optimize_parameters(tool: str) -> str:
    """Recommended parameters and timeout for a tool."""
    return _render(api("/api/intelligence/optimize-parameters", {"tool": tool}), indent=1)


@mcp.tool()
def run_tool(tool: str, params: str = "{}", async_run: bool = False) -> str:
    """Run a registered tool by name with JSON params (async_run=True returns pid immediately).

    Raw shell command execution is not supported; only tools in the registry
    may run.
    """
    parsed = json.loads(params) if params else {}
    return _render(api("/api/command", {"tool": tool, "params": parsed, "async": async_run}), indent=1)


@mcp.tool()
def processes() -> str:
    """List tracked server processes."""
    return _render(api("/api/processes/list"), indent=1)


@mcp.tool()
def process_status(pid: int) -> str:
    """Process status and recent output."""
    return _render(api(f"/api/processes/status/{pid}"), indent=1)


@mcp.tool()
def process_terminate(pid: int) -> str:
    """Kill a tracked process."""
    return _render(api(f"/api/processes/terminate/{pid}", {}), indent=1)


@mcp.tool()
def telemetry() -> str:
    """Server metrics: uptime, request count, avg response, cache, findings."""
    return _render(api("/api/telemetry"), indent=1)


@mcp.tool()
def cache_stats() -> str:
    """Cache entries, hits, evictions."""
    return _render(api("/api/cache/stats"), indent=1)


@mcp.tool()
def probe(target: str) -> str:
    """Quick HTTP probe: status, title, tech fingerprint (JSON)."""
    return _render(api("/api/probe", {"target": target}), indent=1)


@mcp.tool()
def portscan(target: str, ports: str = "") -> str:
    """Port/service scan, nmap -sV -T4 (JSON). ports='80,443' to limit."""
    return _render(api("/api/portscan", {"target": target, "ports": ports}), indent=1)


@mcp.tool()
def webscan(target: str) -> str:
    """Web vuln scan tuned to detected tech."""
    return _render(api("/api/webscan", {"target": target}), indent=1)


@mcp.tool()
def recon(domain: str) -> str:
    """Parallel passive recon: whois, dns, subdomain enumeration."""
    return _render(api("/api/recon", {"domain": domain}), indent=1)


@mcp.tool()
def assess(target: str) -> str:
    """Full pipeline: probe -> portscan -> conditional webscan, correlated findings."""
    return _render(api("/api/assess", {"target": target}), indent=1)


@mcp.tool()
def findings() -> str:
    """All recorded findings as JSON."""
    return _render(api("/api/findings"), indent=1)


@mcp.tool()
def report(fmt: str = "markdown") -> str:
    """Generate assessment report: 'markdown' or 'json'."""
    return _render(api("/api/report", {"fmt": fmt}), indent=1)


def _register(name, spec):
    """Dynamically register tool as MCP tool."""
    def fn(**kwargs):
        params = {k: kwargs.get(k, spec.params.get(k)) for k in spec.params}
        return _render(api("/api/command", {"tool": name, "params": params}), indent=1)

    fn.__name__ = name
    fn.__annotations__ = {k: str for k in spec.params}
    # Required params (None default) must precede defaulted ones in the signature.
    ordered = sorted(spec.params.items(), key=lambda kv: kv[1] is not None)
    fn.__signature__ = inspect.Signature(
        [
            inspect.Parameter(
                k,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                annotation=str,
                default=(inspect.Parameter.empty if v is None else v),
            )
            for k, v in ordered
        ]
    )
    fn.__doc__ = (
        f"{spec.description}\n"
        f"Risk: {spec.risk_level} | Binary: {spec.binary}\n"
        f"Params: {', '.join(spec.params)}"
    )
    mcp.tool()(fn)


def _select_for_limit(selected: dict, tool_limit: int) -> dict:
    """Cull a profile's tools down to tool_limit, stable and installed first.

    A dropped tool is not hidden from the server -- it just is not listed to
    this client, which is the correct response to a client tool-count limit
    rather than bypassing it.
    """
    if not tool_limit or len(selected) <= tool_limit:
        return selected
    ranked = sorted(
        selected.values(),
        key=lambda s: (s.maturity != "stable", not s.available, s.name),
    )
    return {s.name: s for s in ranked[:tool_limit]}


def register_profile_tools(profile_name: str = None, tool_limit: int = None) -> int:
    """Register the registry tools this profile exposes. Returns the count.

    Generating from the registry keeps MCP and REST in step: a tool added,
    reclassified, or removed in one place shows up correctly in both, and
    there is no hand-maintained MCP file to drift.

    tool_limit caps how many tools are registered. When the profile exposes
    more than the limit, the tools most likely to matter are kept first:
    stable maturity beats beta, installed binaries beat missing ones, and the
    rest are dropped (see _select_for_limit).
    """
    profile = mcp_profiles.get_profile(profile_name or PROFILE_NAME)
    selected = _select_for_limit(mcp_profiles.tools_for(profile), tool_limit)
    for name, spec in selected.items():
        _register(name, spec)
    return len(selected)


# ---------------------------------------------------------------------------
# Resources: read-only context a client can pull without spending a tool call.
# ---------------------------------------------------------------------------

@mcp.resource("nexhunter://tools")
def resource_tools() -> str:
    """Every tool in the registry with category, risk, maturity, availability."""
    return _render([spec.describe() for spec in T.TOOLS.values()])


@mcp.resource("nexhunter://tools/stable")
def resource_stable_tools() -> str:
    """Only tools marked stable: parsed, documented, and covered by tests."""
    return _render(
        [spec.describe() for spec in T.TOOLS.values() if spec.maturity == "stable"]
    )


@mcp.resource("nexhunter://tools/available")
def resource_available_tools() -> str:
    """Tools whose binary is actually installed on this host."""
    return _render(
        [spec.describe() for spec in T.TOOLS.values() if spec.available]
    )


def _profiles_summary() -> dict:
    """Which profile is active and what each profile exposes."""
    return {"active": PROFILE_NAME, "profiles": mcp_profiles.summarize()}


@mcp.resource("nexhunter://profiles")
def resource_profiles() -> str:
    """Available MCP profiles and how many tools each exposes."""
    return _render(_profiles_summary())


@mcp.resource("nexhunter://executions")
def resource_executions() -> str:
    """Recent executions with status and duration."""
    return _render(api("/api/executions"))


@mcp.resource("nexhunter://findings")
def resource_findings() -> str:
    """Findings recorded so far."""
    return _render(api("/api/findings"))


@mcp.resource("nexhunter://system/status")
def resource_status() -> str:
    """Server health and tool availability."""
    return _render(api("/health"))


@mcp.tool()
def list_profiles() -> str:
    """List MCP profiles, the tools each exposes, and which one is active."""
    return _render(_profiles_summary())


@mcp.tool()
def tool_info(name: str) -> str:
    """Describe one registered tool: parameters, risk level, maturity, availability."""
    spec = T.get_tool_spec(name)
    if spec is None:
        return json.dumps({"ok": False, "error": f"unknown tool: {name}"})
    return _render(spec.describe())


@mcp.tool()
def executions() -> str:
    """List recorded executions, newest first."""
    return _render(api("/api/executions"), indent=1)


@mcp.tool()
def execution_output(execution_id: str) -> str:
    """Captured stdout and stderr for one execution, with secrets redacted."""
    return _render(api(f"/api/executions/{urllib.parse.quote(execution_id)}/output"), indent=1)


@mcp.tool()
def execution_terminate(execution_id: str) -> str:
    """Terminate a running execution and everything it spawned."""
    return _render(api(f"/api/executions/{urllib.parse.quote(execution_id)}/terminate", {}), indent=1)


@mcp.tool()
def propose_plan(target: str, steps: list, risk_ceiling: str = "active") -> str:
    """Validate an AI-proposed plan WITHOUT executing anything.

    steps is a list of objects: [{"tool": "nmap_scan", "params": {"target": ...}}].
    Every step is looked up in the registry, its parameters are typed-validated,
    and its risk level is checked against the ceiling. Returns three lists:
    approved (validated, within the ceiling), withheld (above the ceiling,
    needs human approval), invalid (unknown tool or bad parameters). Nothing
    runs. Send the approved steps back to autonomous_assess to execute.
    """
    payload = {"target": target, "steps": steps, "risk_ceiling": risk_ceiling}
    return _render(api("/api/plan", payload), indent=1)


@mcp.tool()
def recommend_plan(target: str, risk_ceiling: str = "active") -> str:
    """Generate a senior-pentester methodology plan for a target WITHOUT running anything.

    Phases: recon (DNS/WHOIS/subdomains/web probe) -> enumeration (nmap,
    zone transfer) -> web enumeration (crawl, endpoints, parameters) ->
    assessment (nuclei, TLS, tech-specific) -> exploitation follow-ups.
    Each phase is gated on evidence the previous phase would produce.
    Exploitation steps are listed under 'withheld' - planned, but gated
    behind human approval. Use this first, review the phases, then run
    autonomous_assess.
    """
    payload = {"target": target, "risk_ceiling": risk_ceiling}
    return _render(api("/api/plan/recommend", payload), indent=1)


@mcp.tool()
def autonomous_assess(
    target: str,
    risk_ceiling: str = "active",
    max_steps: int = 20,
    steps: list = None,
) -> str:
    """Run an autonomous assessment of a target.

    Without steps, the orchestrator plans tools from what it observes, runs
    them, folds the results back into a target profile, and re-plans -- adapting
    in real time.

    With steps (the AI's own plan, e.g. the 'approved' list from propose_plan),
    exactly those steps are executed: each is typed-validated and ceiling-
    filtered again before it runs; anything above the ceiling is withheld.

    risk_ceiling caps what runs automatically (passive or active) and is
    clamped regardless of what is asked. Intrusive and destructive tools are
    never auto-executed; they are returned under 'recommended_next' for a human
    to approve. Returns a run id to poll with autonomous_status.
    """
    payload = {
        "target": target, "risk_ceiling": risk_ceiling, "max_steps": max_steps,
        "async": True,
    }
    if steps is not None:
        payload["steps"] = steps
    return _render(api("/api/autonomous", payload), indent=1)


@mcp.tool()
def autonomous_status(run_id: str) -> str:
    """Poll an autonomous run: phase, progress, executions, findings, and the
    tools it withheld pending human approval."""
    return _render(api(f"/api/autonomous/{urllib.parse.quote(run_id)}"), indent=1)


_REGISTERED_TOOL_COUNT = register_profile_tools()


def main():
    global SERVER, PROFILE_NAME, TOOL_LIMIT, MAX_OUTPUT
    parser = argparse.ArgumentParser(
        description="nexhunter MCP bridge. Flags override NEXHUNTER_MCP_* env vars."
    )
    parser.add_argument("--server", default=SERVER, help="nexhunter server URL")
    parser.add_argument(
        "--profile",
        default="",
        help=f"tool profile to expose (default: {mcp_profiles.DEFAULT_PROFILE}). "
             f"One of: {', '.join(sorted(mcp_profiles.PROFILES))}",
    )
    parser.add_argument(
        "--tool-limit",
        type=int,
        default=None,
        help="cap registered registry tools at N (stable and installed first). "
             "Respects a client's tool-count limit instead of bypassing it",
    )
    parser.add_argument(
        "--max-output",
        type=int,
        default=None,
        help="max chars kept per string field in tool results. Defaults to "
             "NEXHUNTER_MCP_MAX_OUTPUT or 4000. Keeps large tool output from "
             "flooding the LLM context window",
    )
    parser.add_argument("--list-profiles", action="store_true", help="print profiles and exit")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.list_profiles:
        for row in mcp_profiles.summarize():
            print(f"{row['name']:22} {row['tool_count']:4} tools "
                  f"({row['available_tool_count']} installed)  {row['description']}")
        return

    # Flags override env vars, which override defaults; one pass, one truth.
    import_time_profile = PROFILE_NAME
    SERVER = args.server.rstrip("/")
    PROFILE_NAME = args.profile or PROFILE_NAME
    env_limit = int(TOOL_LIMIT) if TOOL_LIMIT else None
    limit = args.tool_limit if args.tool_limit is not None else env_limit
    if args.max_output is not None:
        MAX_OUTPUT = args.max_output

    # Re-register only when the runtime settings differ from the import-time
    # defaults, so a plain `python -m nexhunter.api.mcp` stays a no-op and a
    # re-registration of identical tools is never attempted.
    if (args.profile and args.profile != import_time_profile) or args.tool_limit is not None:
        register_profile_tools(PROFILE_NAME, limit)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="[nexhunter-mcp] %(levelname)s %(message)s",
    )
    log.info(
        "server=%s profile=%s tools=%d limit=%s max_output=%d",
        SERVER, PROFILE_NAME,
        len(mcp_profiles.tools_for(mcp_profiles.get_profile(PROFILE_NAME))),
        limit, MAX_OUTPUT,
    )

    mcp.run()


if __name__ == "__main__":
    main()
