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
from nexhunter.api.logging_setup import InterceptHandler

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
    if not url.lower().startswith(("http://", "https://")):
        return {"ok": False, "error": f"refusing non-http server URL: {url}"}
    headers = {"Content-Type": "application/json"}
    req = urllib.request.Request(  # noqa: S310 - scheme guard above
        url,
        data=json.dumps(payload or {}).encode() if payload is not None else None,
        headers=headers,
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - scheme guard above
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


def _render(data, indent: int = 1) -> str:
    """Serialize an API response with token-economy trimming applied."""
    return json.dumps(_trim_json(data), indent=indent)


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
def cve_monitor(days: int = 7, severity: str = "", keyword: str = "",
                limit: int = 20) -> str:
    """Recent NVD CVEs (window in days, optional severity/keyword filter)
    ranked by exploitability (kind, CVSS, PoC hints)."""
    return _render(api("/api/agents/cve_watch", {
        "days": days, "severity": severity, "keyword": keyword, "limit": limit,
    }), indent=1)


@mcp.tool()
def run_tool(tool: str, params: str = "{}", async_run: bool = False, direct: bool = True) -> str:
    """Run a registered tool by name with JSON params (async_run=True returns pid immediately).

    Direct by default (in-process, no execution record);
    pass direct=False for tracked execution with history and workspaces.

    Raw shell command execution is not supported; only tools in the registry
    may run.
    """
    parsed = json.loads(params) if params else {}
    return _render(api("/api/command", {"tool": tool, "params": parsed, "async": async_run, "direct": direct}), indent=1)


@mcp.tool()
def run_with_recovery(tool: str, params: str = "{}", max_attempts: int = 3) -> str:
    """Run a registered tool with automatic failure recovery.

    On failure the run is retried along the cheapest viable path:
    reduced scope (fewer threads/gentler timing/smaller port range), then
    backoff, then an equivalent alternative tool. Returns the final result
    with a 'recovery' trail of attempts.
    """
    parsed = json.loads(params) if params else {}
    return _render(api("/api/recover", {"tool": tool, "params": parsed, "max_attempts": max_attempts}), indent=1)


@mcp.tool()
def http_repeater(request: str) -> str:
    """Fire one hand-tuned HTTP request and return the full response.

    request = JSON: {"method": "GET", "url": "https://x/", "headers": {}, "body": ""}
    """
    return _render(api("/api/web/repeater", {"request": json.loads(request) if request else {}}), indent=1)


@mcp.tool()
def http_intruder(request: str, payloads: str) -> str:
    """Sniper-style parameter fuzzing on an authorized target.

    Mark injection points in the URL/body with '§' (e.g.
    /user?id=§1§); each payload replaces every marker. payloads = JSON list
    of strings. Returns status distribution and anomalies.
    """
    try:
        req = json.loads(request) if request else {}
        pays = json.loads(payloads) if payloads else []
    except json.JSONDecodeError:
        return json.dumps({"ok": False, "error": "request/payloads must be valid JSON"})
    return _render(api("/api/web/intruder", {"request": req, "payloads": pays}), indent=1)


@mcp.tool()
def http_spider(url: str, max_pages: int = 50) -> str:
    """Crawl a site from a seed URL (same-origin only) and list pages found."""
    return _render(api("/api/web/spider", {"url": url, "max_pages": max_pages}), indent=1)


@mcp.tool()
def proxy_start(port: int = 8080, rules: str = "[]") -> str:
    """Start the localhost-only logging proxy (match-replace rules = JSON list
    of {"match": "regex", "replace": "..."})."""
    try:
        parsed_rules = json.loads(rules) if rules else []
    except json.JSONDecodeError:
        return json.dumps({"ok": False, "error": "rules must be valid JSON"})
    return _render(api("/api/web/proxy/start", {"port": port, "rules": parsed_rules}), indent=1)


@mcp.tool()
def proxy_stop(port: int = 8080) -> str:
    """Stop the localhost-only logging proxy."""
    return _render(api("/api/web/proxy/stop", {"port": port}), indent=1)


@mcp.tool()
def proxy_logs(port: int = 8080) -> str:
    """Requests seen by the localhost-only logging proxy."""
    return _render(api("/api/web/proxy/logs", {"port": port}), indent=1)


@mcp.tool()
def browser_analyze(url: str) -> str:
    """Full browser analysis of a URL: DOM artifacts, security headers,
    cookie flags, technology fingerprint, JS errors. Selenium when installed,
    stdlib fallback otherwise."""
    return _render(api("/api/browser/analyze", {"url": url}), indent=1)


@mcp.tool()
def browser_screenshot(url: str) -> str:
    """Take a screenshot of a URL with a headless browser and save it into
    the execution workspace. Selenium must be installed."""
    return _render(api("/api/browser/screenshot", {"url": url}), indent=1)


@mcp.tool()
def browser_network(url: str) -> str:
    """Capture the requests a page makes while loading (XHR, fetch, scripts,
    resources) with types and sizes. Selenium when installed."""
    return _render(api("/api/browser/network", {"url": url}), indent=1)


@mcp.tool()
def browser_discover(url: str) -> str:
    """JS-aware link discovery on a target (same-origin links rendered by
    JavaScript). Selenium when installed, static fallback otherwise."""
    return _render(api("/api/browser/crawl", {"url": url}), indent=1)


@mcp.tool()
def browser_forms(url: str) -> str:
    """Enumerate forms on a page: actions, methods, and input fields.
    Selenium when installed."""
    return _render(api("/api/browser/forms", {"url": url}), indent=1)


@mcp.tool()
def vulnerability_card(
    title: str,
    severity: str = "info",
    endpoint: str = "",
    impact: str = "",
    remediation: str = "",
    vuln_type: str = "Unknown",
    cvss_score: float | None = None,
    poc: str = "",
) -> str:
    """Format a vulnerability card (title, severity, endpoint, impact, fix,
    CVSS, PoC) into a structured record for reporting."""
    return _render(api("/api/visual/vulnerability-card", {
        "title": title, "severity": severity, "endpoint": endpoint,
        "impact": impact, "remediation": remediation, "type": vuln_type,
        "cvss_score": cvss_score, "poc": poc,
    }), indent=1)


@mcp.tool()
def dashboard() -> str:
    """Server dashboard metrics: requests, findings, processes, cache."""
    data = api("/api/visual/dashboard?format=box")
    box = data.get("box") if isinstance(data, dict) else None
    return box or _render(data, indent=1)


@mcp.tool()
def visual_vulnerabilities() -> str:
    """All recorded findings with severity statistics."""
    return _render(api("/api/visual/vulnerabilities"), indent=1)


@mcp.tool()
def attack_chain(chain: str, target: str, domain: str = "", host: str = "",
                 username: str = "", wordlist: str = "") -> str:
    """Build a named attack chain (each step: tool, params, gate, availability)
    scored with a success probability. Call with chain='' to list patterns.
    Patterns include recon_sweep, web_rce, ssrf_internal, credential_capture,
    api_abuse. Nothing executes; this is planning only."""
    return _render(api("/api/attack-chain", {
        "chain": chain, "target": target, "domain": domain, "host": host,
        "username": username, "wordlist": wordlist,
    }), indent=1)


@mcp.tool()
def file_list(path: str = "") -> str:
    """List a readable directory (defaults to the lab allow root)."""
    return _render(api("/api/file/list", {"path": path}), indent=1)


@mcp.tool()
def file_read(path: str) -> str:
    """Read a file, capped at max_bytes."""
    return _render(api("/api/file/read", {"path": path}), indent=1)


@mcp.tool()
def file_write(path: str, content: str) -> str:
    """Write a file under the allow root only (lab sandbox)."""
    return _render(api("/api/file/write", {"path": path, "content": content}), indent=1)


@mcp.tool()
def python_run(code: str, timeout: int = 60) -> str:
    """Run a short Python snippet in an isolated scratch cwd (capped output)."""
    return _render(api("/api/python/run", {"code": code, "timeout": timeout}), indent=1)


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
def process_pause(pid: int) -> str:
    """Pause a running process (SIGSTOP). Use for long scans; the run timeout still applies."""
    return _render(api(f"/api/processes/pause/{pid}", {}), indent=1)


@mcp.tool()
def process_resume(pid: int) -> str:
    """Resume a paused process (SIGCONT)."""
    return _render(api(f"/api/processes/resume/{pid}", {}), indent=1)


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


@mcp.tool()
def create_file(filename: str, content: str, binary: bool = False) -> str:
    """Create a file with specified content on the server. Confined to sandbox root."""
    return _render(api("/api/files/create", {"filename": filename, "content": content, "binary": binary}), indent=1)


@mcp.tool()
def modify_file(filename: str, content: str, append: bool = False) -> str:
    """Modify an existing file on the server (append or overwrite). Confined to sandbox."""
    return _render(api("/api/files/modify", {"filename": filename, "content": content, "append": append}), indent=1)


@mcp.tool()
def delete_file(filename: str) -> str:
    """Delete a file or directory on the server. Confined to sandbox."""
    return _render(api("/api/files/delete", {"filename": filename}), indent=1)


@mcp.tool()
def list_files(directory: str = ".") -> str:
    """List files in a directory on the server. Confined to sandbox."""
    return _render(api("/api/files/list", {"directory": directory}), indent=1)


@mcp.tool()
def install_python_package(package: str, env_name: str = "default") -> str:
    """Install a Python package in the environment on the server."""
    return _render(api("/api/python/install", {"package": package, "env_name": env_name}), indent=1)


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


def _select_for_limit(selected: dict, tool_limit: int | None) -> dict:
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


def register_profile_tools(profile_name: str | None = None, tool_limit: int | None = None) -> int:
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
def plan_assessment(
    target: str, objective: str = "standard", risk_ceiling: str = "active"
) -> str:
    """Get a SCORED shortlist of the tools worth running against a target, WITHOUT running anything.

    This is the plan-first step: instead of considering all 252 registered
    tools, the selector scores every tool against the target profile (its type,
    technologies, web/TLS surface), its category relevance, maturity, and
    whether the binary is installed -- then returns only the high-value few,
    ranked, each with the reasons behind the pick.

    objective controls breadth:
      quick          top ~5, highest-value only
      standard       top ~12 (default)
      comprehensive  up to ~30, everything above a low threshold
      stealth        passive tools only

    Returns 'selected' (recommended, within the ceiling), grouped into phases,
    plus 'withheld' (above the ceiling, needs human approval) and 'considered'
    (how many tools were weighed). Review this, choose the subset you actually
    want, then pass those to propose_plan / autonomous_assess. This is how you
    ensure only the necessary tools run, not the whole registry.
    """
    payload = {"target": target, "objective": objective, "risk_ceiling": risk_ceiling}
    return _render(api("/api/plan/select", payload), indent=1)


@mcp.tool()
def optimize_tool(tool: str, target: str, objective: str = "standard") -> str:
    """Show how one tool would be invoked against a target, WITHOUT running it.

    Derives the parameters the tool should run with -- the right target form
    (bare hostname vs full URL vs host/IP), an installed wordlist where one is
    required, web ports for a web target -- and returns them together with the
    exact command line they build and whether it is runnable. Use this to check
    that a selected tool is actually going to work before executing it, or to
    see the tuned parameters to hand to propose_plan / autonomous_assess.
    """
    payload = {"tool": tool, "target": target, "objective": objective}
    return _render(api("/api/tools/optimize", payload), indent=1)


@mcp.tool()
def autonomous_assess(
    target: str,
    risk_ceiling: str = "active",
    max_steps: int = 20,
    steps: list | None = None,
    strategy: str = "methodology",
    objective: str = "standard",
    direct: bool = True,
) -> str:
    """Run an autonomous assessment of a target.

    Without steps, the orchestrator plans tools from what it observes, runs
    them, folds the results back into a target profile, and re-plans -- adapting
    in real time. `strategy` chooses how it plans:
      methodology  fixed, reviewed phase walk (default, deterministic)
      select       scoring-driven selection over the whole registry, capped by
                   `objective` (quick|standard|comprehensive|stealth) so only
                   high-value tools for the observed profile run

    With steps (the AI's own plan, e.g. the 'approved' list from propose_plan,
    or a subset chosen from plan_assessment), exactly those steps are executed:
    each is typed-validated and ceiling-filtered again before it runs; anything
    above the ceiling is withheld.

    risk_ceiling caps what runs automatically (passive or active) and is
    clamped regardless of what is asked. Intrusive and destructive tools are
    never auto-executed; they are returned under 'recommended_next' for a human
    to approve. Returns a run id to poll with autonomous_status.

    `direct=True` (the default) runs each step through the
    in-process path: no per-tool execution records or workspaces, while cache,
    redaction, the risk ceiling and result absorption stay on. Pass
    direct=False for fully tracked step execution.
    """
    payload = {
        "target": target, "risk_ceiling": risk_ceiling, "max_steps": max_steps,
        "async": True, "strategy": strategy, "objective": objective,
        "direct": bool(direct),
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
        handlers=[InterceptHandler()],
        level=logging.DEBUG if args.debug else logging.INFO,
        force=True,
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
