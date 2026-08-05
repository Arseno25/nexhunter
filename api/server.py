"""nexhunter HTTP API Server - REST API only (CLI access recommended).

Architecture:
  Tool Registry → ToolSpec class with validation
  Engine Layer → Orchestration with caching, parallel execution
  Agent Layer → 18 specialized agents (13 core + 5 enhanced)
  API Layer → HTTP REST endpoints

Features:
  ✓ Real-time telemetry & process monitoring
  ✓ Full security assessment workflows (9 types, 73 phases)
  ✓ CVE intelligence via NVD API
  ✓ Finding deduplication & correlation
  ✓ Multi-tool orchestration with caching

Key Endpoints:
  Health:
    GET  /health         Server status & capabilities
  Assessment:
    POST /api/assess     Full target assessment
    POST /api/probe      Quick HTTP probe
    POST /api/portscan   Port/service discovery
    POST /api/webscan    Web vulnerability scan
    POST /api/recon      Domain reconnaissance
  Workflows:
    POST /api/flow/bugbounty    Phased bug bounty flow
    POST /api/flow/ctf          CTF challenge toolkit
  Agents:
    GET  /api/agents/list       List all agents
    POST /api/agents/<name>     Run agent
  Tools:
    POST /api/command           Registered tool execution (by name; raw
                                OS commands are rejected)
  Intelligence:
    POST /api/intelligence/analyze-target
    POST /api/intelligence/select-tools
    POST /api/intelligence/optimize-parameters
  Results:
    GET  /api/findings          All findings (JSON)
    POST /api/report            Generate report
    POST /api/clear             Clear findings
  Telemetry:
    GET  /api/telemetry         Server metrics
    GET  /api/cache/stats       Cache statistics
  Process Management:
    GET  /api/processes/list              Active processes
    GET  /api/processes/status/<pid>      Process status
    POST /api/processes/terminate/<pid>   Kill process

Run:
    python -m nexhunter.api.server [--port 8888]

Access:
    CLI: python nexhunter.py <command>
    REST: curl http://localhost:8888/api/...
"""

import argparse
import dataclasses
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nexhunter.core import tools as T
from nexhunter.agents import AGENTS, run_agent
from nexhunter.agents.enhanced import ENHANCED_AGENTS
from nexhunter.core.engine import Engine
from nexhunter.api.visual import VulnerabilityCard, ProgressTracker, DashboardMetrics
from nexhunter.execution.service import ExecutionService
from nexhunter.api import mcp_profiles
from nexhunter.findings import export as findings_export
from nexhunter.findings.store import FindingStore
from nexhunter.workflows.orchestrator import AutonomousOrchestrator
from nexhunter import config as nexhunter_config

ENGINE = Engine()
FINDINGS = FindingStore()
# Single execution path shared with the MCP server: validate, build, run,
# record. Nothing else in this module spawns a process.
EXEC = ExecutionService()
# Autonomous, adaptive assessment. Drives EXEC, so every step it takes runs on
# exactly the same terms as a manual call.
ORCHESTRATOR = AutonomousOrchestrator(execution_service=EXEC, finding_store=FINDINGS)


class ProcessManager:
    def __init__(self):
        self.procs = {}

    def start(self, cmd, name):
        try:
            p = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        except FileNotFoundError:
            return {"ok": False, "error": f"binary '{cmd[0]}' not found on PATH"}
        rec = {"pid": p.pid, "cmd": cmd, "name": name, "started": time.time(), "running": True, "output": []}
        self.procs[p.pid] = rec

        def pump():
            for line in p.stdout:
                rec["output"].append(line.rstrip())
                if len(rec["output"]) > 200:
                    rec["output"].pop(0)
            rec["running"] = False

        threading.Thread(target=pump, daemon=True).start()
        return {"ok": True, "pid": p.pid, "name": name, "cmd": cmd}

    def start_and_wait(self, cmd, name, timeout=300):
        r = self.start(cmd, name)
        if not r["ok"]:
            return r
        rec = self.procs[r["pid"]]
        deadline = time.time() + timeout
        while rec["running"] and time.time() < deadline:
            time.sleep(0.2)
        return {"ok": not rec["running"], "pid": r["pid"], "timed_out": rec["running"], "output": "\n".join(rec["output"])}

    def list(self):
        return [
            {"pid": pid, "name": r["name"], "cmd": r["cmd"], "running": r["running"], "uptime_s": round(time.time() - r["started"], 1), "lines": len(r["output"])}
            for pid, r in self.procs.items()
        ]

    def status(self, pid):
        r = self.procs.get(pid)
        if not r:
            return {"ok": False, "error": "no such process"}
        return {"ok": True, "pid": pid, "running": r["running"], "uptime_s": round(time.time() - r["started"], 1), "output": r["output"][-50:]}

    def terminate(self, pid):
        r = self.procs.get(pid)
        if not r:
            return {"ok": False, "error": "no such process"}
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
            else:
                subprocess.run(["kill", "-9", str(pid)], capture_output=True)
        except Exception as e:
            return {"ok": False, "error": str(e)}
        r["running"] = False
        return {"ok": True, "pid": pid}


PM = ProcessManager()


class Telemetry:
    def __init__(self):
        self.count = 0
        self.recent = []
        self.start = time.time()

    def record(self, dur):
        self.count += 1
        self.recent.append(dur)
        del self.recent[:-200]

    def stats(self):
        return {
            "uptime_s": round(time.time() - self.start, 1),
            "requests": self.count,
            "avg_response_ms": round(sum(self.recent) / len(self.recent) * 1000, 1) if self.recent else 0,
            "cache_entries": len(ENGINE._cache),
            "cache_hits": ENGINE.cache_hits,
            "cache_evictions": ENGINE.cache_evictions,
            "findings": len(ENGINE.findings),
            "processes": len(PM.procs),
        }


TEL = Telemetry()


def _analyze_target(target):
    tech = run_agent(ENGINE, "technology", {"target": target})
    dec = run_agent(ENGINE, "decision", {"target": target})
    techs = (tech.get("result") or {}).get("tech") or []
    cve = run_agent(ENGINE, "cve", {"tech": ", ".join(techs)}).get("result", {}) if techs else {}
    return {
        "target": target,
        **(tech.get("result") or {}),
        "recommended_tools": (dec.get("result") or {}).get("recommended_tools", []),
        "cve_lookup": cve.get("cves_by_tech", {}),
        "top_critical": cve.get("top_critical", []),
    }


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, code, body_text, content_type):
        body = body_text.encode()
        self.send_response(code)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code, text):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return {}

    def _execution_get(self, path):
        """Route /api/executions/<id>[/output|/artifacts]. Returns (code, body)."""
        rest = path[len("/api/executions/"):].strip("/")
        if not rest:
            return 404, {"ok": False, "error": "not found", "code": "NOT_FOUND"}

        parts = rest.split("/")
        execution_id, sub = parts[0], (parts[1] if len(parts) > 1 else "")

        if sub == "output":
            result = EXEC.output(execution_id)
        elif sub == "artifacts":
            result = EXEC.artifacts(execution_id)
        elif not sub:
            record = EXEC.registry.get(execution_id)
            if record is None:
                return 404, {"ok": False, "error": f"no such execution: {execution_id}", "code": "NOT_FOUND"}
            result = {"ok": True, "execution": record.to_dict()}
        else:
            return 404, {"ok": False, "error": "not found", "code": "NOT_FOUND"}

        return (200 if result.get("ok") else 404), result

    def _command(self, body):
        # Only registered tools may run. Raw OS command passthrough was removed:
        # arbitrary "cmd" strings are no longer accepted under any condition.
        tool_name = body.get("tool")
        if not tool_name:
            return {"ok": False, "error": "missing 'tool'; raw command execution is not permitted", "code": "TOOL_REQUIRED"}

        return EXEC.execute(
            tool_name=tool_name,
            params=body.get("params", {}),
            run_async=bool(body.get("async")),
        )

    def _start_autonomous(self, body):
        """Kick off an adaptive autonomous run, or an AI-proposed plan."""
        target = body.get("target")
        if not target:
            return {"ok": False, "error": "target is required", "code": "TARGET_REQUIRED"}
        run = ORCHESTRATOR.start(
            target=target,
            risk_ceiling=body.get("risk_ceiling", "active"),
            max_steps=int(body.get("max_steps", 20)),
            run_async=bool(body.get("async", True)),
            steps=body.get("steps"),
        )
        return {"ok": True, "run": run.to_dict()}

    def _propose_plan(self, body):
        """Validate an AI-proposed plan without executing anything."""
        target = body.get("target")
        steps = body.get("steps")
        if not target:
            return {"ok": False, "error": "target is required", "code": "TARGET_REQUIRED"}
        if not isinstance(steps, list):
            return {"ok": False, "error": "steps must be a list of {tool, params}", "code": "PLAN_REQUIRED"}
        review = ORCHESTRATOR.review_plan(target, steps, body.get("risk_ceiling", "active"))
        return {"ok": True, "plan": review}

    def do_GET(self):
        t0 = time.time()
        try:
            path = urllib.parse.urlparse(self.path).path
            if path == "/health":
                deg = run_agent(ENGINE, "degradation", {})
                mode = "degraded"
                if deg.get("ok"):
                    mode = deg.get("data", {}).get("mode", "degraded")
                self._json(200, {
                    "ok": True,
                    "version": "3.0.0",
                    "mode": mode,
                    "agents": sorted(AGENTS),
                    "tools_installed": {n: bool(T.which(s.binary)) for n, s in T.TOOLS.items()},
                })
            elif path == "/version":
                self._json(200, {"ok": True, "version": "3.0.0", "name": "NexHunter"})
            elif path == "/ready":
                self._json(200, {"ok": True, "ready": True})
            elif path == "/api/telemetry":
                self._json(200, TEL.stats())
            elif path == "/api/cache/stats":
                self._json(200, {"entries": len(ENGINE._cache), "hits": ENGINE.cache_hits, "evictions": ENGINE.cache_evictions})
            elif path == "/api/agents/list":
                self._json(200, [{"name": a.name, "desc": a.desc} for a in AGENTS.values()])
            elif path == "/api/processes/list":
                self._json(200, PM.list())
            elif path == "/api/findings":
                self._json(200, json.loads(ENGINE.report("json")))
            elif path == "/api/tools":
                query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                specs = list(T.TOOLS.values())
                for field in ("category", "risk_level", "maturity"):
                    wanted = (query.get(field) or [None])[0]
                    if wanted:
                        specs = [s for s in specs if getattr(s, field) == wanted]
                if (query.get("available") or [None])[0] == "true":
                    specs = [s for s in specs if s.available]
                self._json(200, {
                    "ok": True,
                    "count": len(specs),
                    "tools": [s.describe() for s in specs],
                })
            elif path == "/api/tools/status":
                specs = list(T.TOOLS.values())
                installed = [s for s in specs if s.available]
                self._json(200, {
                    "ok": True,
                    "registered": len(specs),
                    "installed": len(installed),
                    "missing": len(specs) - len(installed),
                    "by_category": mcp_profiles.categories(),
                    "by_maturity": {
                        level: sum(1 for s in specs if s.maturity == level)
                        for level in ("stable", "beta", "experimental", "disabled")
                    },
                    "installed_tools": sorted(s.name for s in installed),
                })
            elif path == "/api/autonomous":
                runs = ORCHESTRATOR.list_runs()
                self._json(200, {"ok": True, "runs": [r.to_dict() for r in runs]})
            elif path.startswith("/api/autonomous/"):
                run = ORCHESTRATOR.get_run(path.rsplit("/", 1)[1])
                if run is None:
                    self._json(404, {"ok": False, "error": "no such run", "code": "NOT_FOUND"})
                else:
                    self._json(200, {"ok": True, "run": run.to_dict()})
            elif path == "/api/findings/summary":
                self._json(200, {"ok": True, "summary": FINDINGS.summary()})
            elif path == "/api/findings/export":
                query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                fmt = (query.get("format") or ["json"])[0]
                try:
                    rendered = findings_export.export(
                        FINDINGS.list(), fmt
                    )
                except ValueError as exc:
                    self._json(400, {"ok": False, "error": str(exc), "code": "UNKNOWN_FORMAT"})
                else:
                    if fmt in ("markdown", "md"):
                        self._text(200, rendered, "text/markdown")
                    elif fmt == "html":
                        self._html(200, rendered)
                    elif fmt == "jsonl":
                        self._text(200, rendered, "application/x-ndjson")
                    else:
                        self._text(200, rendered, "application/json")
            elif path == "/api/mcp/profiles":
                self._json(200, {"ok": True, "profiles": mcp_profiles.summarize()})
            elif path.startswith("/api/tools/"):
                name = path[len("/api/tools/"):].strip("/")
                spec = T.get_tool_spec(name)
                if spec is None:
                    self._json(404, {"ok": False, "error": f"unknown tool: {name}", "code": "UNKNOWN_TOOL"})
                else:
                    self._json(200, {"ok": True, "tool": spec.describe()})
            elif path == "/api/executions":
                records = EXEC.registry.list()
                self._json(200, {
                    "ok": True,
                    "executions": [r.to_dict() for r in records],
                    "stats": EXEC.registry.stats(),
                })
            elif path.startswith("/api/executions/"):
                self._json(*self._execution_get(path))
            elif path.startswith("/api/processes/status/"):
                self._json(200, PM.status(int(path.rsplit("/", 1)[1])))
            elif path == "/api/visual/dashboard":
                metrics = DashboardMetrics()
                metrics.requests = getattr(TEL, "total_requests", 0)
                metrics.findings = len(ENGINE.findings) if hasattr(ENGINE, "findings") else 0
                metrics.processes = len(PM.procs)
                self._json(200, metrics.to_dict())
            elif path == "/api/visual/vulnerabilities":
                findings = ENGINE.findings if hasattr(ENGINE, "findings") else []
                vuln_list = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
                self._json(200, {"vulnerabilities": vuln_list, "count": len(vuln_list)})
            else:
                self._json(404, {"error": "not found"})
        finally:
            TEL.record(time.time() - t0)

    def do_POST(self):
        t0 = time.time()
        try:
            path = urllib.parse.urlparse(self.path).path
            body = self._body()
            fn = None
            if path == "/api/command":
                fn = lambda: self._command(body)
            elif path == "/api/autonomous":
                fn = lambda: self._start_autonomous(body)
            elif path == "/api/plan":
                fn = lambda: self._propose_plan(body)
            elif path.startswith("/api/executions/") and path.endswith("/terminate"):
                execution_id = path[len("/api/executions/"):-len("/terminate")].strip("/")
                fn = lambda: EXEC.terminate(execution_id)
            elif path == "/api/intelligence/analyze-target":
                fn = lambda: _analyze_target(body.get("target", ""))
            elif path == "/api/intelligence/select-tools":
                fn = lambda: run_agent(ENGINE, "decision", {"target": body.get("target", ""), "intent": body.get("intent", "auto")})
            elif path == "/api/intelligence/optimize-parameters":
                fn = lambda: run_agent(ENGINE, "optimizer", {"tool": body.get("tool", "")})
            elif path.startswith("/api/agents/"):
                name = path.rsplit("/", 1)[1]
                if name in ENHANCED_AGENTS:
                    fn = lambda: ENHANCED_AGENTS[name].execute(ENGINE, body)
                else:
                    fn = lambda: run_agent(ENGINE, name, body)
            elif path == "/api/flow/bugbounty":
                fn = lambda: run_agent(ENGINE, "bugbounty", {"target": body.get("target", ""), "phases": body.get("phases", "all")})
            elif path == "/api/flow/bugbounty-pro":
                fn = lambda: ENHANCED_AGENTS["bugbounty_pro"].execute(ENGINE, body)
            elif path == "/api/flow/ctf":
                fn = lambda: run_agent(ENGINE, "ctf", {"target": body.get("target", ""), "category": body.get("category", "web"), "file": body.get("file", "")})
            elif path == "/api/intelligence/osint":
                fn = lambda: ENHANCED_AGENTS["osint"].execute(ENGINE, body)
            elif path == "/api/intelligence/vulnerability-analysis":
                fn = lambda: ENHANCED_AGENTS["vuln_analyzer"].execute(ENGINE, body)
            elif path == "/api/intelligence/threat-assessment":
                fn = lambda: ENHANCED_AGENTS["threat_intel"].execute(ENGINE, body)
            elif path == "/api/tools/ctf-solver":
                fn = lambda: ENHANCED_AGENTS["ctf_solver"].execute(ENGINE, body)
            elif path.startswith("/api/processes/terminate/"):
                fn = lambda: PM.terminate(int(path.rsplit("/", 1)[1]))
            elif path == "/api/processes/terminate":
                fn = lambda: PM.terminate(int(body.get("pid", 0)))
            elif path in ("/api/probe", "/api/portscan", "/api/webscan", "/api/recon", "/api/assess"):
                engine_flow = {"target": body.get("target", ""), "ports": body.get("ports", ""), "domain": body.get("domain", "")}
                fn = {
                    "/api/probe": lambda: ENGINE.probe(engine_flow["target"]),
                    "/api/portscan": lambda: ENGINE.portscan(engine_flow["target"], engine_flow["ports"]),
                    "/api/webscan": lambda: ENGINE.webscan(engine_flow["target"]),
                    "/api/recon": lambda: ENGINE.recon(engine_flow["domain"]),
                    "/api/assess": lambda: ENGINE.assess(engine_flow["target"]),
                }[path]
            elif path == "/api/report":
                fn = lambda: {"report": ENGINE.report(body.get("fmt", "markdown"))}
            elif path == "/api/clear":
                fn = lambda: (ENGINE.findings.clear(), {"ok": True})[1]
            elif path == "/api/visual/vulnerability-card":
                fn = lambda: VulnerabilityCard(
                    title=body.get("title", "Unknown"),
                    severity=body.get("severity", "info"),
                    endpoint=body.get("endpoint", ""),
                    impact=body.get("impact", ""),
                    remediation=body.get("remediation", ""),
                    vuln_type=body.get("type", "Unknown"),
                    cvss_score=body.get("cvss_score"),
                    poc=body.get("poc", ""),
                ).to_dict()
            elif path == "/api/visual/vulnerabilities":
                fn = lambda: {
                    "vulnerabilities": [f.to_dict() if hasattr(f, "to_dict") else f for f in ENGINE.findings],
                    "stats": {"total": len(ENGINE.findings), "critical": sum(1 for f in ENGINE.findings if getattr(f, "severity", "") == "critical")},
                }
            if fn:
                try:
                    self._json(200, fn())
                except Exception as e:
                    self._json(500, {"ok": False, "error": str(e)})
            else:
                self._json(404, {"error": "not found"})
        finally:
            TEL.record(time.time() - t0)

    def log_message(self, fmt, *args):
        pass


def selftest():
    from nexhunter.core.engine import Engine

    assert len(AGENTS) >= 13, f"expected 13 agents, got {len(AGENTS)}"
    names = sorted(AGENTS)
    assert "bugbounty" in names and "ctf" in names and "exploit" in names and "browser" in names

    for name, spec in T.TOOLS.items():
        dummy = {k: (v if v is not None else "x") for k, v in spec.params.items()}
        argv = spec.build_cmd(dummy)
        assert isinstance(argv, list) and all(isinstance(a, str) and a for a in argv), name
        assert argv[0] == spec.binary, name

    e = Engine()
    r1 = e._cached_run(["definitely-not-a-binary"], 5)
    r2 = e._cached_run(["definitely-not-a-binary"], 5)
    assert not r1["ok"] and r2["cached"] is True and e.cache_hits == 1

    d = run_agent(e, "decision", {"target": "http://example.com", "intent": "recon"})
    assert d["ok"] and isinstance(d.get("data", {}).get("recommended_tools"), list)
    o = run_agent(e, "optimizer", {"tool": "nmap_scan"})
    assert o["ok"] and o.get("data", {}).get("binary") == "nmap"
    g = run_agent(e, "degradation", {})
    assert g["ok"] and "mode" in g.get("data", {})
    p = run_agent(e, "performance", {})
    assert p["ok"] and "cache_hit_rate" in p.get("data", {})
    c = run_agent(e, "correlator", {})
    assert c["ok"] and "chains" in c.get("data", {})
    r = run_agent(e, "recovery", {"tool": "nmap_scan", "params": {}})
    assert r["ok"] or not r["ok"]
    print(f"nexhunter selftest OK ({len(AGENTS)} agents, {len(T.TOOLS)} tools)")


def main():
    parser = argparse.ArgumentParser(description="NexHunter API server")
    parser.add_argument("--port", type=int, default=None, help="override NEXHUNTER_BIND_PORT")
    parser.add_argument("--host", default=None, help="override NEXHUNTER_BIND_HOST")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        selftest()
        return

    # Validate before binding. Starting with an unintended security posture is
    # worse than not starting, so configuration errors are fatal.
    try:
        config = nexhunter_config.load(refresh=True)
    except nexhunter_config.ConfigError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1

    host = args.host or config.bind_host
    port = args.port or config.bind_port

    if args.host or args.port:
        config = dataclasses.replace(config, bind_host=host, bind_port=port)

    errors = config.validate()
    if errors:
        print("[FAIL] invalid configuration:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    for warning in config.warnings():
        print(f"[WARN] {warning}", file=sys.stderr)

    if config.binds_externally:
        print(
            f"[WARN] Listening on {host}, which is reachable from other hosts. "
            "Only do this on a network you control.",
            file=sys.stderr,
        )

    print(f"NexHunter server on http://{host}:{port} (Ctrl+C to stop)")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
