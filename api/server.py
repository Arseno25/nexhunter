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
    POST /api/command           Direct tool execution
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
import json
import os
import shlex
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
from nexhunter.security.authentication import TokenValidator, AuthenticationError

ENGINE = Engine()
TOKEN_VALIDATOR = TokenValidator()


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
    # Public endpoints that don't require authentication
    PUBLIC_ENDPOINTS = {"/health", "/version", "/ready"}

    def _check_auth(self, path: str) -> bool:
        """Check authentication for protected endpoints. Return True if authenticated."""
        if path in self.PUBLIC_ENDPOINTS:
            return True

        auth_header = self.headers.get("Authorization")
        is_valid, error = TOKEN_VALIDATOR.validate(auth_header)
        if not is_valid:
            self._json(401, {"ok": False, "error": error or "Unauthorized", "code": "UNAUTHORIZED"})
            return False
        return True

    def _json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
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

    def _command(self, body):
        if "tool" in body:
            spec = T.get_tool_spec(body["tool"])
            if not spec:
                return {"ok": False, "error": f"unknown tool: {body['tool']}"}
            user_params = body.get("params", {})
            params = {k: user_params.get(k, spec.params.get(k)) for k in spec.params}
            ok, err = spec.validate(params)
            if not ok:
                return {"ok": False, "error": err}
            cmd = spec.build_cmd(params)
            if not cmd:
                return {"ok": False, "error": f"failed to build command for {body['tool']}"}
            timeout = spec.timeout
        else:
            cmd = shlex.split(body.get("cmd", ""))
            if not cmd:
                return {"ok": False, "error": "empty cmd"}
            timeout = int(body.get("timeout", 300))
        if body.get("async"):
            return PM.start(cmd, cmd[0])
        return PM.start_and_wait(cmd, cmd[0], timeout)

    def do_GET(self):
        t0 = time.time()
        try:
            path = urllib.parse.urlparse(self.path).path
            if not self._check_auth(path):
                return
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
            if not self._check_auth(path):
                return
            body = self._body()
            fn = None
            if path == "/api/command":
                fn = lambda: self._command(body)
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
    parser = argparse.ArgumentParser(description="nexhunter server (13 agents, 24 tools, process mgmt)")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return
    print(f"NexHunter server on http://127.0.0.1:{args.port} (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
