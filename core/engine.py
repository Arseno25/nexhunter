"""nexhunter.engine - orchestration: caching, parallel exec, tech-aware tool selection."""

import hashlib
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Optional, Dict, List, Any

from nexhunter.core import tools as T
from nexhunter.core.config import (
    CACHE_MAX,
    MAX_PARALLEL_WORKERS,
    MAX_TOOL_OUTPUT_PREVIEW,
    FINDING_DEDUP_ENABLED,
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    """Standardized finding with deduplication support."""

    tool: str
    target: str
    title: str
    severity: str = "info"
    evidence: str = ""
    timestamp: float = field(default_factory=time.time)

    def signature(self) -> str:
        """Generate unique signature for deduplication."""
        msg = f"{self.tool}:{self.target}:{self.title}".encode()
        return hashlib.md5(msg).hexdigest()

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


class WorkflowContext:
    """Tracks state across workflow phases."""

    def __init__(self, target: str):
        self.target = target
        self.phases = {}
        self.started = time.time()

    def set_phase(self, name: str, result: Any):
        """Record phase result."""
        self.phases[name] = {"result": result, "timestamp": time.time()}

    def get_phase(self, name: str) -> Optional[Any]:
        """Retrieve phase result."""
        return self.phases.get(name, {}).get("result")

    def elapsed(self) -> float:
        """Get elapsed time."""
        return time.time() - self.started


class Engine:
    """Orchestration engine with caching, parallel exec, finding tracking."""

    def __init__(self):
        self.findings: List[Finding] = []
        self._finding_sigs = set()
        self._cache: Dict[str, dict] = {}
        self._cache_order: List[str] = []
        self.cache_hits = 0
        self.cache_evictions = 0
        self._tool_stats: Dict[str, List[float]] = {}
        self._host_requests: Dict[str, List[float]] = {}
        self.workflow_contexts: Dict[str, WorkflowContext] = {}

    def _track(self, target: str):
        """Track request rate per host."""
        host = target.split("//")[-1].split("/")[0].split(":")[0]
        if host:
            self._host_requests.setdefault(host, []).append(time.time())

    def _cached_run(self, cmd: list, timeout: int) -> dict:
        """Run command with caching."""
        key = " ".join(cmd)
        if key in self._cache:
            self.cache_hits += 1
            return dict(self._cache[key], cached=True)
        res = T.run(cmd, timeout)
        res["cached"] = False
        self._cache[key] = res
        self._cache_order.append(key)
        if len(self._cache) > CACHE_MAX:
            self._cache.pop(self._cache_order.pop(0), None)
            self.cache_evictions += 1
        return res

    def run_tool(self, name: str, params: dict) -> dict:
        """Run tool with validation and stats."""
        spec = T.get_tool_spec(name)
        if not spec:
            return {"ok": False, "error": f"unknown tool: {name}", "stdout": "", "stderr": "", "exit": -1}

        ok, err = spec.validate(params)
        if not ok:
            return {"ok": False, "error": err, "stdout": "", "stderr": "", "exit": -1}

        cmd = spec.build_cmd(params)
        if not cmd:
            return {"ok": False, "error": f"failed to build command for {name}", "stdout": "", "stderr": "", "exit": -1}

        t0 = time.time()
        res = self._cached_run(cmd, spec.timeout)
        elapsed = time.time() - t0
        self._tool_stats.setdefault(name, []).append(elapsed)
        self._tool_stats[name] = self._tool_stats[name][-20:]
        return res

    def parallel(self, jobs: Dict[str, callable]) -> dict:
        """Execute multiple functions in parallel."""
        out = {}
        max_workers = min(MAX_PARALLEL_WORKERS, len(jobs) or 1)
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futs = {ex.submit(fn): n for n, fn in jobs.items()}
            for f in as_completed(futs):
                try:
                    out[futs[f]] = f.result()
                except Exception as e:
                    out[futs[f]] = {"ok": False, "error": str(e)}
        return out

    def add(self, finding: Finding):
        """Add finding with deduplication."""
        if FINDING_DEDUP_ENABLED:
            sig = finding.signature()
            if sig in self._finding_sigs:
                return
            self._finding_sigs.add(sig)
        self.findings.append(finding)

    @staticmethod
    def _parse_curl_probe(headers: str, body: str) -> dict:
        """Parse curl headers and body for HTTP metadata."""
        status = 0
        m = re.search(r"HTTP/\S+\s+(\d{3})", headers)
        if m:
            status = int(m.group(1))
        server = ""
        m = re.search(r"(?im)^server:\s*(.+)$", headers)
        if m:
            server = m.group(1).strip()
        title = ""
        m = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
        if m:
            title = m.group(1).strip()
        return {"status": status, "title": title, "tech": [server] if server else []}

    def probe(self, target: str) -> dict:
        """HTTP probe target for status, title, tech detection."""
        self._track(target)
        res = self.run_tool("httpx_probe", {"target": target})
        if res["ok"] and res["stdout"]:
            return {
                "ok": True,
                "target": target,
                "data": T.parse_output("httpx", res["stdout"]),
                "cached": res.get("cached", False),
            }
        if T.which("curl"):
            head = self._cached_run(["curl", "-sSI", "--max-time", "15", target], 30)
            body = self._cached_run(["curl", "-sS", "--max-time", "15", target], 30)
            if head["ok"] or body["ok"]:
                d = self._parse_curl_probe(head["stdout"], body["stdout"])
                cached = head.get("cached", False) or body.get("cached", False)
                return {"ok": True, "target": target, "data": [{"url": target, **d}], "cached": cached}
        return {
            "ok": False,
            "target": target,
            "error": res.get("error") or "no HTTP response",
            "data": [],
            "cached": False,
        }

    def portscan(self, target: str, ports: str = "") -> dict:
        """Port scan target with nmap."""
        self._track(target)
        res = self.run_tool("nmap_scan", {"target": target, "ports": ports})
        if not res["ok"]:
            return {"ok": False, "target": target, "error": res.get("error") or "scan failed", "hosts": []}
        hosts = T.parse_output("nmap_xml", res["stdout"])
        for h in hosts:
            for p in h["ports"]:
                sev = "low" if p["service"] in ("http", "https") else "info"
                evidence = " ".join(x for x in (p.get("product"), p.get("version")) if x)
                self.add(
                    Finding(
                        tool="nmap",
                        target=h["addr"],
                        title=f"open {p['proto']}/{p['port']} - {p['service'] or 'unknown'}",
                        severity=sev,
                        evidence=evidence,
                    )
                )
        return {
            "ok": bool(hosts),
            "target": target,
            "hosts": hosts,
            "cached": res.get("cached", False),
        }

    def webscan(self, target: str) -> dict:
        """Web vulnerability scan on target."""
        probe = self.probe(target)
        tech = " ".join(probe["data"][0].get("tech") or []) if probe.get("data") else ""
        jobs = {}
        if T.which("nuclei"):
            jobs["nuclei"] = lambda: self.run_tool("nuclei_scan", {"target": target})
        if T.which("wpscan") and "WordPress" in tech:
            jobs["wpscan"] = lambda: self.run_tool("wpscan_scan", {"url": target})
        if T.which("dalfox"):
            jobs["dalfox"] = lambda: self.run_tool("dalfox_xss", {"url": target})
        results = self.parallel(jobs)
        for name, res in results.items():
            if name == "nuclei" and res["ok"] and res["stdout"]:
                for n in T.parse_output("nuclei", res["stdout"]):
                    self.add(
                        Finding(
                            tool="nuclei",
                            target=n["matched"] or target,
                            title=n["name"] or n["template"],
                            severity=n["severity"] or "info",
                            evidence=n["description"],
                        )
                    )
        return {"ok": True, "target": target, "tech": tech, "tools_run": sorted(results)}

    def recon(self, domain: str) -> dict:
        """Domain reconnaissance via whois, DNS, subfinder, amass."""
        jobs = {}
        if T.which("whois"):
            jobs["whois"] = lambda: self.run_tool("whois_lookup", {"query": domain})
        if T.which("dig"):
            jobs["dns"] = lambda: self.run_tool("dns_lookup", {"domain": domain, "type": "ANY"})
        if T.which("subfinder"):
            jobs["subfinder"] = lambda: self.run_tool("subfinder_enum", {"domain": domain})
        if T.which("amass"):
            jobs["amass"] = lambda: self.run_tool("amass_enum", {"domain": domain})
        results = self.parallel(jobs)
        subs = set()
        for name in ("subfinder", "amass"):
            if results.get(name, {}).get("ok"):
                subs.update(l.strip() for l in results[name]["stdout"].splitlines() if l.strip())
        for s in sorted(subs):
            self.add(Finding(tool="recon", target=domain, title=f"subdomain: {s}", severity="info"))
        return {"ok": True, "domain": domain, "tools_run": sorted(results), "subdomains": sorted(subs)}

    def assess(self, target: str) -> dict:
        """Full assessment: probe, portscan, webscan, correlate."""
        target = target.rstrip("/")
        netloc = target.split("//")[-1].split("/")[0]
        host, explicit_port = netloc, ""
        if ":" in host:
            cand_host, _, cand_port = host.rpartition(":")
            if cand_port.isdigit():
                host, explicit_port = cand_host, cand_port

        ctx = WorkflowContext(target)
        out = {"ok": True, "target": target}

        probe = self.probe(target)
        ctx.set_phase("probe", probe)
        out["probe"] = probe

        portscan = self.portscan(host, explicit_port)
        ctx.set_phase("portscan", portscan)
        out["portscan"] = portscan

        http_open = any(
            p["service"] in ("http", "https")
            for h in portscan.get("hosts", [])
            for p in h.get("ports", [])
        )
        if probe.get("ok") or http_open:
            webscan = self.webscan(target)
            ctx.set_phase("webscan", webscan)
            out["webscan"] = webscan

        if "?" in target and probe.get("ok"):
            self.add(
                Finding(
                    tool="sqlmap",
                    target=target,
                    title="query parameter present - manual sqlmap check advised",
                    severity="info",
                    evidence="auto-injection testing skipped to limit noise; run sqlmap_scan directly",
                )
            )

        self.workflow_contexts[target] = ctx
        out["summary"] = self.summary()
        return out

    def summary(self) -> dict:
        """Summary of findings by severity."""
        by_sev = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {"total": len(self.findings), "by_severity": by_sev}

    def report(self, fmt: str = "markdown") -> str:
        """Generate report in markdown or JSON."""
        fs = sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
        if fmt == "json":
            return json.dumps({"findings": [f.to_dict() for f in fs]}, indent=2)
        lines = ["# nexhunter Assessment Report", ""]
        if not fs:
            lines.append("No findings recorded.")
        else:
            for f in fs:
                lines.append(f"- **{f.severity.upper()}** [{f.tool}] {f.title}")
                if f.evidence:
                    lines.append(f"  evidence: {f.evidence}")
        return "\n".join(lines)

    def clear(self):
        """Clear findings and state."""
        self.findings.clear()
        self._finding_sigs.clear()
        self.workflow_contexts.clear()
