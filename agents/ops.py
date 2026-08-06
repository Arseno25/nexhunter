"""Ops agents: recovery, performance monitoring, degradation, correlation."""

from nexhunter.core import tools as T
from nexhunter.execution.recovery import ExecutionRecovery
from nexhunter.agents.base import Agent

FALLBACKS = {
    "gobuster_dir": "ffuf_scan",
    "dalfox_xss": "nuclei_scan",
    "httpx_probe": "curl_headers",
    "nikto_scan": "nuclei_scan",
}


class FailureRecoverySystem(Agent):
    """Automatic fallback when tool execution fails."""

    name = "recovery"
    desc = "Classify failure and retry: backoff, reduced scope, or an equivalent binary"
    param_schema = {
        "tool": (True, str),
        "params": (False, dict),
        "max_attempts": (False, int),
    }

    def run(self, tool: str = "", params: dict = None,
            max_attempts: int = 3):
        """Run tool with a recovery loop, then report the recovery trail."""
        params = params or {}
        recovery = ExecutionRecovery(
            run_fn=lambda t, p: self.ctx.run_tool(t, p),
            max_attempts=int(max_attempts or 3),
            use_backoff=False,  # agents run in-process; never sleep the server
        )
        res = recovery.execute(tool, params, direct=False)
        applied = [
            {
                "attempt": e.get("attempt"),
                "action": e.get("action", e.get("outcome")),
                "tool": e.get("tool"),
                "switched_to": e.get("switched_to"),
            }
            for e in res.get("recovery", {}).get("trail", [])
        ]
        if not applied:
            applied.append("no recoveries needed")

        return self.result(
            ok=res.get("ok", False),
            data={
                "tool": tool,
                "recoveries": applied,
                "result": {
                    "ok": res.get("ok"),
                    "error": res.get("error"),
                    "stdout": (res.get("stdout") or res.get("output") or "")[:2000],
                }
            }
        )


class PerformanceMonitor(Agent):
    """Tool execution timing and cache statistics."""

    name = "performance"
    desc = "Per-tool timing, cache effectiveness, slowest tools"
    param_schema = {}

    def run(self):
        """Analyze performance metrics."""
        stats = {
            t: {"runs": len(v), "avg_s": round(sum(v) / len(v), 2), "total_s": round(sum(v), 1)}
            for t, v in self.ctx._tool_stats.items()
        }
        total = round(sum(sum(v) for v in self.ctx._tool_stats.values()), 1)
        execs = sum(len(v) for v in self.ctx._tool_stats.values())

        return self.result(
            ok=True,
            data={
                "tools": stats,
                "total_tool_time_s": total,
                "cache_hit_rate": round(self.ctx.cache_hits / execs, 3) if execs else 0,
                "slowest": sorted(stats, key=lambda t: stats[t]["avg_s"], reverse=True)[:3],
            },
            meta={"total_executions": execs, "cache_evictions": self.ctx.cache_evictions}
        )


class GracefulDegradation(Agent):
    """Check installed tools and degradation mode."""

    name = "degradation"
    desc = "Capability matrix: what works with installed binaries, degraded mode status"
    param_schema = {}

    def run(self):
        """Check tool availability and report degradation mode."""
        available = {n: s.binary for n, s in T.TOOLS.items() if T.which(s.binary)}
        missing = {n: s.binary for n, s in T.TOOLS.items() if not T.which(s.binary)}
        mode = "full" if len(missing) < 4 else "degraded"

        return self.result(
            ok=True,
            data={
                "mode": mode,
                "tools_ready": len(available),
                "available": available,
                "missing": missing,
                "recommended_installs": sorted(set(missing.values()))[:10],
            },
            meta={"coverage": round(len(available) / (len(available) + len(missing)) * 100, 1) if available or missing else 0}
        )


class VulnerabilityCorrelator(Agent):
    """Correlate findings into attack chains."""

    name = "correlator"
    desc = "Chain recorded findings into attack paths"
    param_schema = {}

    def run(self):
        """Correlate findings and build attack chains."""
        fs = self.ctx.findings
        chains = []

        web = [f for f in fs if f.tool == "nmap" and (f.title.split("-")[-1].strip() in ("http", "https"))]
        if web:
            chains.append({
                "name": "web attack surface",
                "steps": ["nmap: " + ", ".join(f.title for f in web), "tech detect via probe", "nuclei template scan", "manual review"],
                "risk": "medium",
            })

        cves = [f for f in fs if f.tool == "cve"]
        if cves:
            chains.append({"name": "known-CVE exploitation", "steps": [f"{f.title} ({f.severity})" for f in cves], "risk": "high"})

        sqli = [f for f in fs if f.tool == "sqlmap"]
        if sqli:
            chains.append({"name": "injection testing", "steps": [f.title for f in sqli], "risk": "medium"})

        return self.result(
            ok=True,
            data={
                "chains": chains or [{"name": "none yet", "steps": ["run assess() first"], "risk": "info"}],
                "total_findings": len(fs),
            },
            meta={"findings_by_tool": len(set(f.tool for f in fs))}
        )
