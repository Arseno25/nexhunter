"""Workflow agents: bug bounty assessment, CTF challenge solving."""

from nexhunter.core import tools as T
from nexhunter.agents.base import Agent
from nexhunter.agents.ops import VulnerabilityCorrelator

CTF_TOOLS = {
    "web": ["curl_headers", "httpx_probe", "ffuf_scan", "gobuster_dir", "nuclei_scan"],
    "crypto": ["hashid", "john", "hashcat"],
    "forensics": ["strings", "exiftool", "binwalk", "foremost"],
    "pwn": ["checksec", "strings", "objdump", "gdb"],
    "recon": ["nmap_scan", "whois_lookup", "dns_lookup"],
}

CTF_HINTS = {
    "web": "check source, robots.txt, params, cookies",
    "crypto": "identify hash type, then crack (hashcat/john)",
    "forensics": "strings first, then binwalk/exiftool for hidden data",
    "pwn": "checksec for mitigations, then overflow/format-string",
    "recon": "ports/services first, then hidden content",
}


class BugBountyWorkflowManager(Agent):
    """Phased bug bounty assessment workflow."""

    name = "bugbounty"
    desc = "Phased flow: recon -> probe -> scan -> explore -> correlate -> report"
    param_schema = {"target": (True, str), "phases": (False, str)}

    def run(self, target: str = "", phases: str = "all"):
        """Run bug bounty assessment phases."""
        if not target:
            return self.result(ok=False, error="target required")

        want = set(phases.split(",")) if phases != "all" else None
        target = target.rstrip("/")
        netloc = target.split("//")[-1].split("/")[0]
        host, explicit_port = netloc, ""
        if ":" in host:
            cand_host, _, cand_port = host.rpartition(":")
            if cand_port.isdigit():
                host, explicit_port = cand_host, cand_port

        results, skipped = {}, []
        probe_ok = False

        def maybe(name, fn):
            if want is not None and name not in want:
                skipped.append(name)
                return
            try:
                results[name] = fn()
            except Exception as e:
                results[name] = {"ok": False, "error": str(e)}

        maybe("recon", lambda: self.ctx.recon(host))
        maybe("probe", lambda: self.ctx.probe(target))
        probe_ok = results.get("probe", {}).get("ok", False)
        maybe("scan", lambda: self.ctx.portscan(host, explicit_port))

        http_open = any(
            p["service"] in ("http", "https")
            for h in results.get("scan", {}).get("hosts", [])
            for p in h.get("ports", [])
        )
        if (probe_ok or http_open) and (want is None or "explore" in want):
            results["explore"] = self.ctx.webscan(target)
        elif want is None or "explore" in want:
            skipped.append("explore (no web service detected)")

        maybe("correlate", lambda: VulnerabilityCorrelator(self.ctx).run())
        maybe("report", lambda: self.ctx.report())

        return self.result(
            ok=True,
            data={
                "target": target,
                "phases_completed": sorted(results),
                "skipped": skipped,
                "summary": self.ctx.summary(),
                "report": results.get("report", ""),
            },
            meta={"total_findings": self.ctx.summary().get("total", 0)}
        )


class CTFWorkflowManager(Agent):
    """CTF challenge solving with category-specific toolchain."""

    name = "ctf"
    desc = "CTF challenge toolchain per category (web/crypto/forensics/pwn/recon)"

    param_schema = {"target": (True, str), "category": (False, str), "file": (False, str)}

    def run(self, target: str = "", category: str = "web", file: str = ""):
        """Solve CTF challenge using category-specific toolchain."""
        if not target:
            return self.result(ok=False, error="target required")

        plan = CTF_TOOLS.get(category, CTF_TOOLS["web"])
        results = {}
        tools_missing = []

        for tool in plan:
            spec = T.get_tool_spec(tool)
            if not spec or not T.which(spec.binary):
                tools_missing.append(tool)
                continue

            params = {
                k: (target if k in ("target", "hash") else (file if k == "file" else (v if v is not None else "")))
                for k, v in spec.params.items()
            }
            results[tool] = self.ctx.run_tool(tool, params)

        return self.result(
            ok=True,
            data={
                "category": category,
                "target": target,
                "file": file,
                "tools_run": sorted(results),
                "tools_missing": tools_missing,
                "hint": CTF_HINTS.get(category, ""),
            },
            meta={"available_tools": len(results), "missing_tools": len(tools_missing)}
        )
