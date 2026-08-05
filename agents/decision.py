"""Planning agents: technology detection, decision engine, optimizer, rate limiting."""

import time

from nexhunter.core import tools as T
from nexhunter.agents.base import Agent


class TechnologyDetector(Agent):
    """Detect web technology stack with confidence scoring."""

    name = "technology"
    desc = "Fingerprint web tech stack with confidence scoring"
    param_schema = {"target": (True, str)}

    def run(self, target: str = ""):
        """Fingerprint technology stack."""
        if not target:
            return self.result(ok=False, error="target required")

        probe = self.ctx.probe(target)
        if not probe.get("ok"):
            return self.result(ok=True, data={"target": target, "reachable": False, "tech": [], "confidence": 0.0})

        data = probe.get("data", [{}])[0]
        tech = list(data.get("tech") or [])
        known = [
            t for t in tech
            if any(k in t.lower() for k in ("wordpress", "drupal", "joomla", "nginx", "apache", "iis", "php", "node", "python", "java", "express", "django", "tomcat"))
        ]
        confidence = round(min(1.0, 0.4 + 0.15 * len(known)) if known else 0.3, 2)

        return self.result(
            ok=True,
            data={"target": target, "reachable": True, "tech": tech, "known_stack": known, "confidence": confidence},
            meta={"detected_count": len(tech), "known_count": len(known)}
        )


class IntelligentDecisionEngine(Agent):
    """Tool selection and attack planning."""

    name = "decision"
    desc = "Tool selection + ordered attack plan for a target"
    param_schema = {"target": (True, str), "intent": (False, str)}

    def run(self, target: str = "", intent: str = "auto"):
        """Plan tool execution order and phase sequence."""
        if not target:
            return self.result(ok=False, error="target required")

        available = {n for n, s in T.TOOLS.items() if T.which(s.binary)}
        plan = {
            "recon": ["whois_lookup", "dns_lookup", "subfinder_enum", "amass_enum"],
            "web": ["httpx_probe", "nuclei_scan", "ffuf_scan", "gobuster_dir", "dalfox_xss"],
            "network": ["nmap_scan", "nikto_scan"],
        }
        order = list(plan.get(intent, ["nmap_scan", "httpx_probe", "nuclei_scan"]))

        tech = ""
        if target:
            probe = self.ctx.probe(target)
            if probe.get("ok"):
                tech = " ".join(probe.get("data", [{}])[0].get("tech") or [])

        if "WordPress" in tech:
            order.append("wpscan_scan")
        if "?" in target:
            order.append("sqlmap_scan")

        return self.result(
            ok=True,
            data={
                "target": target,
                "intent": intent,
                "phase_order": ["recon", "probe", "scan", "explore", "correlate", "report"],
                "recommended_tools": [t for t in order if t in available],
                "missing_for_plan": [t for t in order if t not in available],
            },
            meta={"available_tools": len(available), "planned_tools": len(order)}
        )


class ParameterOptimizer(Agent):
    """Context-aware tool parameter recommendations."""

    name = "optimizer"
    desc = "Context-aware recommended parameters for a tool"
    param_schema = {"tool": (True, str), "context": (False, str)}

    def run(self, tool: str = "", context: str = ""):
        """Recommend parameters for tool."""
        if not tool:
            return self.result(ok=False, error="tool required")

        spec = T.get_tool_spec(tool)
        if not spec:
            return self.result(ok=False, error=f"unknown tool: {tool}")

        params = {k: (v if v is not None else "") for k, v in spec.params.items()}

        if tool == "nmap_scan" and ":" in context:
            params["ports"] = context.split(":")[-1].split("/")[0]
        if tool in ("ffuf_scan", "gobuster_dir") and not params.get("wordlist"):
            params["wordlist"] = "/usr/share/wordlists/dirb/common.txt"

        return self.result(
            ok=True,
            data={
                "tool": tool,
                "binary": spec.binary,
                "params": params,
                "timeout": spec.timeout,
                "notes": "fastest reliable defaults; tune after first run",
            }
        )


class RateLimitDetector(Agent):
    """Detect and advise on request rate limiting."""

    name = "rate_limit"
    desc = "Detect request pace per host and advise throttling"
    param_schema = {"target": (True, str)}

    def run(self, target: str = ""):
        """Check rate limit state and advise."""
        if not target:
            return self.result(ok=False, error="target required")

        host = target.split("//")[-1].split("/")[0] if target else ""
        stamps = self.ctx._host_requests.get(host, []) if host else []
        now = time.time()
        rate = len([t for t in stamps if now - t < 60])
        state = "ok" if rate < 50 else ("warn" if rate < 100 else "hot")
        advice = {
            "ok": "proceed",
            "warn": "reduce rate; add 2-5s delays",
            "hot": "stop; target may rate-limit or block you",
        }[state]

        return self.result(
            ok=True,
            data={"host": host or "n/a", "requests_last_60s": rate, "state": state, "advice": advice},
            meta={"total_tracked_requests": len(stamps)}
        )
