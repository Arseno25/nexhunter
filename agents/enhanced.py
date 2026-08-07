"""Enhanced security agents - OSINT, threat analysis, bug bounty.

These agents execute registered tools through the Engine and analyze the
real results (tool stdout, engine.findings). Nothing is simulated or
fabricated: every subdomain, finding, and IOC traces back to tool output or
to findings the engine recorded. Agents with nothing to report say so.
"""

import json
import re
from typing import Any
from urllib.parse import urlparse

from nexhunter.agents.base import Agent
from nexhunter.api.security_features import (
    OsintCollector,
    VulnerabilityAnalyzer,
    BugBountyAssessment,
    CTFChallengeAnalyzer,
    ThreatIntelligence,
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)

# ATT&CK mapping per tool, used only to label tools that actually ran.
_TOOL_TTPS = {
    "nmap": ("T1595", "Active Scanning", "Discovery"),
    "masscan": ("T1595", "Active Scanning", "Discovery"),
    "naabu": ("T1595", "Active Scanning", "Discovery"),
    "httpx": ("T1595", "Active Scanning", "Discovery"),
    "whatweb": ("T1595", "Active Scanning", "Discovery"),
    "nuclei": ("T1595.002", "Vulnerability Scanning", "Discovery"),
    "nikto": ("T1595.002", "Vulnerability Scanning", "Discovery"),
    "subfinder": ("T1596", "Search Open Technical Databases", "Discovery"),
    "amass": ("T1596", "Search Open Technical Databases", "Discovery"),
    "crt_sh": ("T1596", "Search Open Technical Databases", "Discovery"),
    "recon": ("T1596", "Search Open Technical Databases", "Discovery"),
    "sqlmap": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "dalfox": ("T1190", "Exploit Public-Facing Application", "Initial Access"),
}


def _hostname(target: str) -> str:
    """Bare host from a URL, host:port, or plain host."""
    text = (target or "").strip()
    if "://" in text:
        host = urlparse(text).hostname
        if host:
            return host
    return urlparse(f"//{text}").hostname or text.split("/")[0].split(":")[0]


def _finding_cwe(finding) -> str:
    """Best-effort CWE id found in a real finding's text."""
    blob = f"{finding.title} {finding.evidence or ''}"
    match = _CWE_RE.search(blob)
    return match.group(0).upper() if match else ""


class OsintAgent(Agent):
    """OSINT intelligence gathering from live recon tool output."""

    name = "osint"
    desc = "Open-source intelligence gathering"

    def __init__(self, ctx=None):
        super().__init__(ctx or None)
        self.collector = OsintCollector()

    def execute(self, engine, params: dict[str, Any]) -> dict:
        """Collect real subdomains, emails, DNS records, and whois data."""
        target = params.get("target", "")
        if not target:
            return self.result(False, error="Target required")
        if engine is None:
            return self.result(False, error="engine required")
        domain = _hostname(target)

        tools_run: list[str] = []

        recon = engine.recon(domain)
        tools_run += sorted(recon.get("tools_run", []))
        for sub in sorted(recon.get("subdomains", [])):
            self.collector.add_subdomain(sub, "", "discovered")

        whois = engine.run_tool("whois_lookup", {"query": domain})
        if whois.get("ok") and whois.get("stdout"):
            tools_run.append("whois_lookup")
            self.collector.data["whois_info"] = {"raw": whois["stdout"][:4000]}
        else:
            self.collector.data["whois_info"] = {"raw": ""}

        dns = engine.run_tool("dns_lookup", {"domain": domain, "type": "ANY"})
        if dns.get("ok") and dns.get("stdout"):
            tools_run.append("dns_lookup")
            for line in dns["stdout"].splitlines():
                match = re.search(r"\sIN\s+(A|AAAA|MX|NS|CNAME|TXT)\s+(.+)$", line)
                if match:
                    self.collector.add_dns_record(match.group(1), match.group(2).strip())

        mail = engine.run_tool("theharvester_recon", {"domain": domain})
        if mail.get("ok"):
            tools_run.append("theharvester_recon")
            blob = f"{mail.get('stdout', '')}\n{mail.get('stderr', '')}"
            for email in sorted(set(_EMAIL_RE.findall(blob))):
                self.collector.add_email(email, "theHarvester")

        certs = engine.run_tool("crt_sh", {"domain": domain})
        if certs.get("ok") and certs.get("stdout"):
            tools_run.append("crt_sh")
            try:
                payload = json.loads(certs["stdout"])
                for entry in payload[:50]:
                    for name in str(entry.get("name_value", "")).splitlines():
                        if name.strip():
                            self.collector.data["ssl_certs"].append(
                                {"domain": name.strip(), "source": "crt.sh"}
                            )
            except (ValueError, TypeError):
                pass

        summary = self.collector.summary()
        meta = {"collection_method": "passive", "tools_run": tools_run}
        if not any(summary.values()) and not tools_run:
            meta["note"] = ("no recon binary installed "
                            "(subfinder, amass, whois, dig, theHarvester)")
        return self.result(
            True,
            data={
                "target": target,
                "intelligence": self.collector.to_dict(),
                "summary": summary,
            },
            meta=meta,
        )


class VulnerabilityAnalysisAgent(Agent):
    """Analyze engine findings: real vulns, chains, threat score."""

    name = "vuln_analyzer"
    desc = "Vulnerability analysis and attack path detection"

    def __init__(self, ctx=None):
        super().__init__(ctx or None)
        self.analyzer = VulnerabilityAnalyzer()

    def execute(self, engine, params: dict[str, Any]) -> dict:
        """Analyze the findings the engine has actually recorded."""
        target = params.get("target", "")
        if not target:
            return self.result(False, error="Target required")
        if engine is None:
            return self.result(False, error="engine required")

        findings = list(engine.findings)
        if not findings:
            return self.result(
                True,
                data={
                    "target": target,
                    "vulnerabilities": [],
                    "attack_chains": [],
                    "threat_level": {
                        "level": "info", "score": 0, "factors": [], "remediation": [],
                    },
                },
                meta={
                    "analysis_type": "correlation", "chains_detected": 0,
                    "note": "no findings recorded; run an assessment first (e.g. /api/assess)",
                },
            )

        for finding in findings:
            self.analyzer.add_vulnerability(
                finding.title,
                _finding_cwe(finding) or "CWE-unknown",
                0.0,
                finding.severity or "info",
                finding.evidence or "",
                finding.target,
            )

        chains = self.analyzer.detect_chains()
        threat = self.analyzer.threat_score()
        return self.result(
            True,
            data={
                "target": target,
                "vulnerabilities": self.analyzer.vulns,
                "attack_chains": chains,
                "threat_level": {
                    "level": threat.level,
                    "score": threat.score,
                    "factors": threat.factors,
                    "remediation": threat.remediation,
                },
            },
            meta={"analysis_type": "correlation", "chains_detected": len(chains)},
        )


class BugBountyAgent(Agent):
    """Bug bounty assessment driven by real engine executions."""

    name = "bugbounty_pro"
    desc = "Professional bug bounty assessment"

    def __init__(self, ctx=None):
        super().__init__(ctx or None)
        self.assessment = None

    def execute(self, engine, params: dict[str, Any]) -> dict:
        """Run the assessment phases that have registered tools; skip the rest."""
        target = params.get("target", "")
        scope = params.get("scope", {})
        if not target:
            return self.result(False, error="Target required")
        if engine is None:
            return self.result(False, error="engine required")
        host = _hostname(target)

        self.assessment = BugBountyAssessment(target)
        self.assessment.set_scope(
            scope.get("in_scope", [target]),
            scope.get("out_of_scope", []),
        )

        runs = {
            "recon": lambda: engine.recon(host),
            "subdomain_enum": lambda: engine.run_tool(
                "subfinder_enum", {"domain": host}
            ),
            "port_scan": lambda: engine.portscan(host),
            "web_scan": lambda: engine.webscan(target),
        }

        completed: list[str] = []
        for phase, run in runs.items():
            before = len(engine.findings)
            self.assessment.start_phase(phase)
            result = run()
            delta = len(engine.findings) - before
            if result.get("ok"):
                self.assessment.complete_phase(phase, delta)
                completed.append(phase)
            else:
                self.assessment.phases[phase]["status"] = "failed"
                self.assessment.phases[phase]["error"] = (
                    result.get("error") or "run failed"
                )

        for phase in ("api_test", "auth_test", "business_logic"):
            self.assessment.phases[phase]["status"] = "skipped"
            self.assessment.phases[phase]["note"] = (
                "no registered tool for this phase; test manually"
            )

        total_findings = sum(
            p.get("findings", 0)
            for p in self.assessment.phases.values()
            if p.get("status") == "completed"
        )
        return self.result(
            True,
            data={
                "target": target,
                "assessment": self.assessment.to_dict(),
                "priority_areas": self.assessment.get_priority_findings(),
            },
            meta={
                "phases_completed": len(completed),
                "total_findings": total_findings,
            },
        )


class CTFSolverAgent(Agent):
    """CTF challenge guidance: tool recommendations filtered by what is installed."""

    name = "ctf_solver"
    desc = "CTF challenge analyzer and solver"

    def __init__(self, ctx=None):
        super().__init__(ctx or None)

    def execute(self, engine, params: dict[str, Any]) -> dict:
        """Recommend installed tools and generic hints for the challenge type."""
        from nexhunter.core import tools as T

        challenge_type = params.get("type", "web")
        challenge_name = params.get("name", "Unknown")
        analyzer = CTFChallengeAnalyzer(challenge_type)

        hints_map = {
            "web": ["Check for SQL injection", "Inspect network requests", "Look for hardcoded credentials"],
            "crypto": ["Analyze hash algorithm", "Check for weak encryption", "Look for key reuse"],
            "forensics": ["Extract metadata", "Check file signatures", "Look for hidden files"],
            "pwn": ["Analyze binary", "Check protections", "Look for buffer overflow"],
            "recon": ["Enumerate services", "Check SSL certificates", "Scan for subdomains"],
        }
        for hint in hints_map.get(challenge_type, []):
            analyzer.add_hint(hint)

        installed: list[str] = []
        missing: list[str] = []
        for name in analyzer.get_recommended_tools():
            spec = T.get_tool_spec(name)
            (installed if (spec and spec.available) else missing).append(name)
        analyzer.tools[challenge_type] = installed

        return self.result(
            True,
            data={
                "challenge": challenge_name,
                "analysis": analyzer.to_dict(),
            },
            meta={
                "type": challenge_type,
                "recommended_tools_installed": len(installed),
                "recommended_tools_missing": len(missing),
            },
        )


class ThreatIntelAgent(Agent):
    """Threat intelligence derived from findings the engine recorded."""

    name = "threat_intel"
    desc = "Threat intelligence and risk assessment"

    def __init__(self, ctx=None):
        super().__init__(ctx or None)
        self.intel = ThreatIntelligence()

    def execute(self, engine, params: dict[str, Any]) -> dict:
        """Extract real IOCs, TTPs, and MITRE techniques from engine findings."""
        target = params.get("target", "")
        if not target:
            return self.result(False, error="Target required")
        if engine is None:
            return self.result(False, error="engine required")

        findings = list(engine.findings)
        if not findings:
            return self.result(
                True,
                data={
                    "target": target,
                    "threat_intelligence": self.intel.to_dict(),
                },
                meta={
                    "ioc_count": 0, "ttp_count": 0, "mitre_techniques": 0,
                    "note": "no findings recorded; run an assessment first",
                },
            )

        ips: set[str] = set()
        cves: set[str] = set()
        hosts: set[str] = set()
        tool_severity: dict[str, str] = {}
        for finding in findings:
            blob = f"{finding.title} {finding.evidence or ''} {finding.target}"
            ips.update(_IP_RE.findall(blob))
            cves.update(match.upper() for match in _CVE_RE.findall(blob))
            if finding.target:
                hosts.add(_hostname(finding.target) or finding.target)
            tool = finding.tool or "unknown"
            tool_severity.setdefault(tool, finding.severity or "info")

        for ip in sorted(ips):
            self.intel.add_ioc("IP", ip, "assessment findings")
        for cve in sorted(cves):
            self.intel.add_ioc("CVE", cve, "assessment findings")
        for host in sorted(hosts):
            self.intel.add_ioc("HOST", host, "assessment findings")

        for tool in sorted(tool_severity):
            mapping = _TOOL_TTPS.get(tool)
            if mapping:
                technique_id, technique_name, tactic = mapping
                self.intel.add_ttp(tactic, technique_name)
                self.intel.add_mitre_technique(
                    technique_id, technique_name, tool_severity[tool]
                )

        return self.result(
            True,
            data={
                "target": target,
                "threat_intelligence": self.intel.to_dict(),
            },
            meta={
                "ioc_count": len(self.intel.indicators["iocs"]),
                "ttp_count": len(self.intel.indicators["ttps"]),
                "mitre_techniques": len(self.intel.indicators["mitre_techniques"]),
            },
        )


# Register enhanced agents
ENHANCED_AGENTS = {
    "osint": OsintAgent(),
    "vuln_analyzer": VulnerabilityAnalysisAgent(),
    "bugbounty_pro": BugBountyAgent(),
    "ctf_solver": CTFSolverAgent(),
    "threat_intel": ThreatIntelAgent(),
}
