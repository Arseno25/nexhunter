"""MCP profiles: which tools a given AI client is shown.

Exposing all 300-odd registered tools to every client is what makes an MCP
integration expensive and error-prone -- a large initialization payload, a
large token cost on every session, and a model choosing between near-identical
tools it has no basis to pick between. A profile narrows that to one job.

Profiles are a usability and blast-radius control, not a security control. Every
execution goes through the same typed validation and execution path regardless
of which profile surfaced the tool; hiding a tool is not the same as
forbidding it.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from nexhunter.core import tools as T

# Risk levels a profile will surface. Destructive tools are never listed by
# any profile; reaching them takes an explicit, separately configured setup.
DEFAULT_RISK_LEVELS = ("passive", "active")


@dataclass(frozen=True)
class Profile:
    """A named subset of the tool registry."""

    name: str
    description: str
    categories: tuple
    risk_levels: tuple = DEFAULT_RISK_LEVELS
    maturities: tuple = ("stable", "beta")
    # Workflow-level MCP tools (assess, recon, findings...) this profile keeps.
    include_workflow_tools: bool = True

    def accepts(self, spec: "T.ToolSpec") -> bool:
        """True when a tool belongs in this profile."""
        if self.categories and spec.category not in self.categories:
            return False
        if spec.risk_level not in self.risk_levels:
            return False
        if spec.maturity not in self.maturities:
            return False
        return True


PROFILES: Dict[str, Profile] = {
    "nexhunter-core": Profile(
        name="nexhunter-core",
        description="Status, findings, executions, and the safest passive checks. "
                    "The default: smallest payload, lowest chance of an accidental scan.",
        categories=(),
        risk_levels=("passive",),
        maturities=("stable",),
    ),
    "nexhunter-recon": Profile(
        name="nexhunter-recon",
        description="Host discovery, DNS, subdomain enumeration, and service identification.",
        categories=("recon",),
    ),
    "nexhunter-web": Profile(
        name="nexhunter-web",
        description="Web application security: content discovery, template scanning, "
                    "injection testing, technology identification, TLS checks. "
                    "Intrusive scanners (sqlmap, ffuf, nikto) included - the autonomy "
                    "ceiling still clamps them in autonomous runs.",
        categories=("web",),
        risk_levels=("passive", "active", "intrusive"),
    ),
    "nexhunter-api": Profile(
        name="nexhunter-api",
        description="API surface testing: schema discovery, parameter discovery, GraphQL.",
        categories=("api",),
        risk_levels=("passive", "active", "intrusive"),
    ),
    "nexhunter-code": Profile(
        name="nexhunter-code",
        description="Static analysis, secret scanning, and dependency review of source code.",
        categories=("code",),
    ),
    "nexhunter-cloud": Profile(
        name="nexhunter-cloud",
        description="Read-only cloud posture review. No mutating cloud actions are registered.",
        categories=("cloud",),
        risk_levels=("passive",),
    ),
    "nexhunter-container": Profile(
        name="nexhunter-container",
        description="Container and Kubernetes image and configuration review.",
        categories=("container",),
    ),
    "nexhunter-forensics": Profile(
        name="nexhunter-forensics",
        description="Offline artifact and binary analysis. Operates on files, not live targets.",
        categories=("forensics", "binary"),
    ),
    "nexhunter-osint": Profile(
        name="nexhunter-osint",
        description="Open-source intelligence: usernames, emails, services, CVE lookup. "
                    "Includes active footprinting tools (maltego, spiderfoot).",
        categories=("osint",),
    ),
    "nexhunter-wireless": Profile(
        name="nexhunter-wireless",
        description="Wireless reconnaissance and assessment. Intrusive attacks included; "
                    "destructive tooling (mdk4) is withheld.",
        categories=("wireless",),
        risk_levels=("passive", "active", "intrusive"),
    ),
    "nexhunter-privesc": Profile(
        name="nexhunter-privesc",
        description="Local privilege escalation discovery: suggesters and privilege audit scripts.",
        categories=("privesc",),
    ),
    "nexhunter-payloads": Profile(
        name="nexhunter-payloads",
        description="Payload generation and C2 framework integration. Intrusive tools "
                    "(mimikatz, hoaxshell, msfvenom) included; never auto-executed in "
                    "autonomous runs.",
        categories=("payloads",),
        risk_levels=("passive", "active", "intrusive"),
    ),
    "nexhunter-vulnscan": Profile(
        name="nexhunter-vulnscan",
        description="Vulnerability scanners and network IDS tooling.",
        categories=("vuln_scan", "ids"),
    ),
    "nexhunter-mobile": Profile(
        name="nexhunter-mobile",
        description="Mobile application analysis: APK inspection, decompilation, "
                    "runtime exploration.",
        categories=("mobile",),
    ),
    "nexhunter-ctf": Profile(
        name="nexhunter-ctf",
        description="Capture-the-flag one-stop profile: Web Exploitation (web, api), "
                    "Cryptography (crypto), Reverse Engineering & Pwn (binary), "
                    "Forensics (forensics), and OSINT (osint). Intrusive web scanners "
                    "included; the autonomy ceiling still clamps them.",
        categories=("ctf", "crypto", "binary", "forensics", "osint", "web", "api"),
        risk_levels=("passive", "active", "intrusive"),
    ),
    "nexhunter-full": Profile(
        name="nexhunter-full",
        description="Every non-destructive registered tool. Large payload; prefer a "
                    "focused profile unless you genuinely need the whole registry.",
        categories=(),
        risk_levels=("passive", "active", "intrusive"),
        maturities=("stable", "beta", "experimental"),
    ),
}

DEFAULT_PROFILE = "nexhunter-core"


def get_profile(name: Optional[str]) -> Profile:
    """Look up a profile by name, falling back to the default."""
    if not name:
        return PROFILES[DEFAULT_PROFILE]
    profile = PROFILES.get(name.strip().lower())
    if profile is None:
        known = ", ".join(sorted(PROFILES))
        raise KeyError(f"unknown MCP profile {name!r}; known profiles: {known}")
    return profile


def tools_for(profile: Profile, registry: Optional[dict] = None) -> Dict[str, "T.ToolSpec"]:
    """Registry tools this profile exposes, keyed by name."""
    source = registry if registry is not None else T.TOOLS
    return {name: spec for name, spec in source.items() if profile.accepts(spec)}


def summarize(registry: Optional[dict] = None) -> List[dict]:
    """Describe every profile and how many tools it exposes."""
    source = registry if registry is not None else T.TOOLS
    summary = []
    for profile in PROFILES.values():
        selected = tools_for(profile, source)
        summary.append({
            "name": profile.name,
            "description": profile.description,
            "categories": list(profile.categories) or ["*"],
            "risk_levels": list(profile.risk_levels),
            "maturities": list(profile.maturities),
            "tool_count": len(selected),
            "available_tool_count": sum(1 for s in selected.values() if s.available),
        })
    return summary


def categories(registry: Optional[dict] = None) -> Dict[str, int]:
    """Tool count per category across the registry."""
    source = registry if registry is not None else T.TOOLS
    counts: Dict[str, int] = {}
    for spec in source.values():
        counts[spec.category] = counts.get(spec.category, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))
