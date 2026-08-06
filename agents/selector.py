"""Intelligent tool selection -- rank and cap the registry per target.

The registry holds 268 tools across 20 categories. Running all of them is both
wasteful and reckless. This module is the "only the necessary tools" layer: it
scores every tool against a target profile, an objective, and a risk ceiling,
then returns a small, ranked shortlist plus the reasons behind each pick.

Scoring is heuristic on purpose -- derived from the metadata each tool already
carries (category, risk_level, maturity, installed-or-not) plus light evidence
gates and a handful of per-tool quality nudges. That scales to every category
without a hand-maintained effectiveness table, and it stays deterministic: the
same profile yields the same ranking, so a plan is reproducible and reviewable.

This does not run anything and it does not replace the methodology planner in
`workflows.orchestrator`. It is the shortlist an operator (or an LLM) reviews
before deciding which subset to actually execute.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from nexhunter.core import tools as T
from nexhunter.core.risk import RiskLevel
from nexhunter.agents.profiler import TargetProfile


# Category relevance per target type (0..1). A category absent from a target's
# map is treated as irrelevant -- e.g. forensics tooling never surfaces for a
# plain web application. `unknown` is the permissive fallback used before any
# evidence has narrowed the target down.
TARGET_TYPE_CATEGORIES: dict[str, dict[str, float]] = {
    "web_application": {
        "web": 1.0, "vuln_scan": 0.9, "api": 0.8, "recon": 0.55,
        "crypto": 0.5, "exploitation": 0.4, "payloads": 0.3, "osint": 0.3,
    },
    "domain": {
        "recon": 1.0, "osint": 0.85, "web": 0.6, "network": 0.45,
        "vuln_scan": 0.4, "crypto": 0.35,
    },
    "host": {
        "network": 1.0, "recon": 0.85, "vuln_scan": 0.6, "exploitation": 0.45,
        "privesc": 0.35, "crypto": 0.3,
    },
    "network": {
        "network": 1.0, "recon": 0.9, "vuln_scan": 0.5, "exploitation": 0.35,
    },
    "binary": {
        "binary": 1.0, "ctf": 0.75, "utility": 0.6, "crypto": 0.55,
        "code": 0.5, "forensics": 0.4,
    },
    "mobile": {
        "mobile": 1.0, "code": 0.6, "crypto": 0.45, "binary": 0.4,
    },
    "forensics": {
        "forensics": 1.0, "ids": 0.7, "crypto": 0.5, "utility": 0.45, "binary": 0.4,
    },
    "code": {
        "code": 1.0, "utility": 0.35,
    },
    "cloud": {
        "cloud": 1.0, "container": 0.85, "code": 0.5, "recon": 0.4,
    },
    "wireless": {
        "wireless": 1.0, "network": 0.4,
    },
    "unknown": {
        "recon": 0.8, "web": 0.6, "network": 0.6, "vuln_scan": 0.4, "osint": 0.4,
    },
}

# Category -> the methodology phase it belongs to, so a shortlist can be grouped
# and ordered the way an operator would walk it.
CATEGORY_PHASE: dict[str, str] = {
    "recon": "recon", "osint": "recon", "utility": "recon",
    "network": "enumeration",
    "web": "web_enum", "api": "web_enum",
    "vuln_scan": "assessment", "crypto": "assessment", "code": "assessment",
    "cloud": "assessment", "container": "assessment", "forensics": "assessment",
    "binary": "assessment", "mobile": "assessment", "ctf": "assessment",
    "ids": "assessment",
    "exploitation": "exploitation", "privesc": "exploitation",
    "payloads": "exploitation", "wireless": "exploitation",
}
PHASE_ORDER: list[str] = ["recon", "enumeration", "web_enum", "assessment", "exploitation"]

_RISK_ORDER = {
    RiskLevel.PASSIVE: 0,
    RiskLevel.ACTIVE: 1,
    RiskLevel.INTRUSIVE: 2,
    RiskLevel.DESTRUCTIVE: 3,
}

_MATURITY_WEIGHT = {"stable": 1.0, "beta": 0.8, "experimental": 0.6, "disabled": 0.0}

# A few high-signal tools get a gentle nudge so they float to the top of their
# category. This is the whole "effectiveness table" -- deliberately tiny.
_TOOL_QUALITY = {
    "nuclei_scan": 1.15, "nmap_scan": 1.15, "httpx_probe": 1.10,
    "subfinder_enum": 1.10, "wpscan_scan": 1.10, "sqlmap_scan": 1.10,
    "amass_enum": 1.05, "katana_crawl": 1.05, "ffuf_scan": 1.05,
    "feroxbuster": 1.05, "dalfox_xss": 1.05, "testssl": 1.05,
}

# Tools that only make sense when a specific technology is present. Running
# wpscan on a non-WordPress site is noise; the absence penalty pushes it down.
_TECH_TOOLS = {
    "wpscan_scan": "wordpress",
    "joomscan": "joomla",
    "droopescan": "drupal",
    "drupwn": "drupal",
}

# TLS-review tools: only relevant when an HTTPS surface is in evidence.
_TLS_TOOLS = {"testssl", "sslyze", "sslscan"}


@dataclass
class Objective:
    """Breadth control: how wide a net the selection casts."""
    cap: int
    threshold: float
    passive_only: bool = False


OBJECTIVES: dict[str, Objective] = {
    "quick": Objective(cap=5, threshold=0.50),
    "standard": Objective(cap=12, threshold=0.35),
    "comprehensive": Objective(cap=30, threshold=0.20),
    "stealth": Objective(cap=8, threshold=0.35, passive_only=True),
}


@dataclass
class ScoredTool:
    name: str
    category: str
    risk_level: str
    phase: str
    score: float
    available: bool
    within_ceiling: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool": self.name,
            "category": self.category,
            "risk_level": self.risk_level,
            "phase": self.phase,
            "score": round(self.score, 3),
            "available": self.available,
            "reasons": self.reasons,
        }


@dataclass
class SelectionResult:
    target: str
    objective: str
    risk_ceiling: str
    selected: list[ScoredTool]
    withheld: list[ScoredTool]
    considered: int

    def phases(self) -> dict[str, list[dict]]:
        """Selected tools grouped by phase, in methodology order."""
        grouped: dict[str, list[dict]] = {}
        for st in self.selected:
            grouped.setdefault(st.phase, []).append(st.to_dict())
        return {p: grouped[p] for p in PHASE_ORDER if p in grouped}

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "objective": self.objective,
            "risk_ceiling": self.risk_ceiling,
            "considered": self.considered,
            "selected_count": len(self.selected),
            "phases": self.phases(),
            "selected": [s.to_dict() for s in self.selected],
            "withheld": [
                {**s.to_dict(), "requires": "human approval"} for s in self.withheld
            ],
        }


def _has_tls(profile: TargetProfile) -> bool:
    return 443 in profile.open_ports() or profile.target.startswith("https://")


class ToolSelector:
    """Rank and cap the tool registry for a given target and objective."""

    def _score(
        self, spec, profile: TargetProfile, tech_blob: str
    ) -> tuple | None:
        """Score one tool for this profile. Returns (score, reasons) or None."""
        cats = TARGET_TYPE_CATEGORIES.get(
            profile.target_type, TARGET_TYPE_CATEGORIES["unknown"]
        )
        base = cats.get(spec.category)
        if base is None:
            return None  # category irrelevant to this target type

        reasons = [f"{spec.category} relevant to {profile.target_type} ({base:.2f})"]
        score = base

        # -- evidence gates (soft: penalize, never hard-drop) ----------------
        if spec.category in ("web", "api", "vuln_scan"):
            if profile.has_web_surface():
                reasons.append("web surface in evidence (+)")
            else:
                score *= 0.25
                reasons.append("no web surface observed yet (-)")

        if spec.name in _TLS_TOOLS:
            if _has_tls(profile):
                reasons.append("HTTPS/TLS service present (+)")
            else:
                score *= 0.35
                reasons.append("no TLS evidence (-)")

        # -- technology-specific tools ---------------------------------------
        tech = _TECH_TOOLS.get(spec.name)
        if tech:
            if tech in tech_blob:
                score *= 1.6
                reasons.append(f"{tech} detected in fingerprint (+)")
            else:
                score *= 0.15
                reasons.append(f"{tech} not detected (-)")

        # -- maturity, availability, quality ---------------------------------
        score *= _MATURITY_WEIGHT.get(spec.maturity, 0.7)
        if spec.available:
            reasons.append("binary installed (+)")
        else:
            # Mild penalty only: a not-installed elite tool should still be
            # recommended (flagged below), not buried under mediocre installed
            # ones. Running it later degrades gracefully to a BLOCKED result.
            score *= 0.7
            reasons.append("binary not installed (-)")

        quality = _TOOL_QUALITY.get(spec.name)
        if quality:
            score *= quality

        return score, reasons

    def select(
        self,
        profile: TargetProfile,
        objective: str = "standard",
        ceiling: RiskLevel = RiskLevel.ACTIVE,
        cap: int | None = None,
    ) -> SelectionResult:
        """Rank the registry, cap the picks, and partition withheld tools."""
        obj = OBJECTIVES.get(objective, OBJECTIVES["standard"])
        tech_blob = " ".join(profile.technology_names())
        ceiling_rank = _RISK_ORDER.get(ceiling, 1)

        scored: list[ScoredTool] = []
        for spec in T.TOOLS.values():
            if obj.passive_only and spec.risk_level != "passive":
                continue
            result = self._score(spec, profile, tech_blob)
            if result is None:
                continue
            score, reasons = result
            if score < obj.threshold:
                continue
            risk = RiskLevel(spec.risk_level) if spec.risk_level in RiskLevel._value2member_map_ else RiskLevel.ACTIVE
            scored.append(ScoredTool(
                name=spec.name,
                category=spec.category,
                risk_level=spec.risk_level,
                phase=CATEGORY_PHASE.get(spec.category, "assessment"),
                score=score,
                available=spec.available,
                within_ceiling=_RISK_ORDER.get(risk, 1) <= ceiling_rank,
                reasons=reasons,
            ))

        # Deterministic: highest score first, ties broken by name.
        scored.sort(key=lambda s: (-s.score, s.name))

        within = [s for s in scored if s.within_ceiling]
        withheld = [s for s in scored if not s.within_ceiling]
        selected = within[: (cap if cap is not None else obj.cap)]

        return SelectionResult(
            target=profile.target,
            objective=objective if objective in OBJECTIVES else "standard",
            risk_ceiling=ceiling.value,
            selected=selected,
            withheld=withheld,
            considered=len(T.TOOLS),
        )
