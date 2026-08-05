"""Evidence-based target profiling.

A profile is what has actually been observed about a target, with the source of
each observation attached. It never invents a technology or a vulnerability:
every value carries the tool that produced it, and observed facts are kept
separate from inferences drawn about them. A profile that guessed would be
worse than none, because the next decision is made from it.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Evidence:
    """Where an observation came from."""

    source: str            # the tool that produced it
    execution_id: str = ""
    confidence: float = 0.5  # 0..1, only as high as the evidence justifies
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "execution_id": self.execution_id,
            "confidence": round(self.confidence, 2),
            "detail": self.detail,
        }


@dataclass
class Observation:
    """One evidenced fact, or one clearly-labelled inference."""

    kind: str              # technology | service | address | header | note
    value: str
    evidence: Evidence
    inferred: bool = False  # True => derived, not directly observed

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "value": self.value,
            "inferred": self.inferred,
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class TargetProfile:
    """Accumulated knowledge about one target."""

    target: str
    target_type: str = "unknown"   # web_application | host | network | domain
    resolved_addresses: List[str] = field(default_factory=list)
    technologies: List[Observation] = field(default_factory=list)
    services: List[Observation] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def technology_names(self) -> List[str]:
        return sorted({o.value.lower() for o in self.technologies})

    def open_ports(self) -> List[int]:
        ports = set()
        for service in self.services:
            match = re.search(r"\b(\d{1,5})\b", service.value)
            if match:
                port = int(match.group(1))
                if 1 <= port <= 65535:
                    ports.add(port)
        return sorted(ports)

    def has_web_surface(self) -> bool:
        """True when something HTTP-shaped has been observed."""
        if self.target.startswith(("http://", "https://")):
            return True
        if any(p in self.open_ports() for p in (80, 443, 8080, 8443, 8000)):
            return True
        return bool(self.technologies)

    def recommended_safe_workflows(self) -> List[str]:
        """Passive-first workflow suggestions, grounded in what was observed."""
        recommendations = []
        if self.has_web_surface():
            recommendations.append("web-passive")
        if self.open_ports():
            recommendations.append("recon-active")
        if not recommendations:
            recommendations.append("recon-passive")
        return recommendations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "resolved_addresses": self.resolved_addresses,
            "open_ports": self.open_ports(),
            "technologies": [o.to_dict() for o in self.technologies],
            "services": [o.to_dict() for o in self.services],
            "observations": [o.to_dict() for o in self.observations],
            "recommended_safe_workflows": self.recommended_safe_workflows(),
            "updated_at": self.updated_at.isoformat(),
        }


class Profiler:
    """Fold tool output into a profile, one execution at a time.

    The profiler does not run anything. It consumes results the orchestrator
    already produced through the gate, so profiling can never itself become an
    unscoped scan.
    """

    def new_profile(self, target: str) -> TargetProfile:
        profile = TargetProfile(target=target)
        if target.startswith(("http://", "https://")):
            profile.target_type = "web_application"
        elif self._looks_like_ip(target):
            profile.target_type = "host"
        elif "/" in target:
            profile.target_type = "network"
        else:
            profile.target_type = "domain"
        return profile

    def observe(
        self,
        profile: TargetProfile,
        tool_name: str,
        parsed: Any,
        execution_id: str = "",
    ) -> TargetProfile:
        """Fold one tool's parsed output into the profile."""
        if parsed is None:
            return profile

        handler = getattr(self, f"_from_{self._family(tool_name)}", None)
        if handler:
            handler(profile, tool_name, parsed, execution_id)
        profile.updated_at = datetime.utcnow()
        return profile

    # -- per-tool-family extraction ----------------------------------------

    @staticmethod
    def _family(tool_name: str) -> str:
        name = tool_name.lower()
        if "httpx" in name or "whatweb" in name or "curl" in name:
            return "http"
        if "nmap" in name or "naabu" in name or "masscan" in name:
            return "portscan"
        if "dns" in name or "dig" in name or "host" in name or "nslookup" in name:
            return "dns"
        return "generic"

    def _from_http(self, profile, tool, parsed, execution_id):
        records = parsed if isinstance(parsed, list) else [parsed]
        for record in records:
            if not isinstance(record, dict):
                continue
            for tech in record.get("tech") or []:
                if not tech:
                    continue
                profile.technologies.append(Observation(
                    kind="technology",
                    value=str(tech),
                    evidence=Evidence(tool, execution_id, 0.8, "HTTP fingerprint"),
                ))
            status = record.get("status")
            if status:
                profile.observations.append(Observation(
                    kind="header",
                    value=f"HTTP {status}",
                    evidence=Evidence(tool, execution_id, 0.9),
                ))
            if record.get("title"):
                profile.observations.append(Observation(
                    kind="note",
                    value=f"title: {record['title']}",
                    evidence=Evidence(tool, execution_id, 0.9),
                ))
        if profile.target_type == "unknown":
            profile.target_type = "web_application"

    def _from_portscan(self, profile, tool, parsed, execution_id):
        hosts = parsed.get("hosts") if isinstance(parsed, dict) else parsed
        for host in hosts or []:
            for port in (host.get("ports") if isinstance(host, dict) else None) or []:
                number = port.get("port") if isinstance(port, dict) else port
                service = port.get("service", "") if isinstance(port, dict) else ""
                profile.services.append(Observation(
                    kind="service",
                    value=f"{number}/{service}".rstrip("/"),
                    evidence=Evidence(tool, execution_id, 0.85, "port scan"),
                ))

    def _from_dns(self, profile, tool, parsed, execution_id):
        values = parsed if isinstance(parsed, list) else [parsed]
        for value in values:
            text = value if isinstance(value, str) else str(value)
            if self._looks_like_ip(text) and text not in profile.resolved_addresses:
                profile.resolved_addresses.append(text)
                profile.observations.append(Observation(
                    kind="address",
                    value=text,
                    evidence=Evidence(tool, execution_id, 0.9, "DNS resolution"),
                ))

    def _from_generic(self, profile, tool, parsed, execution_id):
        # Unknown tools contribute a single labelled note rather than being
        # force-fit into a category the profiler cannot justify.
        summary = str(parsed)
        if len(summary) > 200:
            summary = summary[:197] + "..."
        profile.observations.append(Observation(
            kind="note",
            value=summary,
            evidence=Evidence(tool, execution_id, 0.4, "unstructured output"),
        ))

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value.strip())
            return True
        except ValueError:
            return False
