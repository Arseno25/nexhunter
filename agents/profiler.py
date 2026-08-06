"""Evidence-based target profiling.

A profile is what has actually been observed about a target, with the source of
each observation attached. It never invents a technology or a vulnerability:
every value carries the tool that produced it, and observed facts are kept
separate from inferences drawn about them. A profile that guessed would be
worse than none, because the next decision is made from it.
"""

import ipaddress
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# Target modality detection. A target string tells us which kind of assessment
# is even possible: a URL is a web app, a file is a binary or a capture, a
# directory is a codebase, an interface is wireless. This is what lets the
# selector reach file/cloud/code/wireless tooling instead of only network tools.
_BINARY_EXTS = (".elf", ".bin", ".so", ".o", ".a", ".exe", ".dll", ".macho",
                ".out", ".ko", ".axf", ".sys")
_MOBILE_EXTS = (".apk", ".ipa", ".aab", ".dex")
_FORENSICS_EXTS = (".pcap", ".pcapng", ".cap", ".mem", ".dmp", ".raw", ".vmem",
                   ".e01", ".dd", ".lime", ".img")
_CLOUD_MARKERS = ("arn:aws:", "amazonaws.com", "s3://", "gs://", "azure://",
                  "blob.core.windows.net", "googleapis.com", ".azurewebsites.net")
_IFACE_RE = re.compile(r"^(wlan|mon|wlp|ath|ra)\d")


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
    resolved_addresses: list[str] = field(default_factory=list)
    technologies: list[Observation] = field(default_factory=list)
    services: list[Observation] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def technology_names(self) -> list[str]:
        return sorted({o.value.lower() for o in self.technologies})

    def open_ports(self) -> list[int]:
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

    def recommended_safe_workflows(self) -> list[str]:
        """Passive-first workflow suggestions, grounded in what was observed."""
        recommendations = []
        if self.has_web_surface():
            recommendations.append("web-passive")
        if self.open_ports():
            recommendations.append("recon-active")
        if not recommendations:
            recommendations.append("recon-passive")
        return recommendations

    def to_dict(self) -> dict[str, Any]:
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
        profile.target_type = self._classify(target)
        return profile

    @staticmethod
    def _classify(target: str) -> str:
        """Infer the target's modality, which decides what tooling applies."""
        t = (target or "").strip()
        low = t.lower()

        if low.startswith(("http://", "https://")):
            return "web_application"
        if any(marker in low for marker in _CLOUD_MARKERS):
            return "cloud"

        kind = Profiler._file_kind(t, low)
        if kind:
            return kind
        if Profiler._is_dir(t):
            return "code"
        if _IFACE_RE.match(low) or low.endswith("mon"):
            return "wireless"
        if Profiler._looks_like_ip(t):
            return "host"
        if "/" in t:
            return "network"
        return "domain"

    @staticmethod
    def _file_kind(target: str, low: str) -> str | None:
        """Classify a file target by extension, or by being a real file."""
        if low.endswith(_MOBILE_EXTS):
            return "mobile"
        if low.endswith(_FORENSICS_EXTS):
            return "forensics"
        if low.endswith(_BINARY_EXTS):
            return "binary"
        # A real file with no telling extension is treated as a binary artifact.
        try:
            if os.path.isfile(os.path.expanduser(target)):
                return "binary"
        except (OSError, ValueError):
            pass
        return None

    @staticmethod
    def _is_dir(target: str) -> bool:
        try:
            return os.path.isdir(os.path.expanduser(target))
        except (OSError, ValueError):
            return False

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
        profile.updated_at = datetime.now(timezone.utc)
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
