"""Enhanced security features - advanced workflows, OSINT, threat analysis."""

import json
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class ThreatLevel:
    """Threat level assessment."""
    level: str  # critical, high, medium, low, info
    score: float  # 0-100
    factors: List[str]
    remediation: List[str]
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


class OsintCollector:
    """OSINT data collection and analysis."""

    def __init__(self):
        self.data = {
            "subdomains": [],
            "emails": [],
            "social_media": [],
            "dns_records": [],
            "whois_info": {},
            "ssl_certs": [],
            "shodan_results": [],
        }

    def add_subdomain(self, subdomain: str, ip: str = "", status: str = ""):
        """Add discovered subdomain."""
        self.data["subdomains"].append({"domain": subdomain, "ip": ip, "status": status})

    def add_email(self, email: str, source: str = ""):
        """Add discovered email."""
        self.data["emails"].append({"email": email, "source": source})

    def add_social(self, platform: str, username: str, url: str = ""):
        """Add social media account."""
        self.data["social_media"].append({"platform": platform, "username": username, "url": url})

    def add_dns_record(self, record_type: str, value: str, ttl: int = 0):
        """Add DNS record."""
        self.data["dns_records"].append({"type": record_type, "value": value, "ttl": ttl})

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return self.data

    def summary(self) -> Dict[str, int]:
        """Get summary counts."""
        return {
            "subdomains": len(self.data["subdomains"]),
            "emails": len(self.data["emails"]),
            "social_accounts": len(self.data["social_media"]),
            "dns_records": len(self.data["dns_records"]),
            "ssl_certs": len(self.data["ssl_certs"]),
        }


class VulnerabilityAnalyzer:
    """Analyze and correlate vulnerabilities."""

    def __init__(self):
        self.vulns = []
        self.chains = []  # Vulnerability chains/attack paths

    def add_vulnerability(
        self,
        title: str,
        cwe: str,
        cvss: float,
        severity: str,
        impact: str,
        affected_param: str = "",
    ):
        """Add vulnerability finding."""
        self.vulns.append(
            {
                "id": f"vuln_{int(time.time() * 1000)}",
                "title": title,
                "cwe": cwe,
                "cvss": cvss,
                "severity": severity,
                "impact": impact,
                "affected_param": affected_param,
                "timestamp": time.time(),
            }
        )

    def detect_chains(self) -> List[Dict[str, Any]]:
        """Detect vulnerability chains/attack paths."""
        chains = []
        if not self.vulns:
            return chains

        # Example: Auth bypass + data exposure
        auth_vulns = [v for v in self.vulns if "auth" in v["title"].lower()]
        data_vulns = [v for v in self.vulns if "disclosure" in v["title"].lower() or "exposure" in v["title"].lower()]

        if auth_vulns and data_vulns:
            chains.append(
                {
                    "name": "Authentication Bypass → Data Exposure",
                    "severity": "critical",
                    "vulns": [v["id"] for v in auth_vulns + data_vulns],
                    "impact": "Complete account compromise and data breach",
                }
            )

        # Example: Injection + RCE
        injection_vulns = [v for v in self.vulns if "injection" in v["title"].lower()]
        rce_vulns = [v for v in self.vulns if "rce" in v["title"].lower() or "code execution" in v["title"].lower()]

        if injection_vulns and rce_vulns:
            chains.append(
                {
                    "name": "Code Injection → Remote Code Execution",
                    "severity": "critical",
                    "vulns": [v["id"] for v in injection_vulns + rce_vulns],
                    "impact": "Full system compromise",
                }
            )

        self.chains = chains
        return chains

    def threat_score(self) -> ThreatLevel:
        """Calculate overall threat score."""
        if not self.vulns:
            return ThreatLevel(level="info", score=0, factors=[], remediation=[])

        critical_count = sum(1 for v in self.vulns if v["severity"] == "critical")
        high_count = sum(1 for v in self.vulns if v["severity"] == "high")
        avg_cvss = sum(v["cvss"] for v in self.vulns) / len(self.vulns)

        score = min(100, (critical_count * 30) + (high_count * 15) + (avg_cvss * 0.5))

        if score >= 80:
            level = "critical"
        elif score >= 60:
            level = "high"
        elif score >= 40:
            level = "medium"
        elif score >= 20:
            level = "low"
        else:
            level = "info"

        factors = []
        if critical_count > 0:
            factors.append(f"{critical_count} critical vulnerabilities")
        if high_count > 0:
            factors.append(f"{high_count} high-severity issues")
        if avg_cvss >= 7:
            factors.append(f"High average CVSS ({avg_cvss:.1f})")

        remediation = [
            "Immediate patching required",
            "Security code review needed",
            "Implement WAF rules",
            "Enable monitoring alerts",
        ]

        return ThreatLevel(level=level, score=score, factors=factors, remediation=remediation)


class BugBountyAssessment:
    """Bug bounty specific assessment."""

    def __init__(self, target: str):
        self.target = target
        self.scope = {"in_scope": [], "out_of_scope": []}
        self.phases = {
            "recon": {"status": "pending", "findings": 0},
            "subdomain_enum": {"status": "pending", "findings": 0},
            "port_scan": {"status": "pending", "findings": 0},
            "web_scan": {"status": "pending", "findings": 0},
            "api_test": {"status": "pending", "findings": 0},
            "auth_test": {"status": "pending", "findings": 0},
            "business_logic": {"status": "pending", "findings": 0},
        }
        self.report_template = {
            "summary": "",
            "vulnerability_list": [],
            "impact_assessment": "",
            "remediation_timeline": "",
        }

    def set_scope(self, in_scope: List[str], out_of_scope: List[str] = None):
        """Set assessment scope."""
        self.scope["in_scope"] = in_scope
        self.scope["out_of_scope"] = out_of_scope or []

    def start_phase(self, phase: str):
        """Mark phase as in progress."""
        if phase in self.phases:
            self.phases[phase]["status"] = "in_progress"

    def complete_phase(self, phase: str, findings: int = 0):
        """Mark phase as complete."""
        if phase in self.phases:
            self.phases[phase]["status"] = "completed"
            self.phases[phase]["findings"] = findings

    def get_priority_findings(self) -> List[Dict[str, Any]]:
        """Get high-priority findings for bug bounty."""
        return [
            {
                "priority": "P1",
                "category": "Authentication",
                "examples": ["Password reset bypass", "Session fixation", "Account takeover"],
            },
            {
                "priority": "P2",
                "category": "Authorization",
                "examples": ["Privilege escalation", "IDOR", "Broken access control"],
            },
            {
                "priority": "P3",
                "category": "Data Security",
                "examples": ["Data exposure", "Information disclosure", "API key leakage"],
            },
            {
                "priority": "P4",
                "category": "Logic Flaws",
                "examples": ["Race condition", "Business logic bypass", "Workflow bypass"],
            },
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "scope": self.scope,
            "phases": self.phases,
            "priority_areas": self.get_priority_findings(),
        }


class CTFChallengeAnalyzer:
    """CTF challenge analysis and solver."""

    def __init__(self, challenge_type: str):
        self.type = challenge_type  # web, crypto, forensics, pwn, recon
        self.hints = []
        self.tools = {
            "web": ["burp", "ffuf", "nuclei", "sqlmap", "dalfox"],
            "crypto": ["hashid", "john", "hashcat", "openssl", "python-crypto"],
            "forensics": ["strings", "exiftool", "binwalk", "foremost", "steghide"],
            "pwn": ["gdb", "checksec", "radare2", "pwntools", "ida-pro"],
            "recon": ["nmap", "subfinder", "amass", "shodan", "whois"],
        }
        self.progress = {"discovered": [], "solved_parts": []}

    def get_recommended_tools(self) -> List[str]:
        """Get tools recommended for this challenge type."""
        return self.tools.get(self.type, [])

    def add_hint(self, hint: str):
        """Add discovery hint."""
        self.hints.append({"hint": hint, "timestamp": time.time()})

    def mark_solved(self, part: str):
        """Mark challenge part as solved."""
        self.progress["solved_parts"].append(part)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "tools": self.get_recommended_tools(),
            "hints": self.hints,
            "progress": self.progress,
        }


class ThreatIntelligence:
    """Threat intelligence and risk assessment."""

    def __init__(self):
        self.indicators = {
            "iocs": [],  # Indicators of Compromise
            "ttps": [],  # Tactics, Techniques, Procedures
            "mitre_techniques": [],
            "threat_actors": [],
        }

    def add_ioc(self, indicator_type: str, value: str, source: str = ""):
        """Add indicator of compromise."""
        self.indicators["iocs"].append(
            {"type": indicator_type, "value": value, "source": source, "timestamp": time.time()}
        )

    def add_ttp(self, tactic: str, technique: str, description: str = ""):
        """Add TTP finding."""
        self.indicators["ttps"].append(
            {"tactic": tactic, "technique": technique, "description": description}
        )

    def add_mitre_technique(self, technique_id: str, name: str, severity: str = "medium"):
        """Add MITRE ATT&CK technique."""
        self.indicators["mitre_techniques"].append(
            {"id": technique_id, "name": name, "severity": severity}
        )

    def assess_risk(self) -> Dict[str, Any]:
        """Assess overall risk level."""
        ioc_count = len(self.indicators["iocs"])
        ttp_count = len(self.indicators["ttps"])
        mitre_count = len(self.indicators["mitre_techniques"])

        risk_score = min(100, (ioc_count * 5) + (ttp_count * 8) + (mitre_count * 10))

        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 40:
            risk_level = "medium"
        elif risk_score >= 20:
            risk_level = "low"
        else:
            risk_level = "minimal"

        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "ioc_count": ioc_count,
            "ttp_count": ttp_count,
            "mitre_techniques": mitre_count,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {"indicators": self.indicators, "risk_assessment": self.assess_risk()}
