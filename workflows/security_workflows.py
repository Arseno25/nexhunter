"""Advanced security workflows - comprehensive assessment procedures."""

import json
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class WorkflowPhase:
    """Single workflow phase."""
    name: str
    description: str
    tools: List[str]
    status: str = "pending"  # pending, in_progress, completed, failed
    findings: int = 0
    duration: float = 0.0
    started: float = field(default_factory=time.time)


class BugBountyWorkflow:
    """Professional bug bounty workflow."""

    def __init__(self, target: str):
        self.target = target
        self.phases = {
            "reconnaissance": WorkflowPhase(
                name="Reconnaissance",
                description="Passive information gathering",
                tools=["shodan", "dnsdumpster", "google", "wayback"],
            ),
            "subdomain_enumeration": WorkflowPhase(
                name="Subdomain Enumeration",
                description="Discover all subdomains",
                tools=["subfinder", "amass", "assetfinder", "crt.sh"],
            ),
            "port_scanning": WorkflowPhase(
                name="Port Scanning",
                description="Identify open ports and services",
                tools=["nmap", "masscan", "rustscan"],
            ),
            "service_detection": WorkflowPhase(
                name="Service Detection",
                description="Detect technologies and versions",
                tools=["httpx", "nuclei", "wappalyzer"],
            ),
            "web_application_scanning": WorkflowPhase(
                name="Web Application Scanning",
                description="Scan for web vulnerabilities",
                tools=["nuclei", "sqlmap", "ffuf", "dalfox"],
            ),
            "authentication_testing": WorkflowPhase(
                name="Authentication Testing",
                description="Test auth mechanisms",
                tools=["burp", "custom-scripts"],
            ),
            "api_security_testing": WorkflowPhase(
                name="API Security Testing",
                description="Test API endpoints",
                tools=["httpx", "sqlmap", "nuclei"],
            ),
            "business_logic_testing": WorkflowPhase(
                name="Business Logic Testing",
                description="Test business logic flaws",
                tools=["burp", "manual-testing"],
            ),
            "privilege_escalation": WorkflowPhase(
                name="Privilege Escalation",
                description="Test privilege escalation vectors",
                tools=["custom-exploits"],
            ),
            "data_exposure": WorkflowPhase(
                name="Data Exposure",
                description="Check for sensitive data leaks",
                tools=["custom-scanner"],
            ),
        }
        self.findings_log = []
        self.started_at = time.time()

    def execute_phase(self, phase_name: str) -> Dict[str, Any]:
        """Execute single phase."""
        if phase_name not in self.phases:
            return {"ok": False, "error": f"Unknown phase: {phase_name}"}

        phase = self.phases[phase_name]
        phase.status = "in_progress"
        phase.started = time.time()

        try:
            phase.findings = len([f for f in self.findings_log if f.get("phase") == phase_name])
            phase.status = "completed"
            phase.duration = time.time() - phase.started

            return {"ok": True, "phase": phase_name, "findings": phase.findings}
        except Exception as e:
            phase.status = "failed"
            return {"ok": False, "error": str(e)}

    def add_finding(self, phase: str, title: str, severity: str, evidence: str = ""):
        """Add finding to log."""
        self.findings_log.append(
            {
                "phase": phase,
                "title": title,
                "severity": severity,
                "evidence": evidence,
                "timestamp": time.time(),
            }
        )

    def get_summary(self) -> Dict[str, Any]:
        """Get workflow summary."""
        completed = sum(1 for p in self.phases.values() if p.status == "completed")
        total_findings = len(self.findings_log)
        by_severity = {
            "critical": len([f for f in self.findings_log if f["severity"] == "critical"]),
            "high": len([f for f in self.findings_log if f["severity"] == "high"]),
            "medium": len([f for f in self.findings_log if f["severity"] == "medium"]),
            "low": len([f for f in self.findings_log if f["severity"] == "low"]),
            "info": len([f for f in self.findings_log if f["severity"] == "info"]),
        }

        return {
            "target": self.target,
            "phases_completed": completed,
            "total_phases": len(self.phases),
            "total_findings": total_findings,
            "by_severity": by_severity,
            "duration": time.time() - self.started_at,
        }


class PenetrationTestingWorkflow:
    """Full penetration testing workflow."""

    def __init__(self, target: str):
        self.target = target
        self.phases = {
            "scoping": WorkflowPhase("Scoping", "Define engagement scope", ["documentation"]),
            "reconnaissance": WorkflowPhase("Reconnaissance", "Information gathering", ["passive-tools"]),
            "scanning": WorkflowPhase("Scanning", "Active scanning", ["nmap", "nuclei"]),
            "enumeration": WorkflowPhase("Enumeration", "Detailed enumeration", ["custom-scripts"]),
            "vulnerability_assessment": WorkflowPhase("Vulnerability Assessment", "Find vulnerabilities", ["nuclei", "nessus"]),
            "exploitation": WorkflowPhase("Exploitation", "Exploit vulnerabilities", ["metasploit"]),
            "post_exploitation": WorkflowPhase("Post-Exploitation", "Maintain access", ["custom-scripts"]),
            "reporting": WorkflowPhase("Reporting", "Document findings", ["documentation"]),
        }

    def get_phases(self) -> Dict[str, WorkflowPhase]:
        """Get all phases."""
        return self.phases


class RedTeamWorkflow:
    """Adversarial red team assessment."""

    def __init__(self, target: str):
        self.target = target
        self.phases = {
            "threat_modeling": WorkflowPhase("Threat Modeling", "Model potential threats", []),
            "persistence": WorkflowPhase("Persistence", "Establish persistence", []),
            "lateral_movement": WorkflowPhase("Lateral Movement", "Move across network", []),
            "privilege_escalation": WorkflowPhase("Privilege Escalation", "Elevate privileges", []),
            "data_exfiltration": WorkflowPhase("Data Exfiltration", "Extract sensitive data", []),
            "covering_tracks": WorkflowPhase("Covering Tracks", "Remove evidence", []),
        }


class SecurityAuditWorkflow:
    """Compliance and security audit workflow."""

    def __init__(self, target: str, frameworks: List[str] = None):
        self.target = target
        self.frameworks = frameworks or ["OWASP Top 10", "CWE Top 25", "SANS Top 25"]
        self.phases = {
            "asset_inventory": WorkflowPhase("Asset Inventory", "Document all assets", []),
            "configuration_review": WorkflowPhase("Configuration Review", "Review configurations", []),
            "security_controls": WorkflowPhase("Security Controls", "Assess controls", []),
            "vulnerability_scan": WorkflowPhase("Vulnerability Scan", "Automated scanning", ["nuclei", "nessus"]),
            "policy_review": WorkflowPhase("Policy Review", "Review security policies", []),
            "compliance_check": WorkflowPhase("Compliance Check", f"Check against {frameworks}", []),
            "remediation_planning": WorkflowPhase("Remediation Planning", "Plan fixes", []),
        }


class ApiSecurityWorkflow:
    """API-focused security assessment."""

    def __init__(self, api_endpoint: str):
        self.target = api_endpoint
        self.phases = {
            "api_discovery": WorkflowPhase("API Discovery", "Discover API endpoints", ["httpx", "nuclei"]),
            "documentation_review": WorkflowPhase("Documentation Review", "Review API docs", []),
            "authentication_testing": WorkflowPhase("Authentication Testing", "Test auth", ["custom-scripts"]),
            "authorization_testing": WorkflowPhase("Authorization Testing", "Test authz", ["custom-scripts"]),
            "input_validation": WorkflowPhase("Input Validation", "Test input validation", ["ffuf", "sqlmap"]),
            "rate_limiting": WorkflowPhase("Rate Limiting", "Test rate limits", ["custom-scripts"]),
            "data_exposure": WorkflowPhase("Data Exposure", "Check data exposure", ["custom-scripts"]),
            "error_handling": WorkflowPhase("Error Handling", "Test error handling", ["custom-scripts"]),
            "api_versioning": WorkflowPhase("API Versioning", "Test versioning", []),
            "security_headers": WorkflowPhase("Security Headers", "Check headers", ["httpx"]),
        }


class MobileSecurityWorkflow:
    """Mobile application security assessment."""

    def __init__(self, app_path: str):
        self.target = app_path
        self.phases = {
            "static_analysis": WorkflowPhase("Static Analysis", "Static code analysis", ["semgrep", "jadx"]),
            "dynamic_analysis": WorkflowPhase("Dynamic Analysis", "Runtime analysis", ["frida", "burp"]),
            "data_storage": WorkflowPhase("Data Storage", "Check data storage", ["custom-scripts"]),
            "network_analysis": WorkflowPhase("Network Analysis", "Intercept network", ["burp"]),
            "authentication": WorkflowPhase("Authentication", "Test auth mechanisms", []),
            "cryptography": WorkflowPhase("Cryptography", "Check crypto implementation", []),
            "platform_specifics": WorkflowPhase("Platform Specifics", "Test iOS/Android specific", []),
            "reverse_engineering": WorkflowPhase("Reverse Engineering", "Reverse engineer app", ["jadx", "ghidra"]),
        }


class CloudSecurityWorkflow:
    """Cloud infrastructure security assessment."""

    def __init__(self, cloud_account: str):
        self.target = cloud_account
        self.phases = {
            "inventory": WorkflowPhase("Inventory", "Inventory cloud resources", ["aws-cli", "gcloud"]),
            "iam_review": WorkflowPhase("IAM Review", "Review IAM policies", []),
            "network_segmentation": WorkflowPhase("Network Segmentation", "Check network isolation", []),
            "encryption": WorkflowPhase("Encryption", "Verify encryption", []),
            "logging_monitoring": WorkflowPhase("Logging & Monitoring", "Check logging", []),
            "backup_recovery": WorkflowPhase("Backup & Recovery", "Test backups", []),
            "compliance": WorkflowPhase("Compliance", "Check compliance", []),
            "misconfiguration": WorkflowPhase("Misconfiguration", "Find misconfigurations", ["prowler", "cloudmapper"]),
        }


class SupplyChainSecurityWorkflow:
    """Supply chain and dependency security assessment."""

    def __init__(self, project_path: str):
        self.target = project_path
        self.phases = {
            "dependency_audit": WorkflowPhase("Dependency Audit", "Audit dependencies", ["npm-audit", "pip-check"]),
            "vulnerability_scan": WorkflowPhase("Vulnerability Scan", "Scan for CVEs", ["safety", "snyk"]),
            "license_check": WorkflowPhase("License Check", "Check licenses", ["license-checker"]),
            "source_integrity": WorkflowPhase("Source Integrity", "Verify source integrity", ["checksum-verify"]),
            "build_verification": WorkflowPhase("Build Verification", "Verify build process", []),
            "sbom_generation": WorkflowPhase("SBOM Generation", "Generate SBOM", ["cyclonedx"]),
            "typosquatting_check": WorkflowPhase("Typosquatting Check", "Check for typos", []),
        }


class DevSecOpsWorkflow:
    """DevSecOps pipeline security assessment."""

    def __init__(self, pipeline_path: str):
        self.target = pipeline_path
        self.phases = {
            "code_review": WorkflowPhase("Code Review", "Security code review", ["semgrep", "codeql"]),
            "sast": WorkflowPhase("SAST", "Static analysis", ["sonarqube", "checkmarx"]),
            "dependency_check": WorkflowPhase("Dependency Check", "Check dependencies", ["owasp-dependency-check"]),
            "container_scan": WorkflowPhase("Container Scan", "Scan containers", ["trivy"]),
            "secrets_detection": WorkflowPhase("Secrets Detection", "Find exposed secrets", ["truffleHog"]),
            "infrastructure_as_code": WorkflowPhase("Infrastructure as Code", "Scan IaC", ["tfsec"]),
            "configuration_management": WorkflowPhase("Configuration Management", "Check configs", []),
            "deployment_verification": WorkflowPhase("Deployment Verification", "Verify deployment", []),
        }


# Workflow registry
WORKFLOW_TYPES = {
    "bugbounty": BugBountyWorkflow,
    "pentest": PenetrationTestingWorkflow,
    "redteam": RedTeamWorkflow,
    "audit": SecurityAuditWorkflow,
    "api": ApiSecurityWorkflow,
    "mobile": MobileSecurityWorkflow,
    "cloud": CloudSecurityWorkflow,
    "supply-chain": SupplyChainSecurityWorkflow,
    "devsecops": DevSecOpsWorkflow,
}
