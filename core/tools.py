"""nexhunter.tools - 150+ security tools registry with ToolSpec pattern."""

import importlib.util
import json
import shutil
import subprocess
from defusedxml import ElementTree as ET
from dataclasses import dataclass
from typing import Any
from collections.abc import Callable

from nexhunter.core.config import TOOL_TIMEOUTS, DEFAULT_TOOL_TIMEOUT
from nexhunter.core import params as P


# Risk classification by keyword in tool name or binary. First match wins,
# checked most-dangerous first. Anything unmatched defaults to "active".
# ponytail: keyword heuristic over 164 tools; override per-tool via
# ToolSpec(risk_level=...) when a specific tool is misclassified.
_RISK_KEYWORDS = [
    ("destructive", ("wipe", "destroy", "format", "deauth", "aireplay", "flood")),
    ("intrusive", (
        "sqlmap", "hydra", "john", "hashcat", "medusa", "ncrack", "brute",
        "gobuster", "ffuf", "dirb", "wfuzz", "nikto", "wpscan", "metasploit",
        "msf", "exploit", "dalfox", "commix", "xsstrike", "crackmap", "responder",
        "slowhttp", "hping", "dos", "netexec", "psexec", "winrm", "tplmap",
        "nosqlmap",
    )),
    ("passive", (
        "whois", "dig", "nslookup", "host_lookup", "subfinder", "amass",
        "assetfinder", "dnsx", "waybackurls", "gau", "crt", "shodan", "censys",
        "theharvester", "sublist3r", "findomain", "cero", "recon",
    )),
]


def _infer_risk(name: str, binary: str) -> str:
    """Infer a tool's risk level from its name and binary."""
    hay = f"{name} {binary}".lower()
    for level, keywords in _RISK_KEYWORDS:
        if any(kw in hay for kw in keywords):
            return level
    return "active"


# Chrome/Chromium binary names the Selenium driver can drive, in the order a
# Linux/macOS/Windows install is likely to expose them.
_CHROME_BINARIES = (
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
    "chrome", "chrome.exe",
)


def browser_engine_available() -> bool:
    """True when the headless browser crawl can really run.

    browser_crawl shells out to `python -m nexhunter.agents.browser_cli`, so a
    plain `which python` says nothing about whether it can drive a browser. The
    real requirements are the Selenium library and a Chrome/Chromium binary; the
    tool degrades to a static crawl without them, but it is not "available" as a
    browser engine, and reporting otherwise is the kind of unverified claim the
    registry avoids.
    """
    if importlib.util.find_spec("selenium") is None:
        return False
    return any(which(binary) for binary in _CHROME_BINARIES)


def _infer_target_param(params: dict[str, Any]) -> str | None:
    """Guess which parameter carries the scope target."""
    for candidate in ("target", "url", "domain", "host", "query", "ip"):
        if candidate in params:
            return candidate
    return None


# Category drives MCP profile membership: a client asking for the web profile
# should not be handed forensics tooling. Order matters; first hit wins.
# ponytail: keyword heuristic over 180 tools; override per-tool via
# ToolSpec(category=...) when a specific tool is misclassified (see `ss`, `nm`).
_CATEGORY_KEYWORDS = (
    ("code", ("semgrep", "bandit", "pylint", "sonar", "checkmarx", "gitleaks",
              "trufflehog", "snyk", "dependency", "retire", "safety", "npm_audit",
              "pip_audit", "checkov", "tfsec", "gitrob", "detect_secrets", "secret",
              "audit", "osv")),
    ("container", ("docker", "kubectl", "kube", "trivy", "clair", "grype",
                   "helm", "podman", "container", "falco")),
    ("cloud", ("aws", "gcloud", "azure", "prowler", "scoutsuite", "cloudsplaining",
               "s3", "cloudmapper", "pacu", "steampipe")),
    ("forensics", ("volatility", "sleuthkit", "autopsy", "binwalk", "exiftool",
                   "foremost", "bulk_extractor", "plaso", "yara", "capa",
                   "regripper", "pdf2txt", "steghide", "zsteg", "pngcheck",
                   "fcrackzip")),
    ("binary", ("ghidra", "radare", "r2", "objdump", "readelf", "checksec",
                "gdb", "strings", "ropgadget", "pwntools", "angr",
                "cutter", "ida")),
    ("crypto", ("hashid", "hashcat", "john", "openssl", "testssl", "sslscan",
                "sslyze", "cipher")),
    ("ctf", ("xortool", "rsactf", "pwninit", "ctf")),
    ("api", ("graphql", "swagger", "openapi", "postman", "arjun", "kiterunner",
             "insomnia", "jwt")),
    ("web", ("nuclei", "ffuf", "gobuster", "nikto", "sqlmap", "dalfox", "wpscan",
             "joomscan", "drupscan", "zap", "burp", "httpx", "katana", "whatweb",
             "wafw00f", "xsstrike", "commix", "feroxbuster", "dirsearch", "curl",
             "hakrawler", "gau", "waybackurls", "http", "paramspider", "linkfinder",
             "corsy", "subjack", "tplmap", "nosqlmap", "wfuzz", "webanalyze")),
    ("recon", ("nmap", "masscan", "rustscan", "subfinder", "amass", "assetfinder",
               "dns", "whois", "shodan", "censys", "theharvester", "recon",
               "fierce", "dnsx", "naabu", "host", "nslookup", "sublist3r",
               "dig", "axfr", "crt", "dnsrecon", "fping")),
    ("osint", ("maltego", "spiderfoot", "zoomeye", "cve_search", "nist_tool",
               "searchsploit", "theharwest", "sherlock", "holehe", "osint",
               "maigret", "phoneinfoga")),
    ("wireless", ("aireplay", "airodump", "aircrack", "wifite", "reaver", "kismet",
                  "airgeddon", "mdk4", "bettercap")),
    ("network", ("tcpdump", "tshark", "wireshark", "enum4linux",
                 "smbmap", "smbclient", "rpcclient", "ldapsearch", "snmp",
                 "responder", "netexec", "crackmap", "impacket", "arp", "netcat",
                 "socat", "tun2socks", "netdiscover", "winrm", "snmpcheck")),
    ("privesc", ("linpeas", "winpeas", "pspy", "peas", "dirty_cow", "privesc",
                 "exploit_suggester", "linux_exploit", "traitor", "suid")),
    ("payloads", ("veil", "unicorn", "chimera", "evasion", "phishing",
                  "social_engineer", "payload", "mimikatz", "beef",
                  "hoaxshell")),
    ("ids", ("snort", "suricata", "zeek", "ossec", "wazuh")),
    ("vuln_scan", ("nessus", "openvas", "qualys", "w3af", "gvm", "vulners",
                   "arachni", "skipfish", "wapiti")),
    ("exploitation", ("metasploit", "msf", "empire", "cobalt", "havoc", "sliver",
                      "exploit", "hydra", "medusa", "ncrack", "patator")),
    ("mobile", ("apktool", "jadx", "frida", "objection", "mobsf", "androguard")),
    ("utility", ("awk", "sed", "grep", "jq", "yq", "tar", "zip", "xxd", "hexdump",
                 "ldd", "ltrace", "rsync", "netstat", "mtr", "traceroute",
                 "nping", "wget", "strings", "file_type", "ping")),
)

# Maturity is asserted per tool, never guessed: claiming a tool is "stable"
# without a parser, a fixture, and a test is exactly the kind of unverified
# claim this project is meant to stop making. Anything not listed is beta.
STABLE_TOOLS = frozenset({
    "nmap_scan", "httpx_probe", "nuclei_scan", "subfinder_enum", "dns_lookup",
    "whois_lookup", "curl_headers", "nikto_scan", "ffuf_scan", "gobuster_dir",
    "gobuster_dns", "amass_enum", "assetfinder", "host_lookup", "nslookup",
    "wpscan_scan", "semgrep", "trivy", "testssl",
    "aws_get_caller_identity", "aws_list_s3_buckets", "kubectl_get_pods",
    "kubectl_get_namespaces", "docker_list_containers",
})


def _infer_category(name: str, binary: str) -> str:
    """Infer a tool's category from its name and binary."""
    hay = f"{name} {binary}".lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(kw in hay for kw in keywords):
            return category
    return "other"


@dataclass
class ToolSpec:
    """Tool specification with validation and execution."""

    name: str
    binary: str
    description: str
    params: dict[str, Any]
    timeout: int = DEFAULT_TOOL_TIMEOUT
    parser: str | None = None
    builder: Callable | None = None
    # Risk classification used by the autonomy ceiling. None => inferred from name/binary.
    risk_level: str | None = None
    # Which param carries the target (for profiling). None => inferred.
    target_param: str | None = None
    # Grouping used by MCP profiles. None => inferred from name/binary.
    category: str | None = None
    # stable | beta | experimental | disabled. None => derived from STABLE_TOOLS.
    maturity: str | None = None
    # Whether a deterministic terminal result may be cached. False for tools
    # that observe live state (packet/traffic capture), where a repeat is a
    # fresh observation, not the same answer.
    cacheable: bool = True
    # Typed parameter schemas. None => inferred from the `params` dict, so the
    # several hundred legacy entries gain validation without being rewritten.
    param_specs: tuple | None = None
    # Custom availability probe. None => the binary is present on PATH. Set this
    # when the binary alone does not prove the tool can run -- e.g. a wrapper
    # that shells out to Chrome or imports an optional library at runtime.
    availability_check: Callable | None = None

    def __post_init__(self):
        if self.timeout == DEFAULT_TOOL_TIMEOUT and self.name in TOOL_TIMEOUTS:
            self.timeout = TOOL_TIMEOUTS[self.name]
        if self.risk_level is None:
            self.risk_level = _infer_risk(self.name, self.binary)
        if self.target_param is None:
            self.target_param = _infer_target_param(self.params)
        if self.category is None:
            self.category = _infer_category(self.name, self.binary)
        if self.maturity is None:
            self.maturity = "stable" if self.name in STABLE_TOOLS else "beta"
        if self.param_specs is None:
            self.param_specs = tuple(
                P.spec_from_legacy(key, default) for key, default in self.params.items()
            )

    def spec_for(self, name: str):
        """The typed schema for one parameter, or None."""
        for spec in self.param_specs or ():
            if spec.name == name:
                return spec
        return None

    def secret_params(self) -> tuple:
        """Names of parameters whose values are credentials."""
        return tuple(spec.name for spec in (self.param_specs or ()) if spec.secret)

    @property
    def available(self) -> bool:
        """True when the tool can actually run.

        By default that means the binary is on PATH; a tool with a custom
        availability probe (e.g. one needing Chrome and an optional library)
        defers to that instead.
        """
        if self.availability_check is not None:
            try:
                return bool(self.availability_check())
            except Exception:  # noqa: BLE001 - a probe that errors means "not available"
                return False
        return which(self.binary) is not None

    def describe(self) -> dict:
        """Registry metadata, for the tools API and MCP resources."""
        return {
            "name": self.name,
            "description": self.description,
            "binary": self.binary,
            "category": self.category,
            "risk_level": self.risk_level,
            "maturity": self.maturity,
            "cacheable": self.cacheable,
            "timeout_s": self.timeout,
            "parameters": {
                spec.name: spec.describe() for spec in (self.param_specs or ())
            },
            "target_param": self.target_param,
            "available": self.available,
        }

    def target_of(self, params: dict) -> str:
        """Extract the scope target value from params."""
        if self.target_param and self.target_param in params:
            return str(params[self.target_param] or "")
        return ""

    def validate(self, user_params: dict) -> tuple[bool, str | None]:
        """Validate user params against the typed schema. Return (ok, error)."""
        _, error = P.validate_params(self.param_specs or (), user_params or {})
        return (error is None), error

    def normalize(self, user_params: dict) -> tuple[dict | None, str | None]:
        """Validate and return normalized values, or an error.

        Command builders receive the normalized values, so a builder never sees
        a raw caller-supplied string.
        """
        return P.validate_params(self.param_specs or (), user_params or {})

    def build_cmd(self, user_params: dict) -> list | None:
        """Build the argument list from validated parameters."""
        normalized, error = self.normalize(user_params)
        if error is not None or not self.builder:
            return None
        return self.builder(normalized)


_tool_specs = {
    # ==================== RECONNAISSANCE (OSINT) ====================
    "nmap_scan": ToolSpec(
        name="nmap_scan", binary="nmap", description="Port/service discovery",
        params={"target": None, "ports": "", "timing": "4"}, timeout=300,
        builder=lambda p: ["nmap", "-sV", f"-T{p['timing']}", "-oX", "-"] + (["-p", p["ports"]] if p["ports"] else []) + [p["target"]]),
    "masscan": ToolSpec(
        name="masscan", binary="masscan", description="Fast port scanner",
        params={"target": None, "ports": "1-65535", "rate": 1000}, timeout=600,
        builder=lambda p: ["masscan", p["target"], "-p", p["ports"], "-oG", "-", "--rate", str(p["rate"])]),
    "rustscan": ToolSpec(
        name="rustscan", binary="rustscan", description="Fast port scanner in Rust",
        params={"target": None}, timeout=300,
        builder=lambda p: ["rustscan", "-a", p["target"], "--", "-sV", "-T4"]),
    "subfinder_enum": ToolSpec(
        name="subfinder_enum", binary="subfinder", description="Passive subdomain enumeration",
        params={"domain": None}, timeout=60,
        builder=lambda p: ["subfinder", "-d", p["domain"], "-silent"]),
    "amass_enum": ToolSpec(
        name="amass_enum", binary="amass", description="Passive subdomain enumeration",
        params={"domain": None}, timeout=120,
        builder=lambda p: ["amass", "enum", "-passive", "-d", p["domain"]]),
    "assetfinder": ToolSpec(
        name="assetfinder", binary="assetfinder", description="Find subdomains from certificate transparency",
        params={"domain": None}, timeout=60,
        builder=lambda p: ["assetfinder", p["domain"]]),
    "dns_lookup": ToolSpec(
        name="dns_lookup", binary="dig", description="DNS query/enumeration",
        params={"domain": None, "type": "A"}, timeout=15,
        builder=lambda p: ["dig", "+short", p["domain"], p["type"]]),
    "nslookup": ToolSpec(
        name="nslookup", binary="nslookup", description="DNS lookup",
        params={"domain": None}, timeout=15,
        builder=lambda p: ["nslookup", p["domain"]]),
    "whois_lookup": ToolSpec(
        name="whois_lookup", binary="whois", description="WHOIS lookup",
        params={"query": None}, timeout=30,
        builder=lambda p: ["whois", p["query"]]),
    "host_lookup": ToolSpec(
        name="host_lookup", binary="host", description="DNS hostname lookup",
        params={"host": None}, timeout=15,
        builder=lambda p: ["host", p["host"]]),

    # ==================== WEB SCANNING ====================
    "nuclei_scan": ToolSpec(
        name="nuclei_scan", binary="nuclei", description="Vulnerability scanner with templates",
        params={"target": None, "severity": ""}, timeout=300,
        builder=lambda p: ["nuclei", "-u", p["target"], "-silent", "-jsonl"] + (["-severity", p["severity"]] if p["severity"] else [])),
    "ffuf_scan": ToolSpec(
        name="ffuf_scan", binary="ffuf", description="Web content fuzzer",
        params={"target": None, "wordlist": None, "filter_status": "", "threads": 40}, timeout=300,
        builder=lambda p: ["ffuf", "-u", p["target"].rstrip("/") + "/FUZZ", "-w", p["wordlist"], "-t", str(p["threads"])] + (["-fs", p["filter_status"]] if p["filter_status"] else [])),
    "gobuster_dir": ToolSpec(
        name="gobuster_dir", binary="gobuster", description="Directory brute force",
        params={"target": None, "wordlist": None, "extensions": "", "threads": 40}, timeout=300,
        builder=lambda p: ["gobuster", "dir", "-u", p["target"], "-w", p["wordlist"], "-t", str(p["threads"])] + (["-x", p["extensions"]] if p["extensions"] else [])),
    "gobuster_dns": ToolSpec(
        name="gobuster_dns", binary="gobuster", description="DNS subdomain brute force",
        params={"domain": None, "wordlist": None, "threads": 40}, timeout=300,
        builder=lambda p: ["gobuster", "dns", "-d", p["domain"], "-w", p["wordlist"], "-t", str(p["threads"])]),
    "nikto_scan": ToolSpec(
        name="nikto_scan", binary="nikto", description="Web server vulnerability scan",
        params={"target": None}, timeout=300,
        builder=lambda p: ["nikto", "-h", p["target"]]),
    "sqlmap_scan": ToolSpec(
        name="sqlmap_scan", binary="sqlmap", description="SQL injection tester",
        params={"url": None}, timeout=600,
        builder=lambda p: ["sqlmap", "-u", p["url"], "--batch", "--random-agent"]),
    "dalfox_xss": ToolSpec(
        name="dalfox_xss", binary="dalfox", description="XSS vulnerability scanner",
        params={"url": None}, timeout=300,
        builder=lambda p: ["dalfox", "url", p["url"]]),
    "httpx_probe": ToolSpec(
        name="httpx_probe", binary="httpx", description="HTTP probe with tech detection",
        params={"target": None}, timeout=60,
        builder=lambda p: ["httpx", "-u", p["target"], "-status-code", "-title", "-tech-detect", "-silent", "-json"]),
    "curl_headers": ToolSpec(
        name="curl_headers", binary="curl", description="Fetch HTTP headers",
        params={"url": None}, timeout=30,
        builder=lambda p: ["curl", "-sSI", "--max-time", "15", p["url"]]),
    "wpscan_scan": ToolSpec(
        name="wpscan_scan", binary="wpscan", description="WordPress vulnerability scanner",
        params={"url": None, "api_token": ""}, timeout=300,
        builder=lambda p: ["wpscan", "--url", p["url"], "--random-user-agent"] + (["--api-token", p["api_token"]] if p["api_token"] else [])),
    "joomscan": ToolSpec(
        name="joomscan", binary="joomscan", description="Joomla vulnerability scanner",
        params={"url": None}, timeout=300,
        builder=lambda p: ["joomscan", "--url", p["url"]]),
    "drupscan": ToolSpec(
        name="drupscan", binary="drupscan", description="Drupal vulnerability scanner",
        params={"url": None}, timeout=300,
        builder=lambda p: ["drupscan", "scan", "--url", p["url"]]),

    # ==================== INJECTION/EXPLOITATION ====================
    "commix": ToolSpec(
        name="commix", binary="commix", description="Command injection tester",
        params={"url": None}, timeout=300,
        builder=lambda p: ["commix", "-u", p["url"], "--batch"]),
    "xsstrike": ToolSpec(
        name="xsstrike", binary="xsstrike", description="XSS vulnerability tester",
        params={"url": None}, timeout=300,
        builder=lambda p: ["xsstrike", "-u", p["url"]]),
    "subfinder": ToolSpec(
        name="subfinder", binary="subfinder", description="Subdomain finder",
        params={"domain": None}, timeout=60,
        builder=lambda p: ["subfinder", "-d", p["domain"], "-silent"]),

    # ==================== CRYPTOGRAPHY & HASHING ====================
    "hashid": ToolSpec(
        name="hashid", binary="hash-identifier", description="Hash type identifier",
        params={"hash": None}, timeout=5,
        builder=lambda p: ["hash-identifier", p["hash"]]),
    "john": ToolSpec(
        name="john", binary="john", description="Hash cracker (John the Ripper)",
        params={"hashfile": None}, timeout=600,
        builder=lambda p: ["john", p["hashfile"]]),
    "hashcat": ToolSpec(
        name="hashcat", binary="hashcat", description="GPU hash cracker",
        params={"hashfile": None}, timeout=600,
        builder=lambda p: ["hashcat", "-m", "0", p["hashfile"]]),
    "openssl": ToolSpec(
        name="openssl", binary="openssl", description="SSL/TLS certificate checker",
        params={"host": None, "port": "443"}, timeout=15,
        builder=lambda p: ["openssl", "s_client", "-connect", f"{p['host']}:{p['port']}", "-showcerts"]),
    "testssl": ToolSpec(
        name="testssl", binary="testssl.sh", description="SSL/TLS vulnerability scanner",
        params={"url": None}, timeout=300, category="web",
        builder=lambda p: ["testssl.sh", p["url"]]),

    # ==================== FORENSICS & ANALYSIS ====================
    "strings": ToolSpec(
        name="strings", binary="strings", description="Extract printable strings",
        params={"file": None}, timeout=30,
        builder=lambda p: ["strings", p["file"]]),
    "exiftool": ToolSpec(
        name="exiftool", binary="exiftool", description="Extract metadata from files",
        params={"file": None}, timeout=30,
        builder=lambda p: ["exiftool", p["file"]]),
    "binwalk": ToolSpec(
        name="binwalk", binary="binwalk", description="Firmware analysis and extraction",
        params={"file": None}, timeout=60,
        builder=lambda p: ["binwalk", p["file"]]),
    "foremost": ToolSpec(
        name="foremost", binary="foremost", description="File carving and recovery",
        params={"file": None}, timeout=300,
        builder=lambda p: ["foremost", p["file"]]),
    "xxd": ToolSpec(
        name="xxd", binary="xxd", description="Hexdump utility",
        params={"file": None}, timeout=10,
        builder=lambda p: ["xxd", p["file"]]),
    "hexdump": ToolSpec(
        name="hexdump", binary="hexdump", description="ASCII hexdump",
        params={"file": None}, timeout=10,
        builder=lambda p: ["hexdump", "-C", p["file"]]),
    "strings_binary": ToolSpec(
        name="strings_binary", binary="strings", description="Extract strings from binary",
        params={"file": None}, timeout=30,
        builder=lambda p: ["strings", "-a", p["file"]]),
    "file_type": ToolSpec(
        name="file_type", binary="file", description="Detect file type",
        params={"file": None}, timeout=10,
        builder=lambda p: ["file", p["file"]]),

    # ==================== BINARY ANALYSIS & DEBUGGING ====================
    "checksec": ToolSpec(
        name="checksec", binary="checksec", description="Binary security features checker",
        params={"file": None}, timeout=10,
        builder=lambda p: ["checksec", "--file", p["file"]]),
    "objdump": ToolSpec(
        name="objdump", binary="objdump", description="Disassemble binary",
        params={"file": None}, timeout=60,
        builder=lambda p: ["objdump", "-d", p["file"]]),
    "readelf": ToolSpec(
        name="readelf", binary="readelf", description="ELF file analyzer",
        params={"file": None}, timeout=10,
        builder=lambda p: ["readelf", "-a", p["file"]]),
    "nm": ToolSpec(
        name="nm", binary="nm", description="List symbols from object files",
        params={"file": None}, timeout=10, category="utility",
        builder=lambda p: ["nm", p["file"]]),
    "ldd": ToolSpec(
        name="ldd", binary="ldd", description="List dynamic dependencies",
        params={"file": None}, timeout=10,
        builder=lambda p: ["ldd", p["file"]]),
    "gdb": ToolSpec(
        name="gdb", binary="gdb", description="GNU debugger",
        params={"file": None}, timeout=60,
        builder=lambda p: ["gdb", "-batch", "-ex", "info functions", p["file"]]),
    "strace_binary": ToolSpec(
        name="strace_binary", binary="strace", description="Trace system calls made by a binary",
        params={"file": None}, timeout=30, category="binary",
        builder=lambda p: ["strace", "-f", "-e", "trace=all", "--", p["file"]]),
    "ltrace": ToolSpec(
        name="ltrace", binary="ltrace", description="Library call tracer",
        params={"file": None}, timeout=30,
        builder=lambda p: ["ltrace", p["file"]]),

    # ==================== NETWORK TOOLS ====================
    "ping": ToolSpec(
        name="ping", binary="ping", description="ICMP ping host",
        params={"host": None}, timeout=10,
        builder=lambda p: ["ping", "-c", "4", p["host"]]),
    "traceroute": ToolSpec(
        name="traceroute", binary="traceroute", description="Trace route to host",
        params={"host": None}, timeout=30,
        builder=lambda p: ["traceroute", p["host"]]),
    "mtr": ToolSpec(
        name="mtr", binary="mtr", description="Network diagnostic tool",
        params={"host": None}, timeout=30,
        builder=lambda p: ["mtr", "-c", "4", p["host"]]),
    "netstat": ToolSpec(
        name="netstat", binary="netstat", description="Network statistics",
        params={}, timeout=10,
        builder=lambda p: ["netstat", "-tuln"]),
    "ss": ToolSpec(
        name="ss", binary="ss", description="Socket statistics",
        params={}, timeout=10, category="utility",
        builder=lambda p: ["ss", "-tuln"]),
    "arp_scan": ToolSpec(
        name="arp_scan", binary="arp-scan", description="ARP scanner",
        params={"interface": None}, timeout=60,
        builder=lambda p: ["arp-scan", "-l", "-I", p["interface"]] if p["interface"] else ["arp-scan", "-l"]),
    "nping": ToolSpec(
        name="nping", binary="nping", description="Network packet generation",
        params={"target": None}, timeout=30,
        builder=lambda p: ["nping", "--count", "4", p["target"]]),

    # ==================== PASSWORD & AUTH TESTING ====================
    "hydra": ToolSpec(
        name="hydra", binary="hydra", description="Brute force authentication",
        params={"target": None, "service": "ssh"}, timeout=300,
        builder=lambda p: ["hydra", "-l", "admin", "-P", "/usr/share/wordlists/passwords.txt", f"{p['service']}://{p['target']}"]),
    "medusa": ToolSpec(
        name="medusa", binary="medusa", description="Parallel authentication brute force",
        params={"target": None, "service": "ssh"}, timeout=300,
        builder=lambda p: ["medusa", "-h", p["target"], "-M", p["service"]]),
    "ncrack": ToolSpec(
        name="ncrack", binary="ncrack", description="Network authentication cracker",
        params={"target": None}, timeout=300,
        builder=lambda p: ["ncrack", "-p", "22", p["target"]]),
    "patator": ToolSpec(
        name="patator", binary="patator", description="Multi-protocol brute forcer",
        params={"target": None}, timeout=300,
        builder=lambda p: ["patator", "http_get", f"url=http://{p['target']}", "auth=basic"]),

    # ==================== WIRELESS/NETWORK MONITORING ====================
    "airodump": ToolSpec(
        name="airodump", binary="airodump-ng", description="Wireless network sniffer",
        params={"interface": None}, timeout=30, cacheable=False,
        builder=lambda p: ["airodump-ng", p["interface"]]),
    "aireplay": ToolSpec(
        name="aireplay", binary="aireplay-ng", description="Wireless network traffic injector",
        params={"interface": None}, timeout=30, cacheable=False,
        builder=lambda p: ["aireplay-ng", "-h", p["interface"]]),
    "aircrack": ToolSpec(
        name="aircrack", binary="aircrack-ng", description="WEP/WPA password cracker",
        params={"capfile": None}, timeout=600,
        builder=lambda p: ["aircrack-ng", p["capfile"]]),
    "tcpdump": ToolSpec(
        name="tcpdump", binary="tcpdump", description="Packet sniffer",
        params={"interface": "any"}, timeout=30, cacheable=False,
        builder=lambda p: ["tcpdump", "-i", p["interface"], "-n", "-l"]),
    "tshark": ToolSpec(
        name="tshark", binary="tshark", description="Wireshark command-line packet analyzer",
        params={"interface": "any"}, timeout=30, cacheable=False,
        builder=lambda p: ["tshark", "-i", p["interface"]]),

    # ==================== VULNERABILITY DATABASES ====================
    "searchsploit": ToolSpec(
        name="searchsploit", binary="searchsploit", description="Search the local ExploitDB database",
        params={"query": None}, timeout=30, risk_level="passive",
        builder=lambda p: ["searchsploit", p["query"]]),
    "cve_search": ToolSpec(
        name="cve_search", binary="cve_search", description="Search CVE database",
        params={"query": None}, timeout=30, risk_level="passive",
        builder=lambda p: ["cve_search", p["query"]]),

    # ==================== CONTAINER & CLOUD ====================
    # Cloud, container, and orchestration access is exposed as fixed read-only
    # actions. A generic passthrough (["aws"] + command.split()) is an
    # arbitrary-command API wearing a tool's name: it would let any caller,
    # including a model, run "iam create-access-key" or "delete-bucket".
    "docker_list_containers": ToolSpec(
        name="docker_list_containers", binary="docker", description="List Docker containers (read-only)",
        params={"all": ""}, timeout=30, risk_level="passive", category="container",
        builder=lambda p: ["docker", "ps", "--format", "json"] + (["--all"] if p["all"] else [])),
    "docker_inspect_container": ToolSpec(
        name="docker_inspect_container", binary="docker", description="Inspect one Docker container (read-only)",
        params={"container": None}, timeout=30, risk_level="passive", category="container",
        builder=lambda p: ["docker", "inspect", p["container"]]),
    "docker_list_images": ToolSpec(
        name="docker_list_images", binary="docker", description="List local Docker images (read-only)",
        params={}, timeout=30, risk_level="passive", category="container",
        builder=lambda p: ["docker", "images", "--format", "json"]),
    "kubectl_get_namespaces": ToolSpec(
        name="kubectl_get_namespaces", binary="kubectl", description="List Kubernetes namespaces (read-only)",
        params={}, timeout=30, risk_level="passive", category="container",
        builder=lambda p: ["kubectl", "get", "namespaces", "-o", "json"]),
    "kubectl_get_pods": ToolSpec(
        name="kubectl_get_pods", binary="kubectl", description="List pods in a namespace (read-only)",
        params={"namespace": "default"}, timeout=30, risk_level="passive", category="container",
        builder=lambda p: ["kubectl", "get", "pods", "-n", p["namespace"], "-o", "json"]),
    "kubectl_get_nodes": ToolSpec(
        name="kubectl_get_nodes", binary="kubectl", description="List cluster nodes (read-only)",
        params={}, timeout=30, risk_level="passive", category="container",
        builder=lambda p: ["kubectl", "get", "nodes", "-o", "json"]),
    "aws_get_caller_identity": ToolSpec(
        name="aws_get_caller_identity", binary="aws", description="Show the current AWS identity (read-only)",
        params={}, timeout=60, risk_level="passive", category="cloud",
        builder=lambda p: ["aws", "sts", "get-caller-identity", "--output", "json"]),
    "aws_list_s3_buckets": ToolSpec(
        name="aws_list_s3_buckets", binary="aws", description="List S3 buckets (read-only)",
        params={}, timeout=60, risk_level="passive", category="cloud",
        builder=lambda p: ["aws", "s3api", "list-buckets", "--output", "json"]),
    "aws_get_bucket_acl": ToolSpec(
        name="aws_get_bucket_acl", binary="aws", description="Read one S3 bucket's ACL (read-only)",
        params={"bucket": None}, timeout=60, risk_level="passive", category="cloud",
        builder=lambda p: ["aws", "s3api", "get-bucket-acl", "--bucket", p["bucket"], "--output", "json"]),
    "aws_list_iam_users": ToolSpec(
        name="aws_list_iam_users", binary="aws", description="List IAM users (read-only)",
        params={}, timeout=60, risk_level="passive", category="cloud",
        builder=lambda p: ["aws", "iam", "list-users", "--output", "json"]),
    "gcloud_list_projects": ToolSpec(
        name="gcloud_list_projects", binary="gcloud", description="List GCP projects (read-only)",
        params={}, timeout=60, risk_level="passive", category="cloud",
        builder=lambda p: ["gcloud", "projects", "list", "--format", "json"]),
    "gcloud_list_instances": ToolSpec(
        name="gcloud_list_instances", binary="gcloud", description="List Compute Engine instances (read-only)",
        params={}, timeout=60, risk_level="passive", category="cloud",
        builder=lambda p: ["gcloud", "compute", "instances", "list", "--format", "json"]),
    "az_account_show": ToolSpec(
        name="az_account_show", binary="az", description="Show the current Azure account (read-only)",
        params={}, timeout=30, risk_level="passive", category="cloud",
        builder=lambda p: ["az", "account", "show", "--output", "json"]),
    "az_list_resource_groups": ToolSpec(
        name="az_list_resource_groups", binary="az", description="List Azure resource groups (read-only)",
        params={}, timeout=60, risk_level="passive", category="cloud",
        builder=lambda p: ["az", "group", "list", "--output", "json"]),
    "trivy": ToolSpec(
        name="trivy", binary="trivy", description="Container vulnerability scanner",
        params={"image": None}, timeout=300,
        builder=lambda p: ["trivy", "image", p["image"]]),
    "grype": ToolSpec(
        name="grype", binary="grype", description="Vulnerability scanner for containers",
        params={"image": None}, timeout=300,
        builder=lambda p: ["grype", p["image"]]),

    # ==================== MOBILE SECURITY ====================
    "adb_list_devices": ToolSpec(
        name="adb_list_devices", binary="adb", description="List connected Android devices (read-only)",
        params={}, timeout=30, risk_level="passive", category="mobile",
        builder=lambda p: ["adb", "devices", "-l"]),
    "adb_list_packages": ToolSpec(
        name="adb_list_packages", binary="adb", description="List packages on the connected device (read-only)",
        params={}, timeout=30, risk_level="passive", category="mobile",
        builder=lambda p: ["adb", "shell", "pm", "list", "packages"]),
    "apktool": ToolSpec(
        name="apktool", binary="apktool", description="APK analyzer",
        params={"apk": None}, timeout=60,
        builder=lambda p: ["apktool", "d", p["apk"]]),
    "jadx": ToolSpec(
        name="jadx", binary="jadx", description="Android decompiler",
        params={"apk": None}, timeout=120,
        builder=lambda p: ["jadx", p["apk"]]),
    "frida": ToolSpec(
        name="frida", binary="frida", description="Dynamic instrumentation toolkit",
        params={"process": None}, timeout=30,
        builder=lambda p: ["frida", p["process"]]),

    # ==================== CODE ANALYSIS & SAST ====================
    "semgrep": ToolSpec(
        name="semgrep", binary="semgrep", description="Static analysis for multiple languages",
        params={"path": "."}, timeout=300,
        builder=lambda p: ["semgrep", "--json", p["path"]]),
    "sonarqube": ToolSpec(
        name="sonarqube", binary="sonar-scanner", description="Code quality and security scanner",
        params={"project": None}, timeout=600,
        builder=lambda p: ["sonar-scanner", "-Dsonar.projectKey=" + p["project"]]),
    "pylint": ToolSpec(
        name="pylint", binary="pylint", description="Python code analyzer",
        params={"file": None}, timeout=60,
        builder=lambda p: ["pylint", p["file"]]),
    "checkmarx": ToolSpec(
        name="checkmarx", binary="checkmarx", description="Code security scanner",
        params={"path": "."}, timeout=600,
        builder=lambda p: ["checkmarx", p["path"]]),

    # ==================== LOG ANALYSIS ====================
    "grep": ToolSpec(
        name="grep", binary="grep", description="Text search",
        params={"pattern": None, "file": None}, timeout=30,
        builder=lambda p: ["grep", p["pattern"], p["file"]]),
    "awk": ToolSpec(
        name="awk", binary="awk", description="Text processing",
        params={"pattern": None}, timeout=30,
        builder=lambda p: ["awk", p["pattern"]]),
    "sed": ToolSpec(
        name="sed", binary="sed", description="Stream editor",
        params={"expression": None, "file": None}, timeout=30,
        builder=lambda p: ["sed", p["expression"], p["file"]]),

    # ==================== DATA EXTRACTION ====================
    "metadata_anonymizer": ToolSpec(
        name="metadata_anonymizer", binary="exiftool", description="Remove metadata",
        params={"file": None}, timeout=30,
        builder=lambda p: ["exiftool", "-All=", p["file"]]),

    # ==================== NETWORK RECONNAISSANCE ====================
    "shodan": ToolSpec(
        name="shodan", binary="shodan", description="Shodan search engine CLI",
        params={"query": None}, timeout=30,
        builder=lambda p: ["shodan", "search", p["query"]]),
    "censys": ToolSpec(
        name="censys", binary="censys-cli", description="Censys.io CLI",
        params={"query": None}, timeout=30,
        builder=lambda p: ["censys-cli", "search", p["query"]]),
    "zoomeye": ToolSpec(
        name="zoomeye", binary="zoomeye", description="ZoomEye CLI",
        params={"query": None}, timeout=30,
        builder=lambda p: ["zoomeye", p["query"]]),

    # ==================== PAYLOAD GENERATION ====================
    "msfvenom": ToolSpec(
        name="msfvenom", binary="msfvenom", description="Metasploit payload generator",
        params={"payload": "windows/meterpreter/reverse_tcp"}, timeout=30,
        builder=lambda p: ["msfvenom", "-p", p["payload"]]),
    "evasion": ToolSpec(
        name="evasion", binary="veil", description="Obfuscation/evasion tool",
        params={"payload": None}, timeout=60,
        builder=lambda p: ["veil", p["payload"]]),

    # ==================== COMPLIANCE & ASSESSMENT ====================
    "nessus": ToolSpec(
        name="nessus", binary="nessusd", description="Vulnerability assessment",
        params={"target": None}, timeout=600,
        builder=lambda p: ["nessusd", "-q", p["target"]]),
    "qualys": ToolSpec(
        name="qualys", binary="qualys-cli", description="Qualys vulnerability scanner",
        params={"target": None}, timeout=600,
        builder=lambda p: ["qualys-cli", "scan", p["target"]]),
    "openvas": ToolSpec(
        name="openvas", binary="openvassd", description="OpenVAS vulnerability scanner",
        params={"target": None}, timeout=600,
        builder=lambda p: ["openvassd", p["target"]]),
    "nist_tool": ToolSpec(
        name="nist_tool", binary="nist-scan", description="NIST compliance checker",
        params={"target": None}, timeout=300, risk_level="passive",
        builder=lambda p: ["nist-scan", p["target"]]),

    # ==================== THREAT INTELLIGENCE ====================
    "maltego": ToolSpec(
        name="maltego", binary="maltego", description="OSINT data mining and visualization",
        params={"entity": None}, timeout=120,
        builder=lambda p: ["maltego", p["entity"]]),
    "spiderfoot": ToolSpec(
        name="spiderfoot", binary="spiderfoot", description="OSINT automation framework",
        params={"target": None}, timeout=300,
        builder=lambda p: ["spiderfoot", "-s", p["target"]]),

    # ==================== UTILITY TOOLS ====================
    "jq": ToolSpec(
        name="jq", binary="jq", description="JSON query processor",
        params={"file": None}, timeout=10,
        builder=lambda p: ["jq", ".", p["file"]]),
    "yq": ToolSpec(
        name="yq", binary="yq", description="YAML query processor",
        params={"file": None}, timeout=10,
        builder=lambda p: ["yq", p["file"]]),
    "curl": ToolSpec(
        name="curl", binary="curl", description="URL data transfer",
        params={"url": None}, timeout=30,
        builder=lambda p: ["curl", "-v", p["url"]]),
    "wget": ToolSpec(
        name="wget", binary="wget", description="File downloader",
        params={"url": None}, timeout=300,
        builder=lambda p: ["wget", p["url"]]),
    "rsync": ToolSpec(
        name="rsync", binary="rsync", description="File synchronization",
        params={"source": None, "dest": None}, timeout=300,
        builder=lambda p: ["rsync", "-av", p["source"], p["dest"]]),
    "tar": ToolSpec(
        name="tar", binary="tar", description="Archive manager",
        params={"file": None}, timeout=60,
        builder=lambda p: ["tar", "-tzf", p["file"]]),
    "zip": ToolSpec(
        name="zip", binary="zip", description="ZIP archive tool",
        params={"file": None}, timeout=60,
        builder=lambda p: ["zip", "-l", p["file"]]),

    # ==================== ADDITIONAL SECURITY TOOLS ====================
    "burpsuite": ToolSpec(
        name="burpsuite", binary="burpsuite", description="Web security testing platform",
        params={"project": None}, timeout=600,
        builder=lambda p: ["burpsuite", "--headless", "--project-file=" + p["project"]]),
    "zap": ToolSpec(
        name="zap", binary="zaproxy", description="OWASP ZAP web scanner",
        params={"url": None}, timeout=600,
        builder=lambda p: ["zaproxy", "-cmd", "-quickurl", p["url"]]),
    "w3af": ToolSpec(
        name="w3af", binary="w3af", description="Web attack and audit framework",
        params={"url": None}, timeout=600,
        builder=lambda p: ["w3af", "-s", p["url"]]),
    "metasploit": ToolSpec(
        name="metasploit", binary="msfconsole", description="Metasploit exploitation framework",
        params={"module": None}, timeout=300,
        builder=lambda p: ["msfconsole", "-m", p["module"], "-x", "run"]),
    "beef": ToolSpec(
        name="beef", binary="beef", description="Browser exploitation framework",
        params={"url": None}, timeout=300,
        builder=lambda p: ["beef", p["url"]]),
    "empire": ToolSpec(
        name="empire", binary="empire", description="PowerShell post-exploitation framework",
        params={"listener": "http"}, timeout=120,
        builder=lambda p: ["empire", "-l", p["listener"]]),
    "cobalt_strike": ToolSpec(
        name="cobalt_strike", binary="cobaltstrike", description="Adversary simulation framework",
        params={"profile": None}, timeout=120,
        builder=lambda p: ["cobaltstrike", p["profile"]]),
    "havoc": ToolSpec(
        name="havoc", binary="havoc", description="C2 framework",
        params={"profile": None}, timeout=120,
        builder=lambda p: ["havoc", p["profile"]]),
    # "sliver" (C2 framework) was registered as a generic command passthrough.
    # It is removed rather than rewritten as fixed actions: enumerating C2
    # operations would be adding offensive capability, which this platform
    # does not do. Operators who need a C2 run it directly, outside NexHunter.

    # ==================== DEPENDENCY SCANNING ====================
    "npm_audit": ToolSpec(
        name="npm_audit", binary="npm", description="NPM dependency vulnerability audit",
        params={"path": "."}, timeout=60,
        builder=lambda p: ["npm", "audit", "--json"]),
    "safety": ToolSpec(
        name="safety", binary="safety", description="Python security vulnerability scanner",
        params={"file": "requirements.txt"}, timeout=30,
        builder=lambda p: ["safety", "check", "-r", p["file"]]),
    "snyk_test": ToolSpec(
        name="snyk_test", binary="snyk", description="Scan a project's dependencies for known vulnerabilities",
        params={"path": "."}, timeout=120, risk_level="passive", category="code",
        builder=lambda p: ["snyk", "test", "--json", f"--file={p['path']}"]),
    "owasp_dependency_check": ToolSpec(
        name="owasp_dependency_check", binary="dependency-check", description="OWASP dependency analyzer",
        params={"path": "."}, timeout=300,
        builder=lambda p: ["dependency-check", "-scan", p["path"]]),

    # ==================== SECRET DETECTION ====================
    "trufflehog": ToolSpec(
        name="trufflehog", binary="truffleHog", description="Detect secrets in git history",
        params={"repo": None}, timeout=300,
        builder=lambda p: ["truffleHog", "git", p["repo"]]),
    "gitrob": ToolSpec(
        name="gitrob", binary="gitrob", description="GitHub reconnaissance tool",
        params={"user": None}, timeout=120,
        builder=lambda p: ["gitrob", "scan", p["user"]]),

    # ==================== CONFIGURATION SCANNING ====================
    "tfsec": ToolSpec(
        name="tfsec", binary="tfsec", description="Terraform security scanner",
        params={"path": "."}, timeout=60,
        builder=lambda p: ["tfsec", p["path"]]),
    "checkov": ToolSpec(
        name="checkov", binary="checkov", description="Infrastructure as Code scanner",
        params={"path": "."}, timeout=300,
        builder=lambda p: ["checkov", "-d", p["path"]]),
    "kube_bench": ToolSpec(
        name="kube_bench", binary="kube-bench", description="Kubernetes security audit",
        params={}, timeout=120,
        builder=lambda p: ["kube-bench", "run"]),
    "kube_hunter": ToolSpec(
        name="kube_hunter", binary="kube-hunter", description="Kubernetes penetration testing",
        params={"pod": "default"}, timeout=300,
        builder=lambda p: ["kube-hunter", "--pod", p["pod"]]),
    "falco": ToolSpec(
        name="falco", binary="falco", description="Runtime security monitoring",
        params={}, timeout=60,
        builder=lambda p: ["falco", "-o", "json_output=true"]),

    # ==================== API TESTING ====================
    "postman": ToolSpec(
        name="postman", binary="postman", description="API testing and development",
        params={"collection": None}, timeout=300,
        builder=lambda p: ["postman", "run", p["collection"]]),
    "insomnia": ToolSpec(
        name="insomnia", binary="insomnia", description="API client",
        params={"collection": None}, timeout=300,
        builder=lambda p: ["insomnia", "run", p["collection"]]),
    "graphql_voyager": ToolSpec(
        name="graphql_voyager", binary="graphql-voyager", description="GraphQL schema explorer",
        params={"url": None}, timeout=30,
        builder=lambda p: ["graphql-voyager", p["url"]]),
    "graphql_introspect": ToolSpec(
        name="graphql_introspect", binary="graphql", description="GraphQL introspection",
        params={"url": None}, timeout=30,
        builder=lambda p: ["graphql", "introspect", p["url"]]),
    "rest_client": ToolSpec(
        name="rest_client", binary="http", description="HTTPie HTTP client",
        params={"url": None}, timeout=30,
        builder=lambda p: ["http", "GET", p["url"]]),

    # ==================== SOURCE CODE ANALYSIS ====================
    "ghidra": ToolSpec(
        name="ghidra", binary="ghidra", description="Binary reverse engineering tool",
        params={"file": None}, timeout=300,
        builder=lambda p: ["ghidra", p["file"]]),
    "ida": ToolSpec(
        name="ida", binary="ida", description="Interactive disassembler",
        params={"file": None}, timeout=300,
        builder=lambda p: ["ida", p["file"]]),
    "radare2": ToolSpec(
        name="radare2", binary="r2", description="Reverse engineering framework",
        params={"file": None}, timeout=120,
        builder=lambda p: ["r2", "-A", p["file"]]),
    "cutter": ToolSpec(
        name="cutter", binary="cutter", description="Radare2 GUI",
        params={"file": None}, timeout=120,
        builder=lambda p: ["cutter", p["file"]]),
    "angr": ToolSpec(
        name="angr", binary="angr", description="Binary analysis engine",
        params={"binary": None}, timeout=300,
        builder=lambda p: ["angr", p["binary"]]),

    # ==================== NETWORK ENUMERATION ====================
    "enum4linux": ToolSpec(
        name="enum4linux", binary="enum4linux", description="SMB/CIFS enumeration",
        params={"target": None}, timeout=120,
        builder=lambda p: ["enum4linux", "-a", p["target"]]),
    "smbmap": ToolSpec(
        name="smbmap", binary="smbmap", description="SMB share enumeration",
        params={"host": None}, timeout=60,
        builder=lambda p: ["smbmap", "-H", p["host"]]),
    "cme": ToolSpec(
        name="cme", binary="crackmapexec", description="Post-exploitation framework",
        params={"protocol": "smb", "target": None}, timeout=120,
        builder=lambda p: ["crackmapexec", p["protocol"], p["target"]]),
    "smbclient": ToolSpec(
        name="smbclient", binary="smbclient", description="SMB client",
        params={"path": None}, timeout=30,
        builder=lambda p: ["smbclient", p["path"]]),
    "rpcclient": ToolSpec(
        name="rpcclient", binary="rpcclient", description="RPC client",
        params={"server": None}, timeout=30,
        builder=lambda p: ["rpcclient", p["server"]]),
    "ldapsearch": ToolSpec(
        name="ldapsearch", binary="ldapsearch", description="LDAP search",
        params={"server": None}, timeout=30,
        builder=lambda p: ["ldapsearch", "-H", f"ldap://{p['server']}", "-x"]),

    # ==================== PRIVILEGE ESCALATION ====================
    "winpeas": ToolSpec(
        name="winpeas", binary="winPEAS", description="Windows privilege escalation tool",
        params={}, timeout=120,
        builder=lambda p: ["winPEAS"]),
    "linpeas": ToolSpec(
        name="linpeas", binary="bash", description="Linux privilege escalation tool (linpeas.sh)",
        params={}, timeout=120,
        builder=lambda p: ["bash", "linpeas.sh"]),
    "pspy": ToolSpec(
        name="pspy", binary="pspy", description="Process monitoring tool",
        params={}, timeout=60,
        builder=lambda p: ["pspy"]),
    "dirty_cow": ToolSpec(
        name="dirty_cow", binary="dirty_cow", description="Linux kernel exploit",
        params={"binary": None}, timeout=60,
        builder=lambda p: ["./dirty_cow", p["binary"]]),

    # ==================== DATA EXFILTRATION ====================
    "dnscat2": ToolSpec(
        name="dnscat2", binary="dnscat2", description="DNS exfiltration",
        params={"domain": None}, timeout=300,
        builder=lambda p: ["dnscat2", p["domain"]]),
    "tun2socks": ToolSpec(
        name="tun2socks", binary="tun2socks", description="TUN tunnel",
        params={"socks": "127.0.0.1:1080"}, timeout=300,
        builder=lambda p: ["tun2socks", "--socks", p["socks"]]),

    # ==================== EVASION & OBFUSCATION ====================
    "veil": ToolSpec(
        name="veil", binary="veil", description="AV evasion tool",
        params={"payload": None}, timeout=120,
        builder=lambda p: ["veil", p["payload"]]),
    "unicorn": ToolSpec(
        name="unicorn", binary="unicorn", description="PowerShell obfuscator",
        params={"script": None}, timeout=60,
        builder=lambda p: ["unicorn", p["script"]]),
    "chimera": ToolSpec(
        name="chimera", binary="chimera", description="Payload obfuscator",
        params={"payload": None}, timeout=60,
        builder=lambda p: ["chimera", p["payload"]]),

    # ==================== PERSISTENCE ====================
    "empire_persistence": ToolSpec(
        name="empire_persistence", binary="empire", description="Empire persistence module",
        params={"module": "persistence/userland/registry_run"}, timeout=120,
        builder=lambda p: ["empire", "-m", p["module"]]),

    # ==================== FORENSICS & INCIDENT RESPONSE ====================
    "volatility": ToolSpec(
        name="volatility", binary="volatility", description="Memory forensics framework",
        params={"dump": None}, timeout=300,
        builder=lambda p: ["volatility", "-f", p["dump"], "imageinfo"]),
    "sleuthkit": ToolSpec(
        name="sleuthkit", binary="fls", description="Filesystem analysis",
        params={"image": None}, timeout=300,
        builder=lambda p: ["fls", p["image"]]),
    "autopsy": ToolSpec(
        name="autopsy", binary="autopsy", description="Digital forensics platform",
        params={"image": None}, timeout=600,
        builder=lambda p: ["autopsy", p["image"]]),
    "regripper": ToolSpec(
        name="regripper", binary="rip.pl", description="Windows registry extraction",
        params={"hive": None}, timeout=60,
        builder=lambda p: ["rip.pl", "-r", p["hive"]]),

    # ==================== TRAFFIC ANALYSIS ====================
    "wireshark": ToolSpec(
        name="wireshark", binary="wireshark", description="Network protocol analyzer",
        params={"pcap": None}, timeout=60,
        builder=lambda p: ["wireshark", "-r", p["pcap"]]),
    "suricata": ToolSpec(
        name="suricata", binary="suricata", description="IDS/IPS engine",
        params={"pcap": None}, timeout=120,
        builder=lambda p: ["suricata", "-r", p["pcap"]]),
    "snort": ToolSpec(
        name="snort", binary="snort", description="Network intrusion detection",
        params={"pcap": None}, timeout=120,
        builder=lambda p: ["snort", "-r", p["pcap"]]),

    # ==================== SOCIAL ENGINEERING ====================
    "social_engineer_toolkit": ToolSpec(
        name="social_engineer_toolkit", binary="setoolkit", description="Social engineering toolkit",
        params={"attack": None}, timeout=300,
        builder=lambda p: ["setoolkit", p["attack"]]),
    "phishing_framework": ToolSpec(
        name="phishing_framework", binary="gophish", description="Phishing framework",
        params={"config": None}, timeout=60,
        builder=lambda p: ["gophish", "-config", p["config"]]),

    # ==================== MISC SECURITY TOOLS ====================
    "nuclei_templates": ToolSpec(
        name="nuclei_templates", binary="nuclei", description="Nuclei template lister",
        params={}, timeout=30,
        builder=lambda p: ["nuclei", "-list-templates"]),
    "shodan_host_lookup": ToolSpec(
        name="shodan_host_lookup", binary="shodan", description="Look up a host in Shodan (passive, no traffic to the target)",
        params={"ip": None}, timeout=30, risk_level="passive", category="recon",
        builder=lambda p: ["shodan", "host", p["ip"]]),
    "metasploit_payload": ToolSpec(
        name="metasploit_payload", binary="msfvenom", description="Generate MSF payloads",
        params={"lhost": "127.0.0.1", "lport": "4444"}, timeout=30,
        builder=lambda p: ["msfvenom", "-p", "windows/shell_reverse_tcp", "LHOST=" + p["lhost"], "LPORT=" + p["lport"]]),

    # ==================== OSINT ====================
    "sherlock": ToolSpec(
        name="sherlock", binary="sherlock", description="Username enumeration across social networks",
        params={"username": None}, timeout=60, risk_level="passive",
        builder=lambda p: ["sherlock", p["username"]]),
    "holehe": ToolSpec(
        name="holehe", binary="holehe", description="Check if an email is registered on online services",
        params={"email": None}, timeout=60, risk_level="passive",
        builder=lambda p: ["holehe", p["email"]]),
    "theharvester_recon": ToolSpec(
        name="theharvester_recon", binary="theHarvester", description="OSINT email and host harvesting",
        params={"domain": None, "limit": "100"}, timeout=120, risk_level="passive",
        builder=lambda p: ["theHarvester", "-d", p["domain"], "-b", "all", "-l", str(p["limit"])]),

    # ==================== WIRELESS ====================
    "wifite": ToolSpec(
        name="wifite", binary="wifite", description="Automated WPA/WPS wireless attack runner",
        params={"interface": ""}, timeout=600, risk_level="intrusive",
        builder=lambda p: ["wifite"] + (["-i", p["interface"]] if p["interface"] else [])),
    "reaver": ToolSpec(
        name="reaver", binary="reaver", description="WPS PIN brute force",
        params={"target": None, "interface": None}, timeout=600, risk_level="intrusive",
        builder=lambda p: ["reaver", "-i", p["interface"], "-b", p["target"], "-vv"]),

    # ==================== PRIVILEGE ESCALATION ====================
    "linux_exploit_suggester": ToolSpec(
        name="linux_exploit_suggester", binary="bash",
        description="Suggest local privilege escalation exploits for the current host",
        params={}, timeout=60, risk_level="passive",
        builder=lambda p: ["bash", "linux-exploit-suggester.sh"]),

    # ==================== PAYLOADS ====================
    "mimikatz": ToolSpec(
        name="mimikatz", binary="mimikatz", description="Credential extraction from Windows memory",
        params={"action": "sekurlsa::logonpasswords"}, timeout=60, risk_level="intrusive",
        builder=lambda p: ["mimikatz", p["action"]]),

    # ==================== STEGANOGRAPHY & FILE ANALYSIS ====================
    "steghide": ToolSpec(
        name="steghide", binary="steghide", description="Inspect or extract data hidden in media files",
        params={"file": None, "extract": False}, timeout=60, risk_level="passive",
        builder=lambda p: ["steghide", "extract", "-sf", p["file"], "-p", ""]
        if p["extract"] else ["steghide", "info", p["file"]]),
    "zsteg": ToolSpec(
        name="zsteg", binary="zsteg", description="Detect hidden data in PNG/BMP files",
        params={"file": None}, timeout=60, risk_level="passive",
        builder=lambda p: ["zsteg", p["file"]]),
    "pngcheck": ToolSpec(
        name="pngcheck", binary="pngcheck", description="Verify and analyze PNG file integrity",
        params={"file": None}, timeout=30, risk_level="passive",
        builder=lambda p: ["pngcheck", "-v", p["file"]]),
    "fcrackzip": ToolSpec(
        name="fcrackzip", binary="fcrackzip", description="Dictionary attack on password-protected ZIP files",
        params={"file": None, "wordlist": "/usr/share/wordlists/rockyou.txt"}, timeout=300,
        builder=lambda p: ["fcrackzip", "-u", "-D", "-p", p["wordlist"], p["file"]]),

    # ==================== CTF ====================
    "pwninit": ToolSpec(
        name="pwninit", binary="pwninit", description="Prepare a pwning challenge binary: patch, download libc, makefile",
        params={"file": None}, timeout=60, risk_level="passive",
        builder=lambda p: ["pwninit", "--bin", p["file"]]),
    "rsa_ctf_tool": ToolSpec(
        name="rsa_ctf_tool", binary="RsaCtfTool", description="Attack and decode RSA CTF challenges",
        params={"public_key": None, "attack": "all"}, timeout=300, risk_level="passive",
        builder=lambda p: ["RsaCtfTool", "--publickey", p["public_key"], "--attack", p["attack"]]),
    "xortool": ToolSpec(
        name="xortool", binary="xortool", description="Guess XOR key length and recover xored plaintext",
        params={"file": None, "key_length": ""}, timeout=120, risk_level="passive",
        builder=lambda p: ["xortool", "-l", p["key_length"], p["file"]] if p["key_length"] else ["xortool", p["file"]]),

    # ==================== WIRELESS ====================
    "kismet": ToolSpec(
        name="kismet", binary="kismet", description="Passive wireless network detector and channel capture",
        params={"capture_file": ""}, timeout=600, risk_level="passive", cacheable=False,
        builder=lambda p: ["kismet", "--no-gpsd", "--no-server"] + (["--logfile", p["capture_file"]] if p["capture_file"] else [])),
    "airgeddon": ToolSpec(
        name="airgeddon", binary="bash", description="Multipurpose wireless attack framework (airgeddon.sh)",
        params={"interface": None}, timeout=600, risk_level="intrusive",
        builder=lambda p: ["bash", "airgeddon.sh", "-i", p["interface"]]),
    "bettercap": ToolSpec(
        name="bettercap", binary="bettercap", description="Network MITM and reconnaissance framework",
        params={"target": ""}, timeout=300, risk_level="intrusive",
        builder=lambda p: ["bettercap", "-eval", "net.probe on; arp.spoof on"] + (["--target", p["target"]] if p["target"] else [])),
    "mdk4": ToolSpec(
        name="mdk4", binary="mdk4", description="Wireless DoS and deauthentication testing",
        params={"interface": None, "bssid": None}, timeout=300, risk_level="destructive",
        builder=lambda p: ["mdk4", p["interface"], "d", p["bssid"]]),

    # ==================== IDS / NETWORK MONITORING ====================
    "zeek": ToolSpec(
        name="zeek", binary="zeek", description="Network security monitor: analyze pcap files",
        params={"pcap": None}, timeout=600,
        builder=lambda p: ["zeek", "-r", p["pcap"]]),

    # ==================== VULNERABILITY SCANNERS ====================
    "arachni": ToolSpec(
        name="arachni", binary="arachni", description="Full-featured web application vulnerability scanner",
        params={"url": None, "report": "/tmp/arachni.html"}, timeout=900,
        builder=lambda p: ["arachni", "--output-verbose", p["url"], "--report-save-path", p["report"]]),
    "skipfish": ToolSpec(
        name="skipfish", binary="skipfish", description="High-speed web application security scanner",
        params={"url": None, "output_dir": "/tmp/skipfish"}, timeout=900,
        builder=lambda p: ["skipfish", "-o", p["output_dir"], p["url"]]),
    "wapiti": ToolSpec(
        name="wapiti", binary="wapiti", description="Web application vulnerability scanner with a crawl engine",
        params={"url": None}, timeout=900,
        builder=lambda p: ["wapiti", "-u", p["url"], "-f", "html"]),

    # ==================== MOBILE ====================
    "objection": ToolSpec(
        name="objection", binary="objection", description="Runtime mobile application exploration and frida gadget control",
        params={"device_id": None, "action": "explore"}, timeout=300,
        builder=lambda p: ["objection", "--id", p["device_id"], p["action"]]),

    # ==================== OSINT ====================
    "maigret": ToolSpec(
        name="maigret", binary="maigret", description="Username footprinting across hundreds of sites",
        params={"username": None, "limit": "100"}, timeout=300, risk_level="passive",
        builder=lambda p: ["maigret", "--no-recursion", "--limit", str(p["limit"]), p["username"]]),
    "phoneinfoga": ToolSpec(
        name="phoneinfoga", binary="phoneinfoga", description="Phone number OSINT and carrier intelligence",
        params={"number": None}, timeout=60, risk_level="passive",
        builder=lambda p: ["phoneinfoga", "scan", "-n", p["number"]]),

    # ==================== PAYLOADS ====================
    "hoaxshell": ToolSpec(
        name="hoaxshell", binary="python3", description="Generate a PowerShell reverse shell payload (hoaxshell.py)",
        params={"lhost": "127.0.0.1", "lport": "4444", "output": "/tmp/shell.ps1"}, timeout=60, risk_level="intrusive",
        builder=lambda p: ["python3", "hoaxshell.py", "-s", p["lhost"], "-p", p["lport"], "-o", p["output"]]),

    # ==================== PRIVILEGE ESCALATION ====================
    "traitor": ToolSpec(
        name="traitor", binary="traitor", description="Find and run local privilege escalation exploits",
        params={}, timeout=120, risk_level="passive",
        builder=lambda p: ["traitor", "--exploits"]),

    # ==================== NETWORK ====================
    "netdiscover": ToolSpec(
        name="netdiscover", binary="netdiscover", description="ARP-based live host discovery on a subnet",
        params={"range": None}, timeout=120,
        builder=lambda p: ["netdiscover", "-r", p["range"]]),
    "responder": ToolSpec(
        name="responder", binary="responder", description="LLMNR/NBT-NS/mDNS poisoning and credential recovery",
        params={"interface": None, "mode": "off"}, timeout=300, risk_level="intrusive",
        builder=lambda p: ["responder", "-I", p["interface"], "-v"] + (["-A"] if p["mode"] == "analyze" else [])),
    "snmpwalk": ToolSpec(
        name="snmpwalk", binary="snmpwalk", description="Enumerate SNMP MIB tree of a target",
        params={"host": None, "community": "public"}, timeout=120,
        builder=lambda p: ["snmpwalk", "-c", p["community"], "-v2c", p["host"]]),

    # ==================== WEB ====================
    "wafw00f": ToolSpec(
        name="wafw00f", binary="wafw00f", description="Detect Web Application Firewalls in front of a target",
        params={"url": None}, timeout=60, risk_level="passive",
        builder=lambda p: ["wafw00f", p["url"]]),
    "arjun": ToolSpec(
        name="arjun", binary="arjun", description="HTTP parameter discovery for web and API targets",
        params={"url": None, "method": "GET"}, timeout=600, category="api",
        builder=lambda p: ["arjun", "-u", p["url"], "-m", p["method"]]),

    # ==================== WEB: CRAWLING & CONTENT DISCOVERY ====================
    "katana_crawl": ToolSpec(
        name="katana_crawl", binary="katana", description="Web crawler with JS rendering",
        params={"url": None, "depth": 3}, timeout=300,
        builder=lambda p: ["katana", "-u", p["url"], "-silent", "-jc", "-d", str(p["depth"])]),
    "waybackurls": ToolSpec(
        name="waybackurls", binary="waybackurls", description="Historical URLs from the Wayback Machine",
        params={"domain": None}, timeout=60,
        builder=lambda p: ["waybackurls", p["domain"]]),
    "gau": ToolSpec(
        name="gau", binary="gau", description="Get all URLs from many archives",
        params={"domain": None}, timeout=120,
        builder=lambda p: ["gau", p["domain"]]),
    "paramspider": ToolSpec(
        name="paramspider", binary="paramspider", description="Parameter mining from web archives",
        params={"domain": None}, timeout=120,
        builder=lambda p: ["paramspider", "-d", p["domain"]]),
    "whatweb_scan": ToolSpec(
        name="whatweb_scan", binary="whatweb", description="Web technology identification",
        params={"url": None}, timeout=60,
        builder=lambda p: ["whatweb", p["url"]]),
    "feroxbuster": ToolSpec(
        name="feroxbuster", binary="feroxbuster", description="Recursive content discovery",
        params={"url": None, "wordlist": None, "extensions": "", "threads": 40}, timeout=600,
        builder=lambda p: ["feroxbuster", "-u", p["url"], "-w", p["wordlist"], "-q", "-t", str(p["threads"])] + (["-x", p["extensions"]] if p["extensions"] else [])),
    "dirsearch": ToolSpec(
        name="dirsearch", binary="dirsearch", description="Directory/file discovery",
        params={"url": None, "extensions": "php,asp,aspx,jsp,html,js", "threads": 40}, timeout=300,
        builder=lambda p: ["dirsearch", "-u", p["url"], "-e", p["extensions"], "--format", "plain", "-t", str(p["threads"])]),
    "linkfinder": ToolSpec(
        name="linkfinder", binary="linkfinder.py", description="Extract endpoints from JavaScript files",
        params={"url": None}, timeout=60,
        builder=lambda p: ["linkfinder.py", "-d", p["url"], "-o", "linkfinder.html"]),
    "corsy": ToolSpec(
        name="corsy", binary="corsy", description="CORS misconfiguration scanner",
        params={"url": None}, timeout=120,
        builder=lambda p: ["corsy", "-u", p["url"]]),
    "subjack": ToolSpec(
        name="subjack", binary="subjack", description="Subdomain takeover checker",
        params={"wordlist": None, "threads": 10}, timeout=600,
        builder=lambda p: ["subjack", "-w", p["wordlist"], "-t", str(p["threads"]), "-a"]),

    # ==================== WEB: TLS / INJECTION ====================
    "sslscan": ToolSpec(
        name="sslscan", binary="sslscan", description="SSL/TLS cipher suite enumeration",
        params={"host": None, "port": "443"}, timeout=120,
        builder=lambda p: ["sslscan", f"{p['host']}:{p['port']}"]),
    "sslyze": ToolSpec(
        name="sslyze", binary="sslyze", description="SSL/TLS configuration analyzer",
        params={"host": None}, timeout=300,
        builder=lambda p: ["sslyze", "--regular", p["host"]]),
    "tplmap": ToolSpec(
        name="tplmap", binary="tplmap", description="Server-side template injection tester",
        params={"url": None}, timeout=600,
        builder=lambda p: ["tplmap", "-u", p["url"]]),
    "nosqlmap": ToolSpec(
        name="nosqlmap", binary="nosqlmap", description="NoSQL injection tester",
        params={"url": None}, timeout=600,
        builder=lambda p: ["nosqlmap", "-u", p["url"], "--batch"]),
    "wfuzz": ToolSpec(
        name="wfuzz", binary="wfuzz", description="Web fuzzer",
        params={"url": None, "wordlist": None, "threads": 40}, timeout=600,
        builder=lambda p: ["wfuzz", "-u", p["url"].rstrip("/") + "/FUZZ", "-w", p["wordlist"], "--hc", "404", "-t", str(p["threads"])]),

    # ==================== NETWORK: CAPTURE & ENUMERATION ====================
    "tcpdump_capture": ToolSpec(
        name="tcpdump_capture", binary="tcpdump", description="Live packet capture",
        params={"interface": "any", "count": 100, "port": ""}, timeout=120, cacheable=False,
        builder=lambda p: ["tcpdump", "-i", p["interface"], "-c", str(p["count"])]
        + (["port", str(p["port"])] if p["port"] else []) + ["-w", "capture.pcap"]),
    "tshark_capture": ToolSpec(
        name="tshark_capture", binary="tshark", description="Live packet analysis",
        params={"interface": "any", "count": 100}, timeout=120, cacheable=False,
        builder=lambda p: ["tshark", "-i", p["interface"], "-c", str(p["count"])],
    ),
    "enum4linux_ng": ToolSpec(
        name="enum4linux_ng", binary="enum4linux-ng", description="SMB enumeration with user/group/share discovery",
        params={"host": None}, timeout=300,
        builder=lambda p: ["enum4linux-ng", "-A", p["host"]]),
    "netexec_smb": ToolSpec(
        name="netexec_smb", binary="netexec", description="SMB enumeration and validation",
        params={"host": None}, timeout=300,
        builder=lambda p: ["netexec", "smb", p["host"]]),
    "snmp_check": ToolSpec(
        name="snmp_check", binary="snmp-check", description="SNMP enumeration",
        params={"host": None}, timeout=120,
        builder=lambda p: ["snmp-check", p["host"]]),
    "dnsx": ToolSpec(
        name="dnsx", binary="dnsx", description="DNS resolver and probe",
        params={"domain": None}, timeout=60,
        builder=lambda p: ["dnsx", "-d", p["domain"], "-a", "-resp", "-silent"]),
    "naabu": ToolSpec(
        name="naabu", binary="naabu", description="Fast port scanner",
        params={"host": None, "rate": 1000}, timeout=300,
        builder=lambda p: ["naabu", "-host", p["host"], "-silent", "-rate", str(p["rate"])]),
    "dig_axfr": ToolSpec(
        name="dig_axfr", binary="dig", description="DNS zone transfer attempt",
        params={"domain": None}, timeout=30,
        builder=lambda p: ["dig", "AXFR", p["domain"], "+short"]),
    "impacket_psexec": ToolSpec(
        name="impacket_psexec", binary="psexec.py", description="Remote execution via SMB (impacket)",
        params={"host": None, "user": None, "password": "", "domain": ""}, timeout=600,
        builder=lambda p: ["psexec.py", f"{p['domain']}/{p['user']}:{p['password']}@{p['host']}"]),
    "evil_winrm": ToolSpec(
        name="evil_winrm", binary="evil-winrm", description="Windows Remote Management shell",
        params={"host": None, "user": None, "password": ""}, timeout=600,
        builder=lambda p: ["evil-winrm", "-i", p["host"], "-u", p["user"]]
        + (["-p", p["password"]] if p["password"] else [])),

    # ==================== OSINT ====================
    "theharvester": ToolSpec(
        name="theharvester", binary="theharvester", description="Email and subdomain harvesting",
        params={"domain": None}, timeout=300,
        builder=lambda p: ["theharvester", "-d", p["domain"], "-b", "all"]),
    "shodan_search": ToolSpec(
        name="shodan_search", binary="shodan", description="Shodan device search",
        params={"query": None}, timeout=60,
        builder=lambda p: ["shodan", "search", p["query"]]),
    "censys_search": ToolSpec(
        name="censys_search", binary="censys", description="Censys asset search",
        params={"query": None}, timeout=60,
        builder=lambda p: ["censys", "search", p["query"]]),
    "crt_sh": ToolSpec(
        name="crt_sh", binary="curl", description="Certificate transparency log search (crt.sh)",
        params={"domain": None}, timeout=60,
        builder=lambda p: ["curl", "-s", "--max-time", "25", f"https://crt.sh/?q=%25.{p['domain']}&output=json"]),

    # ==================== CLOUD & CONTAINER ====================
    "prowler": ToolSpec(
        name="prowler", binary="prowler", description="AWS security assessment with compliance checks",
        params={"profile": ""}, timeout=1200,
        builder=lambda p: ["prowler", "aws"] + (["-p", p["profile"]] if p["profile"] else []) + ["--quiet"]),
    "scoutsuite": ToolSpec(
        name="scoutsuite", binary="scout", description="Multi-cloud security auditing",
        params={"provider": "aws"}, timeout=1200,
        builder=lambda p: ["scout", p["provider"]]),
    "aws_list_ec2": ToolSpec(
        name="aws_list_ec2", binary="aws", description="List EC2 instances",
        params={}, timeout=60,
        builder=lambda p: ["aws", "ec2", "describe-instances", "--output", "json"]),
    "gcloud_projects_list": ToolSpec(
        name="gcloud_projects_list", binary="gcloud", description="List GCP projects",
        params={}, timeout=60,
        builder=lambda p: ["gcloud", "projects", "list"]),
    "azure_account_list": ToolSpec(
        name="azure_account_list", binary="az", description="List Azure subscriptions",
        params={}, timeout=60,
        builder=lambda p: ["az", "account", "list", "--output", "json"]),
    "kubectl_get_services": ToolSpec(
        name="kubectl_get_services", binary="kubectl", description="List Kubernetes services",
        params={}, timeout=60,
        builder=lambda p: ["kubectl", "get", "services", "-o", "wide"]),
    "kubectl_get_deployments": ToolSpec(
        name="kubectl_get_deployments", binary="kubectl", description="List Kubernetes deployments",
        params={}, timeout=60,
        builder=lambda p: ["kubectl", "get", "deployments", "-o", "wide"]),
    "docker_network_ls": ToolSpec(
        name="docker_network_ls", binary="docker", description="List Docker networks",
        params={}, timeout=60,
        builder=lambda p: ["docker", "network", "ls"]),

    # ==================== CODE & SUPPLY CHAIN ====================
    "bandit": ToolSpec(
        name="bandit", binary="bandit", description="Python security linter",
        params={"path": None}, timeout=300,
        builder=lambda p: ["bandit", "-r", p["path"], "-f", "json"]),
    "detect_secrets": ToolSpec(
        name="detect_secrets", binary="detect-secrets", description="Secret scanning for git repos",
        params={"path": None}, timeout=120,
        builder=lambda p: ["detect-secrets", "scan", p["path"]]),
    "pip_audit": ToolSpec(
        name="pip_audit", binary="pip-audit", description="Python dependency vulnerability audit",
        params={"path": "requirements.txt"}, timeout=300,
        builder=lambda p: ["pip-audit", "-r", p["path"], "-f", "json"]),

    # ==================== API SECURITY ====================
    "jwt_tool": ToolSpec(
        name="jwt_tool", binary="jwt_tool", description="JWT testing toolkit",
        params={"token": None, "url": ""}, timeout=300,
        builder=lambda p: ["jwt_tool", p["token"]] + (["-t", p["url"]] if p["url"] else [])),
    "kiterunner": ToolSpec(
        name="kiterunner", binary="kr", description="API endpoint discovery",
        params={"url": None, "wordlist": None}, timeout=600,
        builder=lambda p: ["kr", "scan", p["url"], "-w", p["wordlist"]]),

    # ==================== MOBILE ====================
    "androguard": ToolSpec(
        name="androguard", binary="androguard", description="Android APK analysis",
        params={"file": None}, timeout=120,
        builder=lambda p: ["androguard", "axml", p["file"]]),

    # ==================== PRIVESC ====================
    "suid_find": ToolSpec(
        name="suid_find", binary="find", description="Find SUID binaries on the host",
        params={}, timeout=120,
        builder=lambda p: ["find", "/", "-perm", "-4000", "-type", "f", "-exec", "ls", "-l", "{}", "+"]),

    # ==================== FORENSICS ====================
    "bulk_extractor": ToolSpec(
        name="bulk_extractor", binary="bulk_extractor", description="Digital forensics feature extraction",
        params={"image": None}, timeout=600,
        builder=lambda p: ["bulk_extractor", "-o", "bulk_extractor_out", p["image"]]),
    "strings_extract": ToolSpec(
        name="strings_extract", binary="strings", description="Extract printable strings from a binary",
        params={"file": None}, timeout=60,
        builder=lambda p: ["strings", "-n", "6", p["file"]]),
    "pdf2txt": ToolSpec(
        name="pdf2txt", binary="pdf2txt.py", description="Extract text from PDF files",
        params={"file": None}, timeout=120,
        builder=lambda p: ["pdf2txt.py", p["file"]]),

    # ==================== BROWSER AGENT ====================
    "browser_crawl": ToolSpec(
        name="browser_crawl", binary="python", description="Headless browser crawl: DOM, JS runtime, screenshots",
        params={"url": None, "wait": 3, "screenshot": False, "dom_depth": 0}, timeout=120,
        category="web", parser="browser_json", availability_check=browser_engine_available,
        builder=lambda p: ["python", "-m", "nexhunter.agents.browser_cli", "-u", p["url"], "--wait", str(p["wait"])]
        + (["--screenshot"] if p["screenshot"] else [])
        + (["--dom-depth", str(p["dom_depth"])] if p["dom_depth"] else [])),

    # ==================== WEB: TECH & HOST DISCOVERY ====================
    "webanalyze": ToolSpec(
        name="webanalyze", binary="webanalyze", description="Website technology fingerprinting",
        params={"host": None, "update": False}, timeout=120,
        builder=lambda p: (["webanalyze", "-update"] if p["update"] else ["webanalyze", "-host", p["host"]])),
    "dnsrecon": ToolSpec(
        name="dnsrecon", binary="dnsrecon", description="DNS reconnaissance and zone enumeration",
        params={"domain": None}, timeout=300,
        builder=lambda p: ["dnsrecon", "-d", p["domain"], "-t", "std", "-j", "dnsrecon.json"]),
    "fping": ToolSpec(
        name="fping", binary="fping", description="Fast ICMP host discovery across a subnet",
        params={"subnet": None}, timeout=120,
        builder=lambda p: ["fping", "-a", "-g", p["subnet"]]),
    "osv_scanner": ToolSpec(
        name="osv_scanner", binary="osv-scanner", description="OSV vulnerability scanner for dependency manifests",
        params={"path": None}, timeout=300,
        builder=lambda p: ["osv-scanner", "-r", p["path"]]),
}

def _parse_nmap_xml(text):
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    hosts = []
    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue
        entry = {"addr": addr.get("addr"), "ports": []}
        for p in host.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = p.find("service")
            entry["ports"].append(
                {
                    "port": p.get("portid"),
                    "proto": p.get("protocol"),
                    "service": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                }
            )
        hosts.append(entry)
    return hosts


def _parse_jsonl(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _parse_httpx(text):
    return [
        {"url": e.get("url"), "status": e.get("status_code"), "title": e.get("title"), "tech": e.get("tech")}
        for e in _parse_jsonl(text)
    ]


def _parse_nuclei(text):
    return [
        {
            "template": e.get("template-id"),
            "name": e.get("info", {}).get("name"),
            "severity": e.get("info", {}).get("severity"),
            "matched": e.get("matched-at"),
            "description": e.get("info", {}).get("description", ""),
        }
        for e in _parse_jsonl(text)
    ]


def _parse_browser_json(text):
    """Parse the browser agent's single-JSON-document output."""
    try:
        return [json.loads(text)]
    except json.JSONDecodeError:
        return []


PARSERS = {
    "nmap_xml": _parse_nmap_xml,
    "httpx": _parse_httpx,
    "nuclei": _parse_nuclei,
    "browser_json": _parse_browser_json,
}

TOOLS = _tool_specs


def get_tool_spec(name: str) -> ToolSpec | None:
    """Get tool specification by name."""
    return TOOLS.get(name)


def risk_of(name: str) -> str:
    """Return the risk level string for a registered tool (default 'active')."""
    spec = TOOLS.get(name)
    return spec.risk_level if spec else "active"


def parse_output(tool: str, text: str):
    """Parse tool output using registered parser."""
    spec = get_tool_spec(tool)
    if not spec or not spec.parser:
        spec = next((s for s in TOOLS.values() if s.parser == tool), None)
    if spec and spec.parser:
        parser = PARSERS.get(spec.parser)
        return parser(text) if parser else None
    return None


def run(cmd: list, timeout: int) -> dict:
    """Run command subprocess with timeout handling."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return {"ok": r.returncode == 0, "exit": r.returncode, "stdout": r.stdout, "stderr": r.stderr, "error": None}
    except FileNotFoundError:
        return {"ok": False, "exit": -1, "stdout": "", "stderr": "", "error": f"binary '{cmd[0]}' not found on PATH"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "exit": -1, "stdout": "", "stderr": "", "error": f"timed out after {timeout}s"}


def which(bin_name: str) -> str | None:
    """Check if binary exists in PATH."""
    return shutil.which(bin_name)
