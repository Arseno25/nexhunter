"""nexhunter.tools - 150+ security tools registry with ToolSpec pattern."""

import json
import shutil
import subprocess
from defusedxml import ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, Optional, Dict, Any

from nexhunter.core.config import TOOL_TIMEOUTS, DEFAULT_TOOL_TIMEOUT


@dataclass
class ToolSpec:
    """Tool specification with validation and execution."""

    name: str
    binary: str
    description: str
    params: Dict[str, Any]
    timeout: int = DEFAULT_TOOL_TIMEOUT
    parser: Optional[str] = None
    builder: Optional[Callable] = None

    def __post_init__(self):
        if self.timeout == DEFAULT_TOOL_TIMEOUT and self.name in TOOL_TIMEOUTS:
            self.timeout = TOOL_TIMEOUTS[self.name]

    def validate(self, user_params: dict) -> tuple[bool, Optional[str]]:
        """Validate user params against spec. Return (ok, error_msg)."""
        missing = [k for k, v in self.params.items() if v is None and k not in user_params]
        if missing:
            return False, f"missing required: {', '.join(missing)}"
        return True, None

    def build_cmd(self, user_params: dict) -> Optional[list]:
        """Build command from spec and params."""
        ok, err = self.validate(user_params)
        if not ok:
            return None
        if self.builder:
            return self.builder(user_params)
        return None


_tool_specs = {
    # ==================== RECONNAISSANCE (OSINT) ====================
    "nmap_scan": ToolSpec(
        name="nmap_scan", binary="nmap", description="Port/service discovery",
        params={"target": None, "ports": ""}, timeout=300,
        builder=lambda p: ["nmap", "-sV", "-T4", "-oX", "-"] + (["-p", p["ports"]] if p["ports"] else []) + [p["target"]]),
    "masscan": ToolSpec(
        name="masscan", binary="masscan", description="Fast port scanner",
        params={"target": None, "ports": "1-65535"}, timeout=600,
        builder=lambda p: ["masscan", p["target"], "-p", p["ports"], "-oG", "-"]),
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
        params={"target": None}, timeout=300,
        builder=lambda p: ["nuclei", "-u", p["target"], "-silent", "-jsonl"]),
    "ffuf_scan": ToolSpec(
        name="ffuf_scan", binary="ffuf", description="Web content fuzzer",
        params={"target": None, "wordlist": None, "filter_status": ""}, timeout=300,
        builder=lambda p: ["ffuf", "-u", p["target"].rstrip("/") + "/FUZZ", "-w", p["wordlist"]] + (["-fs", p["filter_status"]] if p["filter_status"] else [])),
    "gobuster_dir": ToolSpec(
        name="gobuster_dir", binary="gobuster", description="Directory brute force",
        params={"target": None, "wordlist": None}, timeout=300,
        builder=lambda p: ["gobuster", "dir", "-u", p["target"], "-w", p["wordlist"]]),
    "gobuster_dns": ToolSpec(
        name="gobuster_dns", binary="gobuster", description="DNS subdomain brute force",
        params={"domain": None, "wordlist": None}, timeout=300,
        builder=lambda p: ["gobuster", "dns", "-d", p["domain"], "-w", p["wordlist"]]),
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
        params={"url": None}, timeout=300,
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
        params={"file": None}, timeout=10,
        builder=lambda p: ["nm", p["file"]]),
    "ldd": ToolSpec(
        name="ldd", binary="ldd", description="List dynamic dependencies",
        params={"file": None}, timeout=10,
        builder=lambda p: ["ldd", p["file"]]),
    "gdb": ToolSpec(
        name="gdb", binary="gdb", description="GNU debugger",
        params={"file": None}, timeout=60,
        builder=lambda p: ["gdb", "-batch", "-ex", "info functions", p["file"]]),
    "strace": ToolSpec(
        name="strace", binary="strace", description="System call tracer",
        params={"command": None}, timeout=30,
        builder=lambda p: ["strace", "-e", "trace=all", p["command"]]),
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
        params={}, timeout=10,
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
        params={"interface": None}, timeout=30,
        builder=lambda p: ["airodump-ng", p["interface"]]),
    "aireplay": ToolSpec(
        name="aireplay", binary="aireplay-ng", description="Wireless network traffic injector",
        params={"interface": None}, timeout=30,
        builder=lambda p: ["aireplay-ng", "-h", p["interface"]]),
    "aircrack": ToolSpec(
        name="aircrack", binary="aircrack-ng", description="WEP/WPA password cracker",
        params={"capfile": None}, timeout=600,
        builder=lambda p: ["aircrack-ng", p["capfile"]]),
    "tcpdump": ToolSpec(
        name="tcpdump", binary="tcpdump", description="Packet sniffer",
        params={"interface": "any"}, timeout=30,
        builder=lambda p: ["tcpdump", "-i", p["interface"], "-n", "-l"]),
    "tshark": ToolSpec(
        name="tshark", binary="tshark", description="Wireshark command-line packet analyzer",
        params={"interface": "any"}, timeout=30,
        builder=lambda p: ["tshark", "-i", p["interface"]]),

    # ==================== VULNERABILITY DATABASES ====================
    "searchsploit": ToolSpec(
        name="searchsploit", binary="searchsploit", description="Search exploit database",
        params={"query": None}, timeout=10,
        builder=lambda p: ["searchsploit", p["query"]]),
    "cve_search": ToolSpec(
        name="cve_search", binary="cve_search", description="Search CVE database",
        params={"query": None}, timeout=30,
        builder=lambda p: ["cve_search", p["query"]]),

    # ==================== CONTAINER & CLOUD ====================
    "docker": ToolSpec(
        name="docker", binary="docker", description="Docker container tool",
        params={"command": "ps"}, timeout=30,
        builder=lambda p: ["docker", p["command"]]),
    "kubectl": ToolSpec(
        name="kubectl", binary="kubectl", description="Kubernetes client",
        params={"command": "get pods"}, timeout=30,
        builder=lambda p: ["kubectl", p["command"]]),
    "aws_cli": ToolSpec(
        name="aws_cli", binary="aws", description="AWS CLI",
        params={"command": "s3 ls"}, timeout=60,
        builder=lambda p: ["aws"] + p["command"].split()),
    "gcloud": ToolSpec(
        name="gcloud", binary="gcloud", description="Google Cloud CLI",
        params={"command": "compute instances list"}, timeout=60,
        builder=lambda p: ["gcloud"] + p["command"].split()),
    "az": ToolSpec(
        name="az", binary="az", description="Azure CLI",
        params={"command": "account show"}, timeout=30,
        builder=lambda p: ["az"] + p["command"].split()),
    "trivy": ToolSpec(
        name="trivy", binary="trivy", description="Container vulnerability scanner",
        params={"image": None}, timeout=300,
        builder=lambda p: ["trivy", "image", p["image"]]),
    "grype": ToolSpec(
        name="grype", binary="grype", description="Vulnerability scanner for containers",
        params={"image": None}, timeout=300,
        builder=lambda p: ["grype", p["image"]]),

    # ==================== MOBILE SECURITY ====================
    "adb": ToolSpec(
        name="adb", binary="adb", description="Android Debug Bridge",
        params={"command": "devices"}, timeout=30,
        builder=lambda p: ["adb"] + p["command"].split()),
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
    "bandit": ToolSpec(
        name="bandit", binary="bandit", description="Python security linter",
        params={"file": None}, timeout=60,
        builder=lambda p: ["bandit", "-r", p["file"]]),
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
    "pdf2txt": ToolSpec(
        name="pdf2txt", binary="pdftotext", description="Extract text from PDF",
        params={"file": None}, timeout=30,
        builder=lambda p: ["pdftotext", p["file"], "-"]),
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
        params={"target": None}, timeout=300,
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
    "theharwest": ToolSpec(
        name="theharwest", binary="theharwest", description="Domain recon tool",
        params={"domain": None}, timeout=60,
        builder=lambda p: ["theharwest", p["domain"]]),

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
    "sliver": ToolSpec(
        name="sliver", binary="sliver", description="C2 framework",
        params={"command": "help"}, timeout=30,
        builder=lambda p: ["sliver"] + p["command"].split()),

    # ==================== DEPENDENCY SCANNING ====================
    "npm_audit": ToolSpec(
        name="npm_audit", binary="npm", description="NPM dependency vulnerability audit",
        params={"path": "."}, timeout=60,
        builder=lambda p: ["npm", "audit", "--json"]),
    "pip_audit": ToolSpec(
        name="pip_audit", binary="pip-audit", description="Python dependency checker",
        params={"path": "."}, timeout=60,
        builder=lambda p: ["pip-audit", "-r", p["path"] + "/requirements.txt"]),
    "safety": ToolSpec(
        name="safety", binary="safety", description="Python security vulnerability scanner",
        params={"file": "requirements.txt"}, timeout=30,
        builder=lambda p: ["safety", "check", "-r", p["file"]]),
    "snyk": ToolSpec(
        name="snyk", binary="snyk", description="Developer security platform",
        params={"command": "test"}, timeout=120,
        builder=lambda p: ["snyk"] + p["command"].split()),
    "owasp_dependency_check": ToolSpec(
        name="owasp_dependency_check", binary="dependency-check", description="OWASP dependency analyzer",
        params={"path": "."}, timeout=300,
        builder=lambda p: ["dependency-check", "-scan", p["path"]]),

    # ==================== SECRET DETECTION ====================
    "trufflehog": ToolSpec(
        name="trufflehog", binary="truffleHog", description="Detect secrets in git history",
        params={"repo": None}, timeout=300,
        builder=lambda p: ["truffleHog", "git", p["repo"]]),
    "detect_secrets": ToolSpec(
        name="detect_secrets", binary="detect-secrets", description="Secrets detector",
        params={"path": "."}, timeout=60,
        builder=lambda p: ["detect-secrets", "scan", p["path"]]),
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
        name="linpeas", binary="linpeas.sh", description="Linux privilege escalation tool",
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
        name="regripper", binary="rip", description="Windows registry extraction",
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
    "shodan_cli": ToolSpec(
        name="shodan_cli", binary="shodan", description="Shodan CLI interface",
        params={"command": "help"}, timeout=30,
        builder=lambda p: ["shodan"] + p["command"].split()),
    "metasploit_payload": ToolSpec(
        name="metasploit_payload", binary="msfvenom", description="Generate MSF payloads",
        params={"lhost": "127.0.0.1", "lport": "4444"}, timeout=30,
        builder=lambda p: ["msfvenom", "-p", "windows/shell_reverse_tcp", "LHOST=" + p["lhost"], "LPORT=" + p["lport"]]),
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


PARSERS = {
    "nmap_xml": _parse_nmap_xml,
    "httpx": _parse_httpx,
    "nuclei": _parse_nuclei,
}

TOOLS = _tool_specs


def get_tool_spec(name: str) -> Optional[ToolSpec]:
    """Get tool specification by name."""
    return TOOLS.get(name)


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


def which(bin_name: str) -> Optional[str]:
    """Check if binary exists in PATH."""
    return shutil.which(bin_name)
