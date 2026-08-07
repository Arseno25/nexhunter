"""nexhunter.core.tools - security tools registry with ToolSpec pattern."""

import importlib.util
from dataclasses import dataclass
from typing import Any
from collections.abc import Callable

from nexhunter.core.config import TOOL_TIMEOUTS, DEFAULT_TOOL_TIMEOUT

from ._runtime import which
from nexhunter.core import params as P


# Risk classification by keyword in tool name or binary. First match wins,
# checked most-dangerous first. Anything unmatched defaults to "active".
# ponytail: keyword heuristic over 164 tools; override per-tool via
# ToolSpec(risk_level=...) when a specific tool is misclassified.
_RISK_KEYWORDS = [
    ("destructive", ("wipe", "destroy", "format", "deauth", "aireplay", "flood")),
    (
        "intrusive",
        (
            "sqlmap",
            "hydra",
            "john",
            "hashcat",
            "medusa",
            "ncrack",
            "brute",
            "gobuster",
            "ffuf",
            "dirb",
            "wfuzz",
            "nikto",
            "wpscan",
            "metasploit",
            "msf",
            "exploit",
            "dalfox",
            "commix",
            "xsstrike",
            "crackmap",
            "responder",
            "slowhttp",
            "hping",
            "dos",
            "netexec",
            "psexec",
            "winrm",
            "tplmap",
            "nosqlmap",
        ),
    ),
    (
        "passive",
        (
            "whois",
            "dig",
            "nslookup",
            "host_lookup",
            "subfinder",
            "amass",
            "assetfinder",
            "dnsx",
            "waybackurls",
            "gau",
            "crt",
            "shodan",
            "censys",
            "theharvester",
            "sublist3r",
            "findomain",
            "cero",
            "recon",
        ),
    ),
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
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    "chrome",
    "chrome.exe",
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
    from nexhunter.core import tools as _tools_pkg

    if importlib.util.find_spec("selenium") is None:
        return False
    return any(_tools_pkg.which(binary) for binary in _CHROME_BINARIES)


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
    (
        "code",
        (
            "semgrep",
            "bandit",
            "pylint",
            "sonar",
            "checkmarx",
            "gitleaks",
            "trufflehog",
            "snyk",
            "dependency",
            "retire",
            "safety",
            "npm_audit",
            "pip_audit",
            "checkov",
            "tfsec",
            "gitrob",
            "detect_secrets",
            "secret",
            "audit",
            "osv",
        ),
    ),
    ("container", ("docker", "kubectl", "kube", "trivy", "clair", "grype", "helm", "podman", "container", "falco")),
    (
        "cloud",
        ("aws", "gcloud", "azure", "prowler", "scoutsuite", "cloudsplaining", "s3", "cloudmapper", "pacu", "steampipe"),
    ),
    (
        "forensics",
        (
            "volatility",
            "sleuthkit",
            "autopsy",
            "binwalk",
            "exiftool",
            "foremost",
            "bulk_extractor",
            "plaso",
            "yara",
            "capa",
            "regripper",
            "pdf2txt",
            "steghide",
            "zsteg",
            "pngcheck",
            "fcrackzip",
        ),
    ),
    (
        "binary",
        (
            "ghidra",
            "radare",
            "r2",
            "objdump",
            "readelf",
            "checksec",
            "gdb",
            "strings",
            "ropgadget",
            "pwntools",
            "angr",
            "cutter",
            "ida",
        ),
    ),
    (
        "auth",
        ("hydra", "john", "hashcat", "medusa", "ncrack", "patator", "hashid", "netexec", "crackmap", "winrm"),
    ),
    ("crypto", ("openssl", "testssl", "sslscan", "sslyze", "cipher")),
    ("ctf", ("xortool", "rsactf", "pwninit", "ctf")),
    ("api", ("graphql", "swagger", "openapi", "postman", "arjun", "kiterunner", "insomnia", "jwt")),
    (
        "web",
        (
            "nuclei",
            "ffuf",
            "gobuster",
            "nikto",
            "sqlmap",
            "dalfox",
            "wpscan",
            "joomscan",
            "drupscan",
            "zap",
            "burp",
            "httpx",
            "katana",
            "whatweb",
            "wafw00f",
            "xsstrike",
            "commix",
            "feroxbuster",
            "dirsearch",
            "curl",
            "hakrawler",
            "gau",
            "waybackurls",
            "http",
            "paramspider",
            "linkfinder",
            "corsy",
            "subjack",
            "tplmap",
            "nosqlmap",
            "wfuzz",
            "webanalyze",
        ),
    ),
    (
        "recon",
        (
            "nmap",
            "masscan",
            "rustscan",
            "subfinder",
            "amass",
            "assetfinder",
            "dns",
            "whois",
            "shodan",
            "censys",
            "theharvester",
            "recon",
            "fierce",
            "dnsx",
            "naabu",
            "host",
            "nslookup",
            "sublist3r",
            "dig",
            "axfr",
            "crt",
            "dnsrecon",
            "fping",
        ),
    ),
    (
        "osint",
        (
            "maltego",
            "spiderfoot",
            "zoomeye",
            "cve_search",
            "nist_tool",
            "searchsploit",
            "theharwest",
            "sherlock",
            "holehe",
            "osint",
            "maigret",
            "phoneinfoga",
        ),
    ),
    ("wireless", ("aireplay", "airodump", "aircrack", "wifite", "reaver", "kismet", "airgeddon", "mdk4", "bettercap")),
    (
        "network",
        (
            "tcpdump",
            "tshark",
            "wireshark",
            "enum4linux",
            "smbmap",
            "smbclient",
            "rpcclient",
            "ldapsearch",
            "snmp",
            "responder",
            "impacket",
            "arp",
            "netcat",
            "socat",
            "tun2socks",
            "netdiscover",
            "snmpcheck",
        ),
    ),
    (
        "privesc",
        (
            "linpeas",
            "winpeas",
            "pspy",
            "peas",
            "dirty_cow",
            "privesc",
            "exploit_suggester",
            "linux_exploit",
            "traitor",
            "suid",
        ),
    ),
    (
        "payloads",
        (
            "veil",
            "unicorn",
            "chimera",
            "evasion",
            "phishing",
            "social_engineer",
            "payload",
            "mimikatz",
            "beef",
            "hoaxshell",
        ),
    ),
    ("ids", ("snort", "suricata", "zeek", "ossec", "wazuh")),
    ("vuln_scan", ("nessus", "openvas", "qualys", "w3af", "gvm", "vulners", "arachni", "skipfish", "wapiti")),
    (
        "exploitation",
        ("metasploit", "msf", "empire", "cobalt", "havoc", "sliver", "exploit"),
    ),
    ("mobile", ("apktool", "jadx", "frida", "objection", "mobsf", "androguard")),
    (
        "utility",
        (
            "awk",
            "sed",
            "grep",
            "jq",
            "yq",
            "tar",
            "zip",
            "xxd",
            "hexdump",
            "ldd",
            "ltrace",
            "rsync",
            "netstat",
            "mtr",
            "traceroute",
            "nping",
            "wget",
            "strings",
            "file_type",
            "ping",
        ),
    ),
)

# Maturity is asserted per tool, never guessed: claiming a tool is "stable"
# without a parser, a fixture, and a test is exactly the kind of unverified
# claim this project is meant to stop making. Anything not listed is beta.
STABLE_TOOLS = frozenset(
    {
        "nmap_scan",
        "httpx_probe",
        "nuclei_scan",
        "subfinder_enum",
        "dns_lookup",
        "whois_lookup",
        "curl_headers",
        "nikto_scan",
        "ffuf_scan",
        "gobuster_dir",
        "gobuster_dns",
        "amass_enum",
        "assetfinder",
        "host_lookup",
        "nslookup",
        "wpscan_scan",
        "semgrep",
        "trivy",
        "testssl",
        "aws_get_caller_identity",
        "aws_list_s3_buckets",
        "kubectl_get_pods",
        "kubectl_get_namespaces",
        "docker_list_containers",
        # Line/JSON output tools with parsers and tests (see tests/test_tool_parsers.py).
        "katana_crawl",
        "gau",
        "waybackurls",
        "naabu",
        "dnsx",
    }
)

# Registered but not honestly usable as written, so they are not counted as a
# working capability and drop out of the focused profiles (they remain only in
# nexhunter-full). Two kinds live here:
#   * invented/placeholder binaries whose CLI does not exist as invoked, or
#     GUI/framework tools that cannot run as a one-shot command line;
#   * builders with hardcoded stand-in arguments (a fixed username/wordlist, a
#     local script path) that are demos, not real invocations.
# Promoting one out of here means giving it a real builder, a parser, and a test.
EXPERIMENTAL_TOOLS = frozenset(
    {
        # invented / non-existent binaries
        "cve_search",
        "nist_tool",
        "qualys",
        "censys",
        "zoomeye",
        "chimera",
        "unicorn",
        # real tools, but not invocable as a single one-shot command as wired
        "maltego",
        "spiderfoot",
        "w3af",
        "beef",
        "empire",
        "cobalt_strike",
        "havoc",
        "veil",
        "evasion",
        "social_engineer_toolkit",
        "phishing_framework",
        "empire_persistence",
        # builders with hardcoded stand-in arguments (canned demos, not real runs)
        "hydra",
        "linpeas",
        "dirty_cow",
    }
)


def _infer_category(name: str, binary: str) -> str:
    """Infer a tool's category from its name and binary."""
    hay = f"{name} {binary}".lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(kw in hay for kw in keywords):
            return category
    return "other"


class ShellCommand(str):
    """A command string that must run through the OS shell.

    A builder returns this instead of an argv list to ask for shell semantics
    (metacharacters live: pipes, redirects, chaining). The ProcessRunner is
    the only place that honors it; every other builder output stays argv-only.
    No ToolSpec flag exists -- the execution mode is part of the builder's
    output contract, the same way the argv itself is.
    """


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
            if self.name in STABLE_TOOLS:
                self.maturity = "stable"
            elif self.name in EXPERIMENTAL_TOOLS:
                self.maturity = "experimental"
            else:
                self.maturity = "beta"
        if self.param_specs is None:
            self.param_specs = tuple(P.spec_from_legacy(key, default) for key, default in self.params.items())

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
            "parameters": {spec.name: spec.describe() for spec in (self.param_specs or ())},
            "target_param": self.target_param,
            "available": self.available,
        }

    def target_of(self, params: dict) -> str:
        """Extract the scope target value from params."""
        if self.target_param and self.target_param in params:
            return str(params[self.target_param] or "")
        return ""

    def validate(self, user_params: dict) -> tuple[bool, str | None]:
        """Validate user params against the typed schema. Return (ok, error).

        Unknown parameters are silently dropped: the builder only uses declared
        params, so an extra key (e.g. 'severity' from an orchestrator that
        applies it to all tools) cannot change what the command does and should
        not block the run. Required missing params still fail.
        """
        _, error = P.validate_params(self.param_specs or (), user_params or {}, reject_unknown=False)
        return (error is None), error

    def normalize(self, user_params: dict) -> tuple[dict | None, str | None]:
        """Validate and return normalized values, or an error.

        Command builders receive the normalized values so a builder never sees
        a raw caller-supplied string. Unknown keys are dropped: the builder only
        reads declared params, so an extra callers-side key cannot affect
        what the command does.
        """
        return P.validate_params(self.param_specs or (), user_params or {}, reject_unknown=False)

    def build_cmd(self, user_params: dict) -> list | ShellCommand | None:
        """Build the command from validated parameters.

        The output is the builder's contract: an argv list by default, or a
        ShellCommand string when the tool's whole payload must run through the
        OS shell (execute_command). Anything else is None (build refused).
        """
        normalized, error = self.normalize(user_params)
        if error is not None or not self.builder:
            return None
        return self.builder(normalized)
