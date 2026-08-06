"""Profile-aware parameter optimization.

The selector decides *which* tools to run; this decides *how*. A tool is only
useful if it is invoked correctly -- a subdomain enumerator wants a bare
hostname, a web scanner wants a URL, a content brute-forcer needs a wordlist
that actually exists on disk. Feeding every tool the raw run target (e.g.
"https://example.com" into a hostname-typed `domain` parameter) is exactly why
tools were being rejected before they ever ran.

For each parameter a tool declares, this derives the right value from the run
target and the observed profile:

    hostname/domain  -> the bare host, scheme and path stripped
    url/endpoint     -> a full URL with a scheme
    target           -> a URL for web tools, a host/IP for scanners
    ports            -> the web ports when a web surface is in evidence
    wordlist         -> an installed wordlist (dir- or dns-oriented)

Anything it cannot sensibly fill (a hash file, a capture, a binary) is left
alone, so a tool that genuinely needs an operator-supplied artifact still says
so rather than running on a guess.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any
from urllib.parse import urlparse

from nexhunter.core.params import ParamType
from nexhunter.core.tools import ToolSpec
from nexhunter.agents.profiler import TargetProfile


# Candidate wordlists, most-preferred first. The first that exists on the host
# wins; if none do, the parameter is left unset and the tool reports it missing.
_DIR_WORDLISTS = (
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirb/big.txt",
)
_DNS_WORDLISTS = (
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
    "/usr/share/wordlists/dnsmap.txt",
    "/usr/share/seclists/Discovery/DNS/namelist.txt",
)

# Web ports worth scanning when the target is a web surface -- faster and more
# relevant than nmap's default sweep.
_WEB_PORTS = "80,443,8080,8443,8000"

# Tools whose TARGET-typed parameter wants a host/IP, not a URL (port scanners).
_SCANNER_CATEGORIES = {"recon", "network"}

# File/directory/interface modalities: the target IS the artifact under study.
_FILE_MODALITIES = {"binary", "mobile", "forensics"}
_FILE_NAMES = {"apk", "pcap", "dump", "image", "capfile", "capture_file",
               "public_key", "hashfile", "image_file", "hashes", "capture"}
_DIR_NAMES = {"path", "project", "source", "directory", "dir", "folder"}

# Objective -> execution posture. These feed the tunable knobs (nmap timing,
# nuclei severity floor, brute-force threads) so the same tool runs slow and
# quiet under stealth, or fast and thorough under comprehensive.
_OBJECTIVE_TUNING = {
    "stealth":       {"timing": "2", "threads": 10, "severity": "critical,high",       "rate": 150,   "depth": 1},
    "quick":         {"timing": "4", "threads": 40, "severity": "critical,high",        "rate": 1000,  "depth": 2},
    "standard":      {"timing": "4", "threads": 40, "severity": "critical,high,medium", "rate": 1500,  "depth": 3},
    "comprehensive": {"timing": "5", "threads": 60, "severity": "",                     "rate": 10000, "depth": 5},
}

# Detected technology -> the file extensions worth brute-forcing for. Mirrors
# what an operator would pick by hand; the first stack that matches wins.
_TECH_EXTENSIONS = (
    (("php",), "php,html,txt"),
    (("asp", "aspnet", "dotnet", ".net", "iis"), "asp,aspx,html,txt"),
    (("java", "tomcat", "jsp", "jboss"), "jsp,html,txt"),
    (("node", "express"), "js,json,html,txt"),
)
_DEFAULT_EXTENSIONS = "php,html,txt,js"


def _first_existing(paths) -> str | None:
    for path in paths:
        if os.path.isfile(path):
            return path
    return None


def _hostname(target: str) -> str:
    """Bare hostname (or IP) from a URL, host:port, or plain host."""
    text = (target or "").strip()
    if not text:
        return text
    if "://" in text:
        host = urlparse(text).hostname
        if host:
            return host
    # No scheme: let urlparse read the authority, falling back to a manual split.
    host = urlparse(f"//{text}").hostname
    if host:
        return host
    return text.split("/")[0].split(":")[0]


def _as_url(target: str) -> str:
    """A full URL. Keeps an existing scheme; defaults to https otherwise."""
    text = (target or "").strip()
    if "://" in text:
        return text
    return f"https://{text}"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


class ParameterOptimizer:
    """Turn a target + profile into the parameters a tool should actually run with."""

    def optimize(
        self,
        spec: ToolSpec,
        target: str,
        profile: TargetProfile | None = None,
        objective: str = "standard",
    ) -> dict[str, Any]:
        """Return tuned parameters for one tool. Only fills what it can justify."""
        params: dict[str, Any] = {}
        for pspec in spec.param_specs or ():
            value = self._value_for(pspec, spec, target, profile, objective)
            if value is not None:
                params[pspec.name] = value
        return params

    def _value_for(self, pspec, spec, target, profile, objective):
        name = pspec.name.lower()
        ptype = pspec.type
        tuning = _OBJECTIVE_TUNING.get(objective, _OBJECTIVE_TUNING["standard"])

        # -- objective/tech tuning knobs ------------------------------------
        if name == "timing":
            return tuning["timing"]
        if name == "severity":
            return tuning["severity"] or None  # empty => leave default (all)
        if name in ("threads", "concurrency"):
            return tuning["threads"]
        if name == "rate":
            return tuning["rate"]
        if name == "depth":
            return tuning["depth"]
        if name in ("extensions", "ext"):
            return self._extensions_for(profile)

        # -- target-shaped parameters ---------------------------------------
        if ptype == ParamType.HOSTNAME:
            return _hostname(target)
        # ponytail: only whois_lookup's "query" is target-shaped; cve_search,
        # searchsploit, shodan, censys, zoomeye all use "query" for a search
        # string, and filling it with the hostname pollutes the search.
        if name == "query" and spec.name == "whois_lookup":
            return _hostname(target)

        if ptype == ParamType.URL:
            return _as_url(target)

        if ptype == ParamType.IP_ADDRESS:
            if profile and profile.resolved_addresses:
                return profile.resolved_addresses[0]
            host = _hostname(target)
            return host if _is_ip(host) else None  # can't invent an IP

        if ptype == ParamType.CIDR:
            return target if _is_cidr(target) else None

        if ptype == ParamType.TARGET:
            host = _hostname(target)
            if spec.category in _SCANNER_CATEGORIES:
                return host  # nmap/masscan want a host or IP, never a URL
            return _as_url(target) if not _is_ip(host) and not _is_cidr(target) else host

        # -- file / directory / interface modalities ------------------------
        # Route the target into a file, source, or interface parameter only when
        # the target actually is that modality, so an optional file parameter on
        # a web tool is never filled with a URL and broken.
        modality = profile.target_type if profile else "unknown"
        if ptype == ParamType.FILE or name in _FILE_NAMES:
            return target if modality in _FILE_MODALITIES else None
        if ptype == ParamType.DIRECTORY or name in _DIR_NAMES:
            return target if modality == "code" else None
        if name == "interface":
            return target if modality == "wireless" else None

        # -- tuning knobs ---------------------------------------------------
        if ptype == ParamType.PORT_RANGE:
            if self._is_web(target, profile):
                return _WEB_PORTS
            return None  # leave the tool's default sweep

        if ptype == ParamType.WORDLIST:
            return self._wordlist_for(spec)

        # Everything else (files, hashes, durations, free strings) is left to
        # its declared default or to an operator.
        return None

    @staticmethod
    def _is_web(target: str, profile: TargetProfile | None) -> bool:
        if (target or "").startswith(("http://", "https://")):
            return True
        return bool(profile and profile.has_web_surface())

    @staticmethod
    def _wordlist_for(spec: ToolSpec) -> str | None:
        name = spec.name.lower()
        is_dns = "dns" in name or (spec.category == "recon" and "domain" in spec.params)
        return _first_existing(_DNS_WORDLISTS if is_dns else _DIR_WORDLISTS)

    @staticmethod
    def _extensions_for(profile: TargetProfile | None) -> str:
        """Pick brute-force extensions from the detected technology stack."""
        techs = " ".join(profile.technology_names()) if profile else ""
        for needles, extensions in _TECH_EXTENSIONS:
            if any(n in techs for n in needles):
                return extensions
        return _DEFAULT_EXTENSIONS


def optimize_preview(target: str, tool: str, objective: str = "standard") -> dict[str, Any]:
    """Show how one tool would be invoked against a target, without running it.

    Returns the tuned parameters and the exact argv they build -- the answer to
    "is this tool actually going to run correctly?" before anything executes.
    """
    from nexhunter.core import tools as T
    from nexhunter.agents.profiler import Profiler

    spec = T.get_tool_spec(tool)
    if spec is None:
        return {"ok": False, "code": "UNKNOWN_TOOL", "error": f"unknown tool: {tool}"}

    profile = Profiler().new_profile(target)
    params = ParameterOptimizer().optimize(spec, target, profile, objective)

    normalized, err = spec.normalize(params)
    command = None
    if err is None:
        try:
            command = spec.build_cmd(normalized)
        except Exception as exc:  # noqa: BLE001 - a bad build is data, not a crash
            err = f"command build failed: {exc}"

    return {
        "ok": err is None and command is not None,
        "tool": tool,
        "target": target,
        "objective": objective,
        "params": params,
        "command": command,
        "runnable": err is None and command is not None,
        "error": err,
    }
