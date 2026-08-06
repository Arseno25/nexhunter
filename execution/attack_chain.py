"""Attack chain builder: named kill-chain patterns with success odds.

Resilient, plan-first artifact: each *goal* maps to an ordered chain of
registered tools, each step carrying a short rationale (what it proves) and a
gate (what has to be observed before the next step is worth running). The
chain's expected success is scored from per-step base probabilities, adjusted
for whether the tool binary is actually installed -- so the plan is honest
about what this box can do.

This module only *builds and scores* chains. Nothing here executes a tool;
execution stays on the single path behind the registry.
"""

from __future__ import annotations

from typing import Any

from nexhunter.core import tools as T

# base_probability: rough chance a step succeeds on a typical authorized lab
# *given its gate is met*. Availability halves it when the binary is missing.
CHAIN_PATTERNS: dict[str, dict[str, Any]] = {
    "recon_sweep": {
        "goal": "Map the target's network, services, and web surface.",
        "steps": [
            ("subfinder_enum", "Passive subdomain discovery", 0.85,
             {"domain": "{domain}"}, "target resolves"),
            ("dns_lookup", "Resolve discovered names", 0.8,
             {"domain": "{domain}"}, "subdomains > 0"),
            ("nmap_scan", "Port/service discovery", 0.85,
             {"target": "{host}"}, "host is up"),
            ("httpx_probe", "Classify web services", 0.9,
             {"target": "{target}"}, "http(s) port open"),
            ("whatweb_scan", "Fingerprint web tech", 0.85,
             {"url": "{target}"}, "web service found"),
        ],
    },
    "web_rce": {
        "goal": "Turn a web endpoint into remote code execution.",
        "steps": [
            ("httpx_probe", "Confirm the web service responds", 0.9,
             {"target": "{target}"}, "200/redirect"),
            ("gobuster_dir", "Discover hidden endpoints", 0.7,
             {"target": "{target}", "wordlist": "{wordlist}"}, "web up"),
            ("nuclei_scan", "Template scan for known vulns", 0.65,
             {"target": "{target}", "severity": "high"}, "endpoints found"),
            ("http_intruder", "Injection probe on candidate params", 0.5,
             {"request": "{target}"}, "interesting endpoint"),
        ],
    },
    "ssrf_internal": {
        "goal": "Abuse an SSRF to reach the internal network.",
        "steps": [
            ("nuclei_scan", "Detect SSRF templates", 0.6,
             {"target": "{target}"}, "web up"),
            ("curl", "Probe callback endpoints", 0.55,
             {"url": "{target}"}, "ssrf flagged"),
            ("nmap_scan", "Scan internal ranges through the vector", 0.45,
             {"target": "10.0.0.0/8", "ports": "80,443,8080"},
             "callback observed"),
        ],
    },
    "credential_capture": {
        "goal": "Capture leaked/stored credentials on the surface.",
        "steps": [
            ("theharvester", "Harvest emails and names", 0.7,
             {"domain": "{domain}"}, "target is a domain"),
            ("maigret", "Check username footprint across services", 0.6,
             {"username": "{username}"}, "emails found"),
            ("dns_lookup", "Resolve infra records", 0.8,
             {"domain": "{domain}"}, "domain set"),
        ],
    },
    "api_abuse": {
        "goal": "Map and poke API surfaces for misused auth.",
        "steps": [
            ("katana_crawl", "Crawl for API endpoints", 0.75,
             {"url": "{target}"}, "web up"),
            ("linkfinder", "Extract endpoints from JS", 0.7,
             {"url": "{target}"}, "page loaded"),
            ("sqlmap_scan", "Test API params for injection", 0.5,
             {"url": "{target}"}, "api endpoints found"),
        ],
    },
}

_VALID_CHAIN_OPTS = ("recon_sweep", "web_rce", "ssrf_internal",
                     "credential_capture", "api_abuse")


def list_patterns() -> list[dict]:
    """Every named pattern, without probabilities (a decision aid)."""
    return [
        {"name": name, "goal": meta["goal"],
         "steps": [s[1] for s in meta["steps"]]}
        for name, meta in CHAIN_PATTERNS.items()
    ]


def build_chain(name: str, target: str,
                domain: str = "", host: str = "",
                username: str = "", wordlist: str = "") -> dict:
    """Build the named attack chain, scoring each step for this box."""
    if name not in CHAIN_PATTERNS:
        return {"ok": False, "error": f"unknown chain: {name}",
                "available": list(CHAIN_PATTERNS)}
    meta = CHAIN_PATTERNS[name]
    steps: list[dict] = []
    for tool, desc, base, params, gate in meta["steps"]:
        spec = T.get_tool_spec(tool)
        available = bool(spec and spec.available)
        filled = _build(tool, params, target, domain, host, username, wordlist)
        steps.append({
            "tool": tool,
            "description": desc,
            "params": filled,
            "gate": gate,
            "binary_available": available,
            "base_probability": base,
        })

    prob = _chain_probability(steps)
    return {
        "ok": True,
        "name": name,
        "goal": meta["goal"],
        "steps": steps,
        "success_probability": round(prob, 3),
        "chain_length": len(steps),
    }


def _build(tool, params, target, domain, host, username, wordlist) -> dict:
    """Fill keyword placeholders in params with the run context."""
    return {k: (str(v).replace("{target}", target).replace("{domain}", domain or target)
                .replace("{host}", host or target).replace("{username}", username)
                .replace("{wordlist}", wordlist)) for k, v in params.items()}


def _chain_probability(steps: list[dict]) -> float:
    """Multiplicative success odds from per-step base probabilities.

    A missing binary halves the step's odds. The chain-length penalty scales
    with the score, so a long cold chain never scores below zero.
    """
    if not steps:
        return 0.0
    prob = 1.0
    for step in steps:
        step_prob = step.get("base_probability", 0.5)
        if not step.get("binary_available"):
            step_prob /= 2
        prob *= step_prob
    penalty = max(0.0, len(steps) - 3) * 0.05
    return round(max(0.0, prob * (1 - penalty)), 3)
