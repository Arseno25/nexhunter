#!/usr/bin/env python3
"""NexHunter CLI - command-line client for the nexhunter API server.

Commands: health, agents, tools, probe, assess, report, telemetry.
See NEXHUNTER_CLI.md for full documentation.

Usage:
    python nexhunter.py health
    python nexhunter.py probe https://example.com
    python nexhunter.py --server http://127.0.0.1:8888 assess https://example.com
"""

import argparse
import json
import os
import sys
import urllib.request

SERVER = "http://127.0.0.1:8888"


def _enable_vt():
    if os.name != "nt":
        return
    import ctypes

    try:
        h = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if ctypes.windll.kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            ctypes.windll.kernel32.SetConsoleMode(h, mode.value | 0x0004)
    except Exception:
        pass


class _C:
    enabled = False

    @classmethod
    def init(cls):
        if os.environ.get("NO_COLOR") is None:
            cls.enabled = True
            _enable_vt()

    @classmethod
    def w(cls, code, text):
        return f"\x1b[{code}m{text}\x1b[0m" if cls.enabled else text


OK = lambda t: _C.w("32", t)
ERR = lambda t: _C.w("31", t)
INFO = lambda t: _C.w("34", t)
WARN = lambda t: _C.w("33", t)
HEAD = lambda t: _C.w("36", t)
MUTE = lambda t: _C.w("90", t)

BANNER = HEAD(
    "███╗   ██╗███████╗██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗\n"
    "████╗  ██║██╔════╝╚██╗██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗\n"
    "██╔██╗ ██║█████╗   ╚███╔╝ ██║  ██║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝\n"
    "██║╚██╗██║██╔══╝   ██╔██╗ ██║  ██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗\n"
    "██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║\n"
    "╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
)

SEV_COLOR = {"critical": ERR, "high": ERR, "medium": WARN, "low": INFO, "info": MUTE}


def api(path, payload=None, timeout=600):
    req = urllib.request.Request(
        SERVER + path,
        data=json.dumps(payload or {}).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception as e:
        return {"ok": False, "error": f"server unreachable at {SERVER}: {e}"}


def table(headers, rows):
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(str(c)))
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)), "-" * sum(widths)]
    lines += ["  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r)) for r in rows]
    return "\n".join(lines)


def sev_bars(by_sev, total):
    out = []
    for s in ("critical", "high", "medium", "low", "info"):
        n = by_sev.get(s, 0)
        filled = int((n / total) * 20) if total else 0
        bar = "█" * filled + "░" * (20 - filled)
        out.append(f"  {SEV_COLOR[s](bar)} {s:>8} {n}")
    return "\n".join(out)


def verbose(args, data):
    if args.verbose:
        print(MUTE(json.dumps(data, indent=1)))


def cmd_health(args):
    d = api("/health")
    if not d.get("ok"):
        print(ERR("[-] " + d.get("error", "server unreachable")))
        return 1
    print(f"  version:      {d.get('version')}")
    print(f"  mode:         {OK(d.get('mode')) if d.get('mode') == 'full' else WARN(d.get('mode'))}")
    print(f"  agents:       {d.get('agents', []).__len__()}")
    installed = {k: v for k, v in d.get("tools_installed", {}).items() if v}
    print(f"  tools ready:  {len(installed)} / {len(d.get('tools_installed', {}))}")
    print(f"  agents list:  {', '.join(d.get('agents', []))}")
    verbose(args, d)
    return 0


def cmd_agents(args):
    d = api("/api/agents/list")
    if isinstance(d, dict) and d.get("error"):
        print(ERR("[-] " + d["error"]))
        return 1
    for i, a in enumerate(d, 1):
        print(f"  {INFO(str(i).rjust(2))}  {OK(a['name'])} - {a['desc']}")
    verbose(args, d)
    return 0


def cmd_tools(args):
    d = api("/health")
    if not d.get("ok"):
        print(ERR("[-] " + d.get("error", "server unreachable")))
        return 1
    ti = d.get("tools_installed", {})
    inst = [(n, "installed") for n, v in ti.items() if v]
    miss = [(n, "MISSING") for n, v in ti.items() if not v]
    if inst:
        print(HEAD("Installed:"))
        print(table(["tool", "status"], inst))
    if miss:
        print(HEAD("Missing (install to enable):"))
        print(table(["tool", "status"], miss))
    verbose(args, d)
    return 0


def cmd_probe(args):
    d = api("/api/probe", {"target": args.target})
    if not d.get("ok"):
        print(ERR("[-] probe failed: " + str(d.get("error") or d.get("status"))))
        return 1
    for p in d.get("data", []):
        print(f"  {OK('[+]')} {p.get('url')}  ->  HTTP {p.get('status')}")
        print(f"  {INFO('[*]')} title: {p.get('title')}")
        print(f"  {INFO('[*]')} tech:  {', '.join(p.get('tech') or []) or 'unknown'}")
    h = api("/api/command", {"tool": "curl_headers", "params": {"url": args.target}})
    if h.get("ok"):
        lines = [l for l in h.get("output", "").splitlines() if l.strip()][:12]
        print(HEAD("Response headers:"))
        for l in lines:
            print(f"  {MUTE(l)}")
    verbose(args, d)
    return 0


def cmd_assess(args):
    d = api("/api/assess", {"target": args.target})
    s = d.get("summary", {})
    total = s.get("total", 0)
    print(f"  {OK('[+]')} target: {d.get('target')}")
    print(f"  total findings: {total}")
    print(HEAD("Severity breakdown:"))
    print(sev_bars(s.get("by_severity", {}), total))
    print(HEAD("Findings:"))
    f = api("/api/findings")
    for item in f.get("findings", []):
        sev = item.get("severity", "info")
        print(f"  {SEV_COLOR[sev](sev.upper().ljust(8))} [{item.get('tool')}] {item.get('title')}")
    verbose(args, d)
    return 0


def cmd_vulnerabilities(args):
    """Display vulnerability cards."""
    d = api("/api/visual/vulnerabilities")
    if d.get("error"):
        print(ERR("[-] " + d["error"]))
        return 1
    vulns = d.get("vulnerabilities", [])
    print(HEAD(f"Vulnerabilities ({len(vulns)} total):"))
    print("-" * 100)
    for v in vulns[:20]:
        sev_badge = {
            "critical": ERR("[!]"),
            "high": ERR("[!]"),
            "medium": WARN("[*]"),
            "low": INFO("[+]"),
            "info": MUTE("[i]"),
        }.get(v.get("severity", "info"), "[ ]")
        print(f"{sev_badge} {v.get('title', 'Unknown')}")
        print(f"    Type: {v.get('type')} | Endpoint: {v.get('endpoint', 'N/A')}")
        print(f"    Impact: {v.get('impact')} | Fix: {v.get('remediation')}")
        if v.get("cvss_score"):
            print(f"    CVSS: {v.get('cvss_score')}")
        print()
    if len(vulns) > 20:
        print(f"... and {len(vulns) - 20} more")
    return 0


def cmd_dashboard(args):
    """Display assessment dashboard."""
    d = api("/api/visual/dashboard")
    if d.get("error"):
        print(ERR("[-] " + d["error"]))
        return 1
    print(HEAD("Assessment Dashboard:"))
    print(f"  Requests: {d.get('requests', 0)}")
    print(f"  Findings: {d.get('findings', 0)}")
    print(f"  Active Processes: {d.get('processes', 0)}")
    print(f"  Cache Hits: {d.get('cache_hits', 0)}")
    vulns = d.get("vulnerabilities", {})
    if vulns:
        print(HEAD("Vulnerabilities by Severity:"))
        for sev in ("critical", "high", "medium", "low", "info"):
            count = vulns.get(sev, 0)
            bar_width = 20
            filled = int((count / max(sum(vulns.values()), 1)) * bar_width)
            bar = "█" * filled + "░" * (bar_width - filled)
            color_map = {"critical": ERR, "high": ERR, "medium": WARN, "low": INFO, "info": MUTE}
            print(f"  {color_map[sev](bar)} {sev:>8} {count}")
    return 0


def cmd_osint(args):
    """OSINT intelligence gathering."""
    d = api("/api/intelligence/osint", {"target": args.target})
    if d.get("error"):
        print(ERR("[-] " + d["error"]))
        return 1
    intel = d.get("data", {}).get("intelligence", {})
    print(HEAD(f"OSINT Intelligence: {args.target}"))
    summary = d.get("data", {}).get("summary", {})
    print(f"  Subdomains: {summary.get('subdomains', 0)}")
    print(f"  Emails: {summary.get('emails', 0)}")
    print(f"  Social Accounts: {summary.get('social_accounts', 0)}")
    print(f"  DNS Records: {summary.get('dns_records', 0)}")

    if intel.get("subdomains"):
        print(HEAD("Discovered Subdomains:"))
        for sub in intel["subdomains"][:10]:
            print(f"  {OK('[+]')} {sub['domain']} ({sub.get('ip', 'N/A')})")

    return 0


def cmd_analyze_vulns(args):
    """Advanced vulnerability analysis."""
    d = api("/api/intelligence/vulnerability-analysis", {"target": args.target})
    if d.get("error"):
        print(ERR("[-] " + d["error"]))
        return 1
    data = d.get("data", {})
    threat = data.get("threat_level", {})
    print(HEAD(f"Vulnerability Analysis: {args.target}"))
    print(f"  Threat Level: {WARN(threat.get('level', 'N/A').upper())}")
    print(f"  Risk Score: {threat.get('score', 0):.1f}/100")

    if threat.get("factors"):
        print(HEAD("Risk Factors:"))
        for factor in threat["factors"]:
            print(f"  {WARN('[!]')} {factor}")

    chains = data.get("attack_chains", [])
    if chains:
        print(HEAD("Attack Chains Detected:"))
        for chain in chains:
            print(f"  {ERR('[CRITICAL]')} {chain['name']}")
            print(f"    Impact: {chain['impact']}")

    return 0


def cmd_threat_intel(args):
    """Threat intelligence assessment."""
    d = api("/api/intelligence/threat-assessment", {"target": args.target})
    if d.get("error"):
        print(ERR("[-] " + d["error"]))
        return 1
    intel = d.get("data", {}).get("threat_intelligence", {})
    risk = intel.get("risk_assessment", {})

    print(HEAD(f"Threat Intelligence: {args.target}"))
    print(f"  Risk Level: {WARN(risk.get('risk_level', 'N/A').upper())}")
    print(f"  Risk Score: {risk.get('risk_score', 0)}/100")
    print(f"  IOCs: {risk.get('ioc_count', 0)}")
    print(f"  TTPs: {risk.get('ttp_count', 0)}")
    print(f"  MITRE Techniques: {risk.get('mitre_techniques', 0)}")

    return 0


def cmd_bugbounty_pro(args):
    """Professional bug bounty assessment."""
    d = api("/api/flow/bugbounty-pro", {"target": args.target})
    if d.get("error"):
        print(ERR("[-] " + d["error"]))
        return 1
    assessment = d.get("data", {}).get("assessment", {})
    phases = assessment.get("phases", {})

    print(HEAD(f"Bug Bounty Assessment: {args.target}"))
    print(HEAD("Phase Status:"))
    for phase, status in phases.items():
        badge = OK("[+]") if status.get("status") == "completed" else WARN("[~]") if status.get("status") == "in_progress" else MUTE("[ ]")
        print(f"  {badge} {phase:20} - {status.get('findings', 0)} findings")

    return 0


def cmd_ctf_solver(args):
    """CTF challenge analyzer."""
    d = api("/api/tools/ctf-solver", {"type": args.type, "name": "Challenge"})
    if d.get("error"):
        print(ERR("[-] " + d["error"]))
        return 1
    analysis = d.get("data", {}).get("analysis", {})
    tools = analysis.get("tools", [])

    print(HEAD(f"CTF Solver: {args.type.upper()} Challenge"))
    print(HEAD("Recommended Tools:"))
    for tool in tools[:10]:
        print(f"  {INFO('[*]')} {tool}")

    hints = analysis.get("hints", [])
    if hints:
        print(HEAD("Hints:"))
        for hint in hints:
            print(f"  {WARN('[?]')} {hint['hint']}")

    return 0


def cmd_report(args):
    d = api("/api/report", {"fmt": args.fmt})
    if d.get("error"):
        print(ERR("[-] " + d["error"]))
        return 1
    print(d.get("report", ""))
    return 0


def cmd_telemetry(args):
    d = api("/api/telemetry")
    if d.get("error"):
        print(ERR("[-] " + d["error"]))
        return 1
    print(f"  uptime:            {d.get('uptime_s')}s")
    print(f"  requests:          {d.get('requests')}")
    print(f"  avg response:      {d.get('avg_response_ms')}ms")
    print(f"  cache:             {d.get('cache_entries')} entries, {d.get('cache_hits')} hits, {d.get('cache_evictions')} evictions")
    print(f"  findings:          {d.get('findings')}")
    print(f"  processes:         {d.get('processes')}")
    verbose(args, d)
    return 0


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    _C.init()
    print(BANNER)
    print(MUTE("  NexHunter - AI-driven security assessment platform") + "\n")
    parser = argparse.ArgumentParser(prog="nexhunter", description="NexHunter CLI - AI-driven security assessment platform")
    parser.add_argument("--server", default="http://127.0.0.1:8888", help="API server address (default: http://127.0.0.1:8888)")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("health", help="check server status, version, agents, tools")
    sub.add_parser("agents", help="list all available AI agents")
    sub.add_parser("tools", help="list installed and missing security tools")
    p_probe = sub.add_parser("probe", help="quick HTTP reconnaissance on a target")
    p_probe.add_argument("target")
    p_assess = sub.add_parser("assess", help="comprehensive security assessment")
    p_assess.add_argument("target")
    p_report = sub.add_parser("report", help="generate findings report")
    p_report.add_argument("--fmt", choices=["markdown", "json"], default="markdown")
    sub.add_parser("telemetry", help="server performance and cache statistics")
    sub.add_parser("vulns", help="display vulnerability cards")
    sub.add_parser("dashboard", help="display assessment dashboard")

    # Enhanced features
    osint_parser = sub.add_parser("osint", help="OSINT intelligence gathering")
    osint_parser.add_argument("target")

    vuln_parser = sub.add_parser("analyze-vulns", help="advanced vulnerability analysis")
    vuln_parser.add_argument("target")

    threat_parser = sub.add_parser("threat-intel", help="threat intelligence assessment")
    threat_parser.add_argument("target")

    bb_parser = sub.add_parser("bugbounty-pro", help="professional bug bounty assessment")
    bb_parser.add_argument("target")

    ctf_parser = sub.add_parser("ctf-solver", help="CTF challenge analyzer")
    ctf_parser.add_argument("--type", choices=["web", "crypto", "forensics", "pwn", "recon"], default="web")
    args = parser.parse_args(argv)
    global SERVER
    SERVER = args.server.rstrip("/")
    handlers = {
        "health": cmd_health,
        "agents": cmd_agents,
        "tools": cmd_tools,
        "probe": cmd_probe,
        "assess": cmd_assess,
        "report": cmd_report,
        "telemetry": cmd_telemetry,
        "vulns": cmd_vulnerabilities,
        "dashboard": cmd_dashboard,
        "osint": cmd_osint,
        "analyze-vulns": cmd_analyze_vulns,
        "threat-intel": cmd_threat_intel,
        "bugbounty-pro": cmd_bugbounty_pro,
        "ctf-solver": cmd_ctf_solver,
    }
    try:
        return handlers[args.cmd](args) or 0
    except KeyboardInterrupt:
        return 1


if __name__ == "__main__":
    sys.exit(main())
