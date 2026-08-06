#!/usr/bin/env python3
"""NexHunter CLI - command-line client for the nexhunter API server.

Commands: health, agents, tools, probe, assess, report, telemetry.
See NEXHUNTER_CLI.md for full documentation.

Usage:
    nexhunter health
    nexhunter probe https://example.com
    nexhunter --server http://127.0.0.1:8888 assess https://example.com
"""

import argparse
import json
import os
import sys
import time
import urllib.request

from nexhunter.api.visual import NEXHUNTER_ART

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
    except Exception:  # noqa: S110 - best-effort console setup
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


def OK(t):
    return _C.w("32", t)


def ERR(t):
    return _C.w("31", t)


def INFO(t):
    return _C.w("34", t)


def WARN(t):
    return _C.w("33", t)


def HEAD(t):
    return _C.w("36", t)


def MUTE(t):
    return _C.w("90", t)

BANNER = HEAD(NEXHUNTER_ART.strip("\n"))

SEV_COLOR = {"critical": ERR, "high": ERR, "medium": WARN, "low": INFO, "info": MUTE}


def api(path, payload=None, timeout=600):
    url = SERVER + path
    if not url.lower().startswith(("http://", "https://")):
        return {"ok": False, "error": f"refusing non-http server URL: {url}"}
    req = urllib.request.Request(  # noqa: S310 - scheme guard above
        url,
        data=json.dumps(payload or {}).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - scheme guard above
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
        lines = [line for line in h.get("output", "").splitlines() if line.strip()][:12]
        print(HEAD("Response headers:"))
        for line in lines:
            print(f"  {MUTE(line)}")
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


_TERMINAL = {"completed", "failed", "timed_out", "terminated", "blocked", "stopped"}
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _draw(line):
    """Redraw one status line: in place on a TTY, appended otherwise."""
    if sys.stderr.isatty():
        sys.stderr.write("\r\x1b[2K" + line)
    else:
        sys.stderr.write(line + "\n")
    sys.stderr.flush()


def _clear_line():
    if sys.stderr.isatty():
        sys.stderr.write("\r\x1b[2K")
        sys.stderr.flush()


def _fmt_secs(s):
    s = int(s or 0)
    return f"{s // 60}m{s % 60:02d}s" if s >= 60 else f"{s}s"


def cmd_run(args):
    """Run one registered tool with a live progress indicator.

    Kicks off an async execution and polls its status so the terminal shows a
    spinner + elapsed + captured bytes instead of hanging silently. A single
    tool does not report a percentage, so this is an activity indicator, not a
    bar; the autonomous command shows a real bar.
    """
    params = {}
    for kv in (args.param or []):
        if "=" not in kv:
            print(ERR(f"[-] bad --param {kv!r}, expected key=value"))
            return 1
        key, value = kv.split("=", 1)
        params[key] = value

    start = api("/api/command", {"tool": args.tool, "params": params, "async": True})
    if not start.get("ok"):
        print(ERR("[-] " + str(start.get("error") or start.get("code") or "start failed")))
        return 1

    eid = start["execution_id"]
    t0 = time.time()
    i = 0
    status = "running"
    last = None
    rec = {}
    while True:
        st = api(f"/api/executions/{eid}", timeout=15)
        rec = st.get("execution", {}) if st.get("ok") else {}
        status = rec.get("status", "running")
        if status in _TERMINAL:
            break
        elapsed = _fmt_secs(time.time() - t0)
        kb = (rec.get("stdout_bytes", 0) or 0) / 1024
        if sys.stderr.isatty():
            frame = _SPINNER[i % len(_SPINNER)]
            i += 1
            _draw(f"  {INFO(frame)} {args.tool}  {MUTE(status)}  {elapsed}  {kb:.0f} KB")
        elif status != last:
            _draw(f"  [{status}] {args.tool} {elapsed}")
            last = status
        time.sleep(0.4)

    _clear_line()
    ok = status == "completed"
    badge = OK("[+]") if ok else ERR("[-]")
    dur = _fmt_secs(rec.get("duration_s") or (time.time() - t0))
    print(f"  {badge} {args.tool}  {status}  ({dur})")

    out = api(f"/api/executions/{eid}/output")
    body = out.get("stdout", "") if out.get("ok") else ""
    for line in body.splitlines()[:60]:
        print(f"  {MUTE(line)}")
    extra = len(body.splitlines()) - 60
    if extra > 0:
        print(MUTE(f"  ... {extra} more lines (GET /api/executions/{eid}/output)"))
    if not ok:
        err = out.get("stderr", "") if out.get("ok") else ""
        for line in err.splitlines()[:20]:
            print(f"  {WARN(line)}")
    verbose(args, rec)
    return 0 if ok else 1


def cmd_autonomous(args):
    """Run an adaptive autonomous assessment with a live progress bar."""
    from nexhunter.api.visual import render_progress_bar

    start = api("/api/autonomous", {
        "target": args.target,
        "risk_ceiling": args.ceiling,
        "max_steps": args.max_steps,
        "objective": args.objective,
        "strategy": args.strategy,
        "async": True,
    })
    if not start.get("ok"):
        print(ERR("[-] " + str(start.get("error") or "start failed")))
        return 1

    run = start.get("run", {})
    rid = run.get("run_id", "")
    print(f"  {OK('[+]')} autonomous run {INFO(rid)}  target={args.target}  ceiling={args.ceiling}")

    last_phase = None
    try:
        while True:
            r = api(f"/api/autonomous/{rid}", timeout=15).get("run", {})
            status = r.get("status", "running")
            steps = r.get("steps_taken", 0)
            total = r.get("max_steps", 0) or 1
            phase = r.get("current_phase", "")
            if status != "running":
                break
            if sys.stderr.isatty():
                bar = render_progress_bar(steps, total, width=24, color=True)
                _draw(f"  {bar}  {MUTE(f'step {steps}/{total}')}  {INFO(phase)}")
            elif phase != last_phase:
                _draw(f"  step {steps}/{total} · {phase}")
                last_phase = phase
            time.sleep(1.0)
    except KeyboardInterrupt:
        _clear_line()
        print(WARN(f"  [~] detached; the run continues server-side: {rid}"))
        return 1

    _clear_line()
    r = api(f"/api/autonomous/{rid}").get("run", {})
    ok = r.get("status") == "completed"
    print(f"  {OK('[+]') if ok else ERR('[-]')} status={r.get('status')}  "
          f"steps={r.get('steps_taken')}/{r.get('max_steps')}")

    execs = r.get("executions", [])
    if execs:
        print(HEAD("  Executed:"))
        for e in execs:
            mark = OK("ok ") if e.get("ok") else ERR("err")
            print(f"    {mark} {e.get('tool')}  {MUTE(e.get('status') or '')}")
    withheld = r.get("recommended_next", [])
    if withheld:
        print(HEAD("  Withheld (needs human approval):"))
        for w in withheld[:10]:
            print(f"    {WARN('[!]')} {w.get('tool')}  {MUTE(w.get('risk_level', ''))}")

    summ = api("/api/findings/summary")
    if isinstance(summ, dict) and summ.get("ok"):
        s = summ.get("summary", {})
        total_f = s.get("total") if isinstance(s, dict) else None
        if total_f:
            print(HEAD(f"  Findings: {total_f}") + MUTE("  (nexhunter report)"))
    verbose(args, r)
    return 0 if ok else 1


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
    color = "1" if _C.enabled else "0"
    d = api(f"/api/visual/dashboard?format=box&color={color}")
    if d.get("error"):
        print(ERR("[-] " + d["error"]))
        return 1
    if d.get("box"):
        print(d["box"])
        return 0
    # Fallback: plain metrics from an older server.
    print(HEAD("Assessment Dashboard:"))
    print(f"  Requests: {d.get('requests', 0)}")
    print(f"  Findings: {d.get('findings', 0)}")
    print(f"  Active Processes: {d.get('processes', 0)}")
    print(f"  Cache Hits: {d.get('cache_hits', 0)}")
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


def cmd_doctor(args):
    """Check that this installation can actually run."""
    from nexhunter.cli import doctor

    return doctor.run(check_versions=not args.no_versions, show_all_tools=args.all)


def cmd_registry(args):
    """Inspect the tool registry locally, without contacting a server."""
    from nexhunter.core import tools as T
    from nexhunter.core.availability import check_binary

    if args.registry_cmd == "info":
        spec = T.get_tool_spec(args.name)
        if spec is None:
            print(f"unknown tool: {args.name}")
            return 1
        info = spec.describe()
        print(f"\n{info['name']}\n  {info['description']}\n")
        print(f"  binary     {info['binary']}" + ("" if info["available"] else "  (NOT INSTALLED)"))
        print(f"  category   {info['category']}")
        print(f"  risk       {info['risk_level']}")
        print(f"  maturity   {info['maturity']}")
        print(f"  timeout    {info['timeout_s']}s")
        print("  parameters")
        for key, meta in info["parameters"].items():
            requirement = "required" if meta["required"] else f"default={meta['default']!r}"
            print(f"    {key:16} {requirement}")
        print()
        return 0

    if args.registry_cmd == "check":
        binaries = {}
        for spec in T.TOOLS.values():
            binaries.setdefault(spec.binary, []).append(spec.name)
        installed = 0
        for binary in sorted(binaries):
            status = check_binary(binary)
            if status.installed:
                installed += 1
                version = f" {status.version}" if status.version else ""
                print(f"  [OK]      {binary}{version}")
            else:
                print(f"  [MISSING] {binary}")
        print(f"\n{installed}/{len(binaries)} binaries installed. NexHunter never installs them for you.\n")
        return 0

    specs = list(T.TOOLS.values())
    if args.category:
        specs = [s for s in specs if s.category == args.category]
    if args.risk:
        specs = [s for s in specs if s.risk_level == args.risk]
    if args.maturity:
        specs = [s for s in specs if s.maturity == args.maturity]
    if args.installed:
        specs = [s for s in specs if s.available]

    for spec in sorted(specs, key=lambda s: (s.category, s.name)):
        mark = " " if spec.available else "!"
        print(f"{mark} {spec.name:34} {spec.category:12} {spec.risk_level:10} {spec.maturity:12} {spec.description}")
    print(f"\n{len(specs)} tools ('!' means the binary is not installed)\n")
    return 0


def cmd_profiles(args):
    """List MCP profiles, or the tools in one."""
    from nexhunter.api import mcp_profiles

    if args.name:
        try:
            profile = mcp_profiles.get_profile(args.name)
        except KeyError as exc:
            print(exc)
            return 1
        selected = mcp_profiles.tools_for(profile)
        print(f"\n{profile.name}\n  {profile.description}\n")
        for name, spec in sorted(selected.items()):
            mark = " " if spec.available else "!"
            print(f"  {mark} {name:34} {spec.risk_level:10} {spec.maturity}")
        print(f"\n{len(selected)} tools ('!' means the binary is not installed)\n")
        return 0

    print()
    for row in mcp_profiles.summarize():
        print(f"  {row['name']:22} {row['tool_count']:4} tools  {row['available_tool_count']:3} installed")
        print(f"  {'':22} {row['description']}")
    print()
    return 0


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: S110 - encoding already usable
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
    p_run = sub.add_parser("run", help="run one registered tool with a live progress indicator")
    p_run.add_argument("tool")
    p_run.add_argument("--param", action="append", metavar="KEY=VALUE", help="tool parameter (repeatable)")
    p_auto = sub.add_parser("autonomous", help="adaptive autonomous assessment with a live progress bar")
    p_auto.add_argument("target")
    p_auto.add_argument("--ceiling", default="active", choices=["passive", "active", "intrusive"],
                        help="risk ceiling (clamped to active for autonomy)")
    p_auto.add_argument("--max-steps", type=int, default=20, dest="max_steps")
    p_auto.add_argument("--objective", default="standard",
                        choices=["quick", "standard", "comprehensive", "stealth"])
    p_auto.add_argument("--strategy", default="methodology", choices=["methodology", "select"])
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

    # Local commands: these inspect this installation and need no server.
    doctor_parser = sub.add_parser("doctor", help="check this installation can run (no server needed)")
    doctor_parser.add_argument("--all", action="store_true", help="list every missing stable tool")
    doctor_parser.add_argument("--no-versions", action="store_true", help="skip version probes (faster)")

    registry_parser = sub.add_parser("registry", help="inspect the tool registry (no server needed)")
    registry_sub = registry_parser.add_subparsers(dest="registry_cmd", required=True)
    registry_list = registry_sub.add_parser("list", help="list registered tools")
    registry_list.add_argument("--category", default="", help="filter by category")
    registry_list.add_argument("--risk", default="", help="filter by risk level")
    registry_list.add_argument("--maturity", default="", help="filter by maturity")
    registry_list.add_argument("--installed", action="store_true", help="only tools whose binary is present")
    registry_sub.add_parser("check", help="report which tool binaries are installed")
    registry_info = registry_sub.add_parser("info", help="describe one tool")
    registry_info.add_argument("name")

    profiles_parser = sub.add_parser("profiles", help="list MCP profiles (no server needed)")
    profiles_parser.add_argument("--name", default="", help="show the tools in one profile")

    args = parser.parse_args(argv)
    global SERVER
    SERVER = args.server.rstrip("/")
    handlers = {
        "health": cmd_health,
        "agents": cmd_agents,
        "tools": cmd_tools,
        "probe": cmd_probe,
        "assess": cmd_assess,
        "run": cmd_run,
        "autonomous": cmd_autonomous,
        "report": cmd_report,
        "telemetry": cmd_telemetry,
        "vulns": cmd_vulnerabilities,
        "dashboard": cmd_dashboard,
        "osint": cmd_osint,
        "analyze-vulns": cmd_analyze_vulns,
        "threat-intel": cmd_threat_intel,
        "bugbounty-pro": cmd_bugbounty_pro,
        "ctf-solver": cmd_ctf_solver,
        "doctor": cmd_doctor,
        "registry": cmd_registry,
        "profiles": cmd_profiles,
    }
    try:
        return handlers[args.cmd](args) or 0
    except KeyboardInterrupt:
        return 1


if __name__ == "__main__":
    sys.exit(main())
