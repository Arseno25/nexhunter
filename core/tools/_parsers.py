"""Output parsers for tools with structured stdout, keyed by name in PARSERS."""

import json
import re

from defusedxml import ElementTree as ET


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


def _parse_urls(text):
    """One URL per line (katana, gau, waybackurls). Deduplicated, order kept."""
    seen, out = set(), []
    for line in text.splitlines():
        url = line.strip()
        if url and url not in seen:
            seen.add(url)
            out.append({"url": url})
    return out


def _parse_hosts(text):
    """One hostname per line (subfinder, assetfinder, amass). Deduplicated."""
    seen, out = set(), []
    for line in text.splitlines():
        host = line.strip().lower()
        if host and host not in seen:
            seen.add(host)
            out.append({"host": host})
    return out


def _parse_host_port(text):
    """host:port per line (naabu). IPv4/hostname targets."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        host, _, port = line.rpartition(":")
        if host and port.isdigit():
            out.append({"host": host, "port": port})
    return out


def _parse_dnsx(text):
    """dnsx -a -resp lines: "host [1.2.3.4]" -> {host, a:[ips]}."""
    import re

    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        host = line.split()[0]
        ips = re.findall(r"\[([0-9A-Fa-f:.]+)\]", line)
        out.append({"host": host, "a": ips})
    return out


def _parse_masscan_grep(text):
    """masscan -oG output: "Host: 1.2.3.4 () Ports: 80/open/tcp..."."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        host = None
        m = re.match(r"Host:\s*([^\s()]+)", line)
        if m:
            host = m.group(1)
        ports = re.findall(r"([0-9]+)/open/", line)
        for port in ports:
            out.append({"host": host, "port": port})
        if host and not ports:
            out.append({"host": host, "port": "*"})
    return out


def _parse_whatweb(text):
    """WhatWeb text output: one line per target with tech in brackets."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        tech = re.findall(r"\[([^\]]+)\]", line)
        url_m = re.match(r"(https?://[^\s\[,]+)", line)
        out.append({"url": url_m.group(1) if url_m else "", "tech": tech})
    return out


def _parse_nikto(text):
    """Nikto text output: lines starting with '+' are findings."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("+ ") and ":" in line:
            out.append({"finding": line[2:], "severity": "medium"})
    return out


def _parse_ffuf(text):
    """ffuf text output: lines containing status codes and sizes."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        # ffuf line: "path    [Status: 200, Size: 1234, ...]"
        m = re.search(r"Status:\s*(\d+)", line)
        if m and int(m.group(1)) not in (404, 400):
            path_m = re.match(r"(\S+)\s+\[Status", line)
            out.append({
                "url": path_m.group(1) if path_m else line,
                "status": int(m.group(1)),
            })
    return out


def _parse_sqlmap(text):
    """sqlmap text output: extract injection points and backend info."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if "is vulnerable" in line.lower() or "sqlmap identified" in line.lower():
            out.append({"finding": line, "severity": "high"})
        elif "parameter" in line.lower() and "injectable" in line.lower():
            out.append({"finding": line, "severity": "high"})
        elif line.startswith("[+]") or line.startswith("[INFO]"):
            out.append({"finding": line.lstrip("[+] ").lstrip("[INFO] "), "severity": "info"})
    return out or [{"finding": "sqlmap completed", "severity": "info"}]


def _parse_testssl(text):
    """testssl.sh text output: extract severity-tagged findings."""
    out = []
    # testssl marks issues with CRITICAL/HIGH/MEDIUM/LOW/OK/INFO
    sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
               "LOW": "low", "WARN": "medium", "OK": "info", "INFO": "info"}
    for line in text.splitlines():
        line = line.strip()
        for tag, sev in sev_map.items():
            if f" {tag} " in line or line.startswith(tag):
                # strip ANSI color codes
                clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
                if clean:
                    out.append({"finding": clean, "severity": sev})
                break
    return out


def _parse_sslyze(text):
    """sslyze text output: extract cipher/protocol findings."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("*") or line.startswith("="):
            continue
        if any(kw in line.lower() for kw in ["vulnerable", "not supported", "accepted", "rejected", "error"]):
            out.append({"finding": line, "severity": "info"})
    return out


def _parse_wpscan(text):
    """wpscan text output: extract [+] positive findings."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[+]") or line.startswith("[!]") or line.startswith("[i]"):
            sev = "high" if line.startswith("[!]") else "info"
            out.append({"finding": line[4:].strip(), "severity": sev})
    return out


PARSERS = {
    "nmap_xml": _parse_nmap_xml,
    "httpx": _parse_httpx,
    "nuclei": _parse_nuclei,
    "browser_json": _parse_browser_json,
    "urls": _parse_urls,
    "hosts": _parse_hosts,
    "host_port": _parse_host_port,
    "dnsx_resp": _parse_dnsx,
    "masscan_grep": _parse_masscan_grep,
    "whatweb": _parse_whatweb,
    "nikto": _parse_nikto,
    "ffuf": _parse_ffuf,
    "sqlmap": _parse_sqlmap,
    "testssl": _parse_testssl,
    "sslyze": _parse_sslyze,
    "wpscan": _parse_wpscan,
}
