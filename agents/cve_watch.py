"""CVE watch agent: recent disclosures from NVD, scored for exploitability.

Keeps the lab operator on top of what changed this week: fetch the newest
CVEs (optionally filtered by severity/keyword), classify each into an
exploit kind, and rank them by how likely a working exploit is to exist
or emerge quickly. Intended to feed later modules, not to be an exploit
engine itself.
"""

from __future__ import annotations

import datetime
import re

from nexhunter.agents.base import Agent
from nexhunter.agents.exploit_kit import core as C

NVD_SEARCH = "https://services.nvd.nist.gov/rest/json/cves/2.0?"

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# PoC-hinting markers found in descriptions or references.
_EXPLOIT_HINTS = (
    "exploit-db", "metasploit", "exploit", "poc", "proof of concept",
    "cisa", "actively exploited", "ransomware", "public exploit",
    "weaponized",
)


class CVEWatchAgent(Agent):
    """Monitor recent CVEs from NVD by severity/keyword, ranked by
    exploitability (kind + PoC availability hints)."""

    name = "cve_watch"
    desc = "Recent NVD CVEs (days/severity/keyword) ranked by exploitability"
    param_schema = {
        "days": (False, int),
        "severity": (False, str),
        "keyword": (False, str),
        "limit": (False, int),
    }

    def run(self, days: int = 7, severity: str = "",
            keyword: str = "", limit: int = 20):
        """Fetch the latest CVEs, classify, score, and rank them."""
        days = max(1, min(90, int(days or 7)))
        limit = max(1, min(100, int(limit or 20)))
        now = datetime.datetime.now(datetime.timezone.utc)
        start = (now - datetime.timedelta(days=days)).isoformat()
        end = now.isoformat()

        params = {
            "pubStartDate": start,
            "pubEndDate": end,
            "resultsPerPage": str(min(limit * 3, 200)),
        }
        if severity:
            params["cvssV3Severity"] = severity.upper()
        if keyword:
            params["keywordSearch"] = keyword

        try:
            data = C.fetch_json(NVD_SEARCH + C.urllib.parse.urlencode(params))
        except Exception as exc:  # noqa: BLE001 - report the network failure
            return self.result(ok=False, error=f"NVD unreachable: {exc}")

        vulns = (data or {}).get("vulnerabilities") or []
        ranked = [self._score(v["cve"]) for v in vulns]
        ranked.sort(key=lambda x: (x["exploitability"], x["cvss"]), reverse=True)

        return self.result(
            ok=True,
            data={
                "window_days": days,
                "severity_filter": severity.upper() if severity else "any",
                "keyword": keyword,
                "total_fetched": len(ranked),
                "top": ranked[:limit],
            },
            meta={
                "critical": sum(1 for r in ranked if r["severity"] == "CRITICAL"),
                "high": sum(1 for r in ranked if r["severity"] == "HIGH"),
            },
        )

    def _score(self, cve: dict) -> dict:
        cid = cve.get("id", "")
        desc = next(
            (d["value"] for d in cve.get("descriptions", [])
             if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {}) or {}
        cvss = 0.0
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            group = metrics.get(key)
            if group:
                data = group[0].get("cvssData", {})
                cvss = float(data.get("baseScore", 0) or 0)
                severity = (data.get("baseSeverity", "")
                            or group[0].get("baseSeverity", "")
                            or severity)
                break

        refs = [r.get("url", "") for r in cve.get("references", [])]
        low = f"{desc} {' '.join(refs)}".lower()
        hints = [h for h in _EXPLOIT_HINTS if h in low]

        kind = self._classify(desc)
        # Exploitability 0..10: severity weight + PoC hint presence + how
        # concrete the affected product surface is.
        exploitability = SEVERITY_ORDER.get(severity, 0) * 2
        exploitability += min(4, len(hints) * 2)
        if re.search(r"cwe-\d+", low):
            exploitability += 1
        if kind != "generic":
            exploitability += 1

        return {
            "cve": cid,
            "severity": severity.upper(),
            "cvss": cvss,
            "kind": kind,
            "summary": desc[:300],
            "references": refs[:5],
            "poc_hints": hints[:5],
            "exploitability": min(10, exploitability),
        }

    @staticmethod
    def _classify(desc: str) -> str:
        low = desc.lower()
        for kind, words in (
            ("rce", ("remote code execution", "rce", "code execution",
                     "command injection", "deserialization")),
            ("sqli", ("sql injection", "sqli")),
            ("xss", ("cross-site script", "xss")),
            ("lfi", ("local file", "path traversal", "directory traversal")),
            ("ssrf", ("server-side request", "ssrf")),
            ("auth", ("authentication bypass", "privilege escalation")),
        ):
            if any(w in low for w in words):
                return kind
        return "generic"
