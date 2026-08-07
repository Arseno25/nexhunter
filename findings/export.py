"""Finding export: JSON, JSONL, Markdown, HTML, SARIF."""

import html
import json
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from nexhunter.findings import attack
from nexhunter.findings.models import Category, Finding, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spectool-schema/main/sarif-schema-2.1.0.json"

# SARIF has three levels plus "none"; the five-level scale collapses onto them.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def to_json(findings: Sequence[Finding], indent: int = 2) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=indent)


def to_jsonl(findings: Sequence[Finding]) -> str:
    """One finding per line, for streaming into a pipeline."""
    return "\n".join(json.dumps(f.to_dict(), separators=(",", ":")) for f in findings)


def to_markdown(findings: Sequence[Finding], title: str = "Security Assessment Findings") -> str:
    """A report a human reads.

    Observations and parser failures are kept in their own sections rather than
    mixed into the vulnerability list, because a reader skimming for problems
    should not have to sort facts from findings.
    """
    lines = [f"# {title}", ""]
    lines.append(f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    lines.append("")

    vulnerabilities = [f for f in findings if f.is_vulnerability]
    observations = [f for f in findings if f.category == Category.OBSERVATION.value]
    failures = [f for f in findings if f.category == Category.PARSER_FAILURE.value]

    counts = {level: sum(1 for f in vulnerabilities if f.severity is level) for level in _SEVERITY_ORDER}
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for level in _SEVERITY_ORDER:
        lines.append(f"| {level.value.title()} | {counts[level]} |")
    lines.append(f"| **Total findings** | **{len(vulnerabilities)}** |")
    lines.append("")
    lines.append(f"Plus {len(observations)} observation(s) and {len(failures)} parser failure(s).")
    lines.append("")

    if vulnerabilities:
        lines.append("## Findings")
        lines.append("")
        for finding in vulnerabilities:
            lines.append(f"### [{finding.severity.value.upper()}] {finding.title}")
            lines.append("")
            lines.append(f"- **Target:** `{finding.target}`")
            lines.append(f"- **Tool:** {finding.tool}")
            lines.append(f"- **Confidence:** {finding.confidence.value}")
            if finding.location:
                lines.append(f"- **Location:** `{finding.location}`")
            if finding.cvss_score is not None:
                lines.append(f"- **CVSS:** {finding.cvss_score}")
            if finding.cve_ids:
                lines.append(f"- **CVE:** {', '.join(finding.cve_ids)}")
            if finding.cwe_ids:
                lines.append(f"- **CWE:** {', '.join(finding.cwe_ids)}")
            if finding.attack_ids:
                labeled = ", ".join(
                    f"{technique} ({attack.attack_name(technique)})" if attack.attack_name(technique) else technique
                    for technique in finding.attack_ids
                )
                lines.append(f"- **MITRE ATT&CK:** {labeled}")
            lines.append(f"- **First seen:** {finding.first_seen_at.isoformat(timespec='seconds')}")
            lines.append("")
            if finding.description:
                lines.append(finding.description)
                lines.append("")
            if finding.evidence:
                lines.append("**Evidence**")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(finding.evidence, indent=2))
                lines.append("```")
                lines.append("")
            if finding.artifacts:
                lines.append("**Evidence artifacts**")
                lines.append("")
                for artifact in finding.artifacts:
                    lines.append(f"- `{artifact}`")
                lines.append("")
            if finding.remediation:
                lines.append(f"**Remediation:** {finding.remediation}")
                lines.append("")
            if finding.references:
                lines.append("**References**")
                lines.append("")
                for reference in finding.references:
                    lines.append(f"- {reference}")
                lines.append("")

    if observations:
        lines.append("## Observations")
        lines.append("")
        lines.append("Facts recorded about the target. These are not findings.")
        lines.append("")
        lines.append("| Target | Observation | Tool |")
        lines.append("|---|---|---|")
        for finding in observations:
            lines.append(f"| `{finding.target}` | {finding.title} | {finding.tool} |")
        lines.append("")

    if failures:
        lines.append("## Parser failures")
        lines.append("")
        lines.append(
            "Output that could not be read. These are **not** clean results: "
            "the tool ran, but its findings are unknown."
        )
        lines.append("")
        for finding in failures:
            lines.append(f"- `{finding.target}` — {finding.tool}: {finding.description}")
        lines.append("")

    if not findings:
        lines.append("_No findings recorded._")
        lines.append("")

    return "\n".join(lines)


def to_html(findings: Sequence[Finding], title: str = "Security Assessment Findings") -> str:
    """Self-contained HTML report. Every interpolated value is escaped."""
    severity_colors = {
        Severity.CRITICAL: "#dc2626",
        Severity.HIGH: "#ea580c",
        Severity.MEDIUM: "#d97706",
        Severity.LOW: "#0891b2",
        Severity.INFO: "#6b7280",
    }
    vulnerabilities = [f for f in findings if f.is_vulnerability]
    counts = {level: sum(1 for f in vulnerabilities if f.severity is level) for level in _SEVERITY_ORDER}

    rows = []
    for finding in findings:
        color = severity_colors[finding.severity]
        rows.append(
            "<tr>"
            f'<td><span class="sev" style="background:{color}">{html.escape(finding.severity.value)}</span></td>'
            f"<td>{html.escape(finding.title)}</td>"
            f"<td><code>{html.escape(finding.target)}</code></td>"
            f"<td>{html.escape(finding.tool)}</td>"
            f"<td>{html.escape(finding.confidence.value)}</td>"
            f"<td>{html.escape(finding.category)}</td>"
            f"<td>{html.escape(', '.join(finding.attack_ids))}</td>"
            f"<td>{html.escape(', '.join(finding.artifacts))}</td>"
            "</tr>"
        )

    chips = "".join(
        f'<span class="chip" style="background:{severity_colors[level]}">{level.value.title()}: {counts[level]}</span>'
        for level in _SEVERITY_ORDER
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.6 system-ui, -apple-system, sans-serif; margin: 0; padding: 2rem;
         background: Canvas; color: CanvasText; }}
  h1 {{ margin: 0 0 .25rem; font-size: 1.6rem; }}
  .meta {{ opacity: .7; font-size: .875rem; margin-bottom: 1.5rem; }}
  .chip, .sev {{ display: inline-block; padding: .15rem .6rem; border-radius: 999px;
                 color: #fff; font-size: .8rem; font-weight: 600; }}
  .chip {{ margin: 0 .4rem .4rem 0; }}
  .wrap {{ overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; min-width: 640px; margin-top: 1.5rem; }}
  th, td {{ text-align: left; padding: .55rem .75rem;
            border-bottom: 1px solid color-mix(in srgb, CanvasText 15%, transparent); }}
  th {{ font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; opacity: .7; }}
  code {{ font-size: .875em; }}
  .empty {{ opacity: .7; font-style: italic; margin-top: 2rem; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<div class="meta">Generated {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")} ·
  {len(vulnerabilities)} finding(s), {len(findings)} record(s) total</div>
<div>{chips}</div>
<div class="wrap">
<table>
<thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>Tool</th><th>Confidence</th><th>Category</th><th>ATT&amp;CK</th><th>Evidence</th></tr></thead>
<tbody>{"".join(rows) if rows else '<tr><td colspan="8" class="empty">No findings recorded.</td></tr>'}</tbody>
</table>
</div>
</body>
</html>"""


def to_sarif(findings: Sequence[Finding], tool_name: str = "NexHunter") -> str:
    """SARIF 2.1.0, for code and dependency findings in CI.

    Each distinct finding title becomes a rule, and each finding an occurrence
    of it, which is the shape SARIF consumers expect.
    """
    rules: dict[str, dict[str, Any]] = {}
    results = []

    for finding in findings:
        rule_id = finding.title.strip().lower().replace(" ", "-")[:64] or "finding"

        if rule_id not in rules:
            rule: dict[str, Any] = {
                "id": rule_id,
                "name": finding.title[:120],
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description or finding.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
                "properties": {
                    "category": finding.category,
                    "tags": [finding.category, finding.tool, *finding.attack_ids],
                },
            }
            if finding.cwe_ids:
                rule["properties"]["cwe"] = list(finding.cwe_ids)
            if finding.attack_ids:
                rule["properties"]["attack"] = list(finding.attack_ids)
            if finding.references:
                rule["helpUri"] = finding.references[0]
            rules[rule_id] = rule

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": finding.description or finding.title},
            "fingerprints": {"nexhunter/v1": finding.fingerprint},
            "properties": {
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "target": finding.target,
                "tool": finding.tool,
                "attack_ids": finding.attack_ids,
                "artifacts": finding.artifacts,
            },
        }
        if finding.cve_ids:
            result["properties"]["cve"] = finding.cve_ids
        if finding.cvss_score is not None:
            result["properties"]["cvss"] = finding.cvss_score

        # SARIF locations are file-shaped. A network target has no file, so it
        # is reported as a logical location rather than invented as a path.
        if (
            finding.location
            and finding.category in {Category.SECRET.value, Category.VULNERABILITY.value}
            and ("/" in finding.location or "\\" in finding.location)
        ):
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.location.replace("\\", "/")},
                    }
                }
            ]
        else:
            result["locations"] = [
                {
                    "logicalLocations": [
                        {
                            "name": finding.location or finding.target,
                            "kind": "resource",
                        }
                    ]
                }
            ]

        results.append(result)

    return json.dumps(
        {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "informationUri": "https://github.com/Arseno25/nexhunter",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        },
        indent=2,
    )


FORMATS = {
    "json": to_json,
    "jsonl": to_jsonl,
    "markdown": to_markdown,
    "md": to_markdown,
    "html": to_html,
    "sarif": to_sarif,
}


def export(findings: Sequence[Finding], fmt: str = "json") -> str:
    """Render findings in the named format."""
    key = (fmt or "json").strip().lower()
    if key not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; available: {', '.join(sorted(FORMATS))}")
    return FORMATS[key](findings)
