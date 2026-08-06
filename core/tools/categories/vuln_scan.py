"""Vulnerability scanners tool specs."""

from .._spec import ToolSpec


TOOLS = {
    "nessus":     ToolSpec(
            name="nessus",
            binary="nessusd",
            description="Vulnerability assessment",
            params={"target": None},
            timeout=600,
            builder=lambda p: ["nessusd", "-q", p["target"]],
        ),
    "qualys":     ToolSpec(
            name="qualys",
            binary="qualys-cli",
            description="Qualys vulnerability scanner",
            params={"target": None},
            timeout=600,
            builder=lambda p: ["qualys-cli", "scan", p["target"]],
        ),
    "openvas":     ToolSpec(
            name="openvas",
            binary="openvassd",
            description="OpenVAS vulnerability scanner",
            params={"target": None},
            timeout=600,
            builder=lambda p: ["openvassd", p["target"]],
        ),
    "w3af":     ToolSpec(
            name="w3af",
            binary="w3af",
            description="Web attack and audit framework",
            params={"url": None},
            timeout=600,
            builder=lambda p: ["w3af", "-s", p["url"]],
        ),
    "arachni":     ToolSpec(
            name="arachni",
            binary="arachni",
            description="Full-featured web application vulnerability scanner",
            params={"url": None, "report": "arachni-report.html"},
            timeout=900,
            builder=lambda p: ["arachni", "--output-verbose", p["url"], "--report-save-path", p["report"]],
        ),
    "skipfish":     ToolSpec(
            name="skipfish",
            binary="skipfish",
            description="High-speed web application security scanner",
            params={"url": None, "output_dir": "skipfish-out"},
            timeout=900,
            builder=lambda p: ["skipfish", "-o", p["output_dir"], p["url"]],
        ),
    "wapiti":     ToolSpec(
            name="wapiti",
            binary="wapiti",
            description="Web application vulnerability scanner with a crawl engine",
            params={"url": None},
            timeout=900,
            builder=lambda p: ["wapiti", "-u", p["url"], "-f", "html"],
        ),
}
