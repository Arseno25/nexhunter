"""Privilege escalation tool specs."""

from .._spec import ToolSpec


TOOLS = {
    "winpeas":     ToolSpec(
            name="winpeas",
            binary="winPEAS",
            description="Windows privilege escalation tool",
            params={},
            timeout=120,
            builder=lambda p: ["winPEAS"],
        ),
    "linpeas":     ToolSpec(
            name="linpeas",
            binary="bash",
            description="Linux privilege escalation tool (linpeas.sh)",
            params={},
            timeout=120,
            builder=lambda p: ["bash", "linpeas.sh"],
        ),
    "pspy":     ToolSpec(
            name="pspy",
            binary="pspy",
            description="Process monitoring tool",
            params={},
            timeout=60,
            builder=lambda p: ["pspy"],
        ),
    "dirty_cow":     ToolSpec(
            name="dirty_cow",
            binary="dirty_cow",
            description="Linux kernel exploit",
            params={"binary": None},
            timeout=60,
            risk_level="destructive",
            builder=lambda p: ["./dirty_cow", p["binary"]],
        ),
    "linux_exploit_suggester":     ToolSpec(
            name="linux_exploit_suggester",
            binary="bash",
            description="Suggest local privilege escalation exploits for the current host",
            params={},
            timeout=60,
            risk_level="passive",
            builder=lambda p: ["bash", "linux-exploit-suggester.sh"],
        ),
    "traitor":     ToolSpec(
            name="traitor",
            binary="traitor",
            description="Find and run local privilege escalation exploits",
            params={},
            timeout=120,
            risk_level="passive",
            builder=lambda p: ["traitor", "--exploits"],
        ),
    "suid_find":     ToolSpec(
            name="suid_find",
            binary="find",
            description="Find SUID binaries on the host",
            params={},
            timeout=120,
            builder=lambda p: ["find", "/", "-perm", "-4000", "-type", "f", "-exec", "ls", "-l", "{}", "+"],
        ),
}
