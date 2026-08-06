"""Payload generation tool specs."""

from .._spec import ToolSpec


TOOLS = {
    "evasion":     ToolSpec(
            name="evasion",
            binary="veil",
            description="Obfuscation/evasion tool",
            params={"payload": None},
            timeout=60,
            builder=lambda p: ["veil", p["payload"]],
        ),
    "beef":     ToolSpec(
            name="beef",
            binary="beef",
            description="Browser exploitation framework",
            params={"url": None},
            timeout=300,
            builder=lambda p: ["beef", p["url"]],
        ),
    "veil":     ToolSpec(
            name="veil",
            binary="veil",
            description="AV evasion tool",
            params={"payload": None},
            timeout=120,
            builder=lambda p: ["veil", p["payload"]],
        ),
    "unicorn":     ToolSpec(
            name="unicorn",
            binary="unicorn",
            description="PowerShell obfuscator",
            params={"script": None},
            timeout=60,
            builder=lambda p: ["unicorn", p["script"]],
        ),
    "chimera":     ToolSpec(
            name="chimera",
            binary="chimera",
            description="Payload obfuscator",
            params={"payload": None},
            timeout=60,
            builder=lambda p: ["chimera", p["payload"]],
        ),
    "social_engineer_toolkit":     ToolSpec(
            name="social_engineer_toolkit",
            binary="setoolkit",
            description="Social engineering toolkit",
            params={"attack": None},
            timeout=300,
            builder=lambda p: ["setoolkit", p["attack"]],
        ),
    "phishing_framework":     ToolSpec(
            name="phishing_framework",
            binary="gophish",
            description="Phishing framework",
            params={"config": None},
            timeout=60,
            builder=lambda p: ["gophish", "-config", p["config"]],
        ),
    "mimikatz":     ToolSpec(
            name="mimikatz",
            binary="mimikatz",
            description="Credential extraction from Windows memory",
            params={"action": "sekurlsa::logonpasswords"},
            timeout=60,
            risk_level="intrusive",
            builder=lambda p: ["mimikatz", p["action"]],
        ),
    "hoaxshell":     ToolSpec(
            name="hoaxshell",
            binary="python3",
            description="Generate a PowerShell reverse shell payload (hoaxshell.py)",
            params={"lhost": "127.0.0.1", "lport": "4444", "output": "shell.ps1"},
            timeout=60,
            risk_level="intrusive",
            builder=lambda p: ["python3", "hoaxshell.py", "-s", p["lhost"], "-p", p["lport"], "-o", p["output"]],
        ),
}
