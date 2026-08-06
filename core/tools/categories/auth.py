"""Authentication & password-attack tool specs (brute force, hash cracking,
 credential-based lateral movement)."""

from .._spec import ToolSpec


TOOLS = {
    "hashid":     ToolSpec(
                name="hashid",
                binary="hash-identifier",
                description="Hash type identifier",
                params={"hash": None},
                timeout=5,
                builder=lambda p: ["hash-identifier", p["hash"]],
            ),
    "john":     ToolSpec(
                name="john",
                binary="john",
                description="Hash cracker (John the Ripper)",
                params={"hashfile": None},
                timeout=600,
                builder=lambda p: ["john", p["hashfile"]],
            ),
    "hashcat":     ToolSpec(
                name="hashcat",
                binary="hashcat",
                description="GPU hash cracker",
                params={"hashfile": None},
                timeout=600,
                builder=lambda p: ["hashcat", "-m", "0", p["hashfile"]],
            ),
    "hydra":     ToolSpec(
                name="hydra",
                binary="hydra",
                description="Brute force authentication",
                params={"target": None, "service": "ssh"},
                timeout=300,
                builder=lambda p: [
                    "hydra",
                    "-l",
                    "admin",
                    "-P",
                    "/usr/share/wordlists/passwords.txt",
                    f"{p['service']}://{p['target']}",
                ],
            ),
    "medusa":     ToolSpec(
                name="medusa",
                binary="medusa",
                description="Parallel authentication brute force",
                params={"target": None, "service": "ssh"},
                timeout=300,
                builder=lambda p: ["medusa", "-h", p["target"], "-M", p["service"]],
            ),
    "ncrack":     ToolSpec(
                name="ncrack",
                binary="ncrack",
                description="Network authentication cracker",
                params={"target": None},
                timeout=300,
                builder=lambda p: ["ncrack", "-p", "22", p["target"]],
            ),
    "patator":     ToolSpec(
                name="patator",
                binary="patator",
                description="Multi-protocol brute forcer",
                params={"target": None},
                timeout=300,
                builder=lambda p: ["patator", "http_get", f"url=http://{p['target']}", "auth=basic"],
            ),
    "evil_winrm":     ToolSpec(
                name="evil_winrm",
                binary="evil-winrm",
                description="Windows Remote Management shell",
                params={"host": None, "user": None, "password": ""},
                timeout=600,
                builder=lambda p: (
                    ["evil-winrm", "-i", p["host"], "-u", p["user"]] + (["-p", p["password"]] if p["password"] else [])
                ),
            ),
    "netexec_smb":     ToolSpec(
                name="netexec_smb",
                binary="netexec",
                description="SMB enumeration and validation",
                params={"host": None},
                timeout=300,
                builder=lambda p: ["netexec", "smb", p["host"]],
            ),
    "cme":     ToolSpec(
                name="cme",
                binary="crackmapexec",
                description="Post-exploitation framework",
                params={"protocol": "smb", "target": None},
                timeout=120,
                builder=lambda p: ["crackmapexec", p["protocol"], p["target"]],
            ),
}
