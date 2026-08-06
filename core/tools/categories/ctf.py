"""CTF-specific utilities tool specs."""

from .._spec import ToolSpec


TOOLS = {
    "pwninit":     ToolSpec(
            name="pwninit",
            binary="pwninit",
            description="Prepare a pwning challenge binary: patch, download libc, makefile",
            params={"file": None},
            timeout=60,
            risk_level="passive",
            builder=lambda p: ["pwninit", "--bin", p["file"]],
        ),
    "rsa_ctf_tool":     ToolSpec(
            name="rsa_ctf_tool",
            binary="RsaCtfTool",
            description="Attack and decode RSA CTF challenges",
            params={"public_key": None, "attack": "all"},
            timeout=300,
            risk_level="passive",
            builder=lambda p: ["RsaCtfTool", "--publickey", p["public_key"], "--attack", p["attack"]],
        ),
    "xortool":     ToolSpec(
            name="xortool",
            binary="xortool",
            description="Guess XOR key length and recover xored plaintext",
            params={"file": None, "key_length": ""},
            timeout=120,
            risk_level="passive",
            builder=lambda p: ["xortool", "-l", p["key_length"], p["file"]] if p["key_length"] else ["xortool", p["file"]],
        ),
}
