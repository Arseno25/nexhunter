"""Cryptography & TLS tool specs."""

from .._spec import ToolSpec


TOOLS = {
    "openssl":     ToolSpec(
                name="openssl",
                binary="openssl",
                description="SSL/TLS certificate checker",
                params={"host": None, "port": "443"},
                timeout=15,
                builder=lambda p: ["openssl", "s_client", "-connect", f"{p['host']}:{p['port']}", "-showcerts"],
            ),
    "sslscan":     ToolSpec(
                name="sslscan",
                binary="sslscan",
                description="SSL/TLS cipher suite enumeration",
                params={"host": None, "port": "443"},
                timeout=120,
                builder=lambda p: ["sslscan", f"{p['host']}:{p['port']}"],
            ),
    "sslyze":     ToolSpec(
                name="sslyze",
                binary="sslyze",
                description="SSL/TLS configuration analyzer",
                params={"host": None},
                timeout=300,
                parser="sslyze",
                builder=lambda p: ["sslyze", "--regular", p["host"]],
            ),
}
