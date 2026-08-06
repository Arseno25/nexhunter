"""nexhunter.core.tools - security tools registry with ToolSpec pattern.

Split by category under categories/ to keep files reviewable; this module
re-assembles the flat TOOLS dict and re-exports the same public API the
single-file module used to, so `from nexhunter.core import tools as T`
call sites elsewhere are unaffected.
"""

from ._spec import (
    ShellCommand as ShellCommand,
    ToolSpec,
    STABLE_TOOLS as STABLE_TOOLS,
    EXPERIMENTAL_TOOLS as EXPERIMENTAL_TOOLS,
    _CHROME_BINARIES as _CHROME_BINARIES,
    browser_engine_available as browser_engine_available,
)
from ._parsers import PARSERS as PARSERS
from ._runtime import run as run, which as which

from .categories import api as _api
from .categories import auth as _auth
from .categories import binary as _binary
from .categories import cloud as _cloud
from .categories import code as _code
from .categories import container as _container
from .categories import crypto as _crypto
from .categories import ctf as _ctf
from .categories import exploitation as _exploitation
from .categories import forensics as _forensics
from .categories import ids as _ids
from .categories import mobile as _mobile
from .categories import network as _network
from .categories import osint as _osint
from .categories import payloads as _payloads
from .categories import privesc as _privesc
from .categories import recon as _recon
from .categories import utility as _utility
from .categories import vuln_scan as _vuln_scan
from .categories import web as _web
from .categories import wireless as _wireless

TOOLS = {**_api.TOOLS, **_auth.TOOLS, **_binary.TOOLS, **_cloud.TOOLS, **_code.TOOLS, **_container.TOOLS, **_crypto.TOOLS, **_ctf.TOOLS, **_exploitation.TOOLS, **_forensics.TOOLS, **_ids.TOOLS, **_mobile.TOOLS, **_network.TOOLS, **_osint.TOOLS, **_payloads.TOOLS, **_privesc.TOOLS, **_recon.TOOLS, **_utility.TOOLS, **_vuln_scan.TOOLS, **_web.TOOLS, **_wireless.TOOLS}


def get_tool_spec(name: str) -> ToolSpec | None:
    """Get tool specification by name."""
    return TOOLS.get(name)


def risk_of(name: str) -> str:
    """Return the risk level string for a registered tool (default 'active')."""
    spec = TOOLS.get(name)
    return (spec.risk_level if spec else None) or "active"


def parse_output(tool: str, text: str):
    """Parse tool output using registered parser."""
    spec = get_tool_spec(tool)
    if not spec or not spec.parser:
        spec = next((s for s in TOOLS.values() if s.parser == tool), None)
    if spec and spec.parser:
        parser = PARSERS.get(spec.parser)
        return parser(text) if parser else None
    return None
