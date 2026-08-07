"""Optional installer for registry tool binaries, used by ``doctor --install``.

NexHunter's default stays hands-off: doctor reports, it never changes the
system. ``--install`` is an explicit opt-in that runs the known install recipe
for each missing tool through the system's own package sources -- apt, ``go
install``, or ``pipx`` -- the same sources scripts/install-defensive-tools.sh
uses.

Recipes are a fixed table keyed by binary name; the target is never derived
from user input, so the argv handed to each installer is not attacker
-controllable. A binary with no recipe is reported as manual, never guessed at
with a fragile ``curl | sh``.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

APT = "apt"
GO = "go"
PIPX = "pipx"


@dataclass(frozen=True)
class Recipe:
    """How to install one binary. ``target`` is an apt package, a go module
    (``module@version``), or a pipx package."""

    method: str
    target: str


# binary name (ToolSpec.binary) -> install recipe. Confident entries only:
# standard apt packages on Debian/Kali/Parrot, ProjectDiscovery/tomnomnom go
# modules, and pipx-installable Python tools. Anything not here is reported as
# "manual" rather than guessed.
INSTALL_RECIPES: dict[str, Recipe] = {
    # --- apt (Debian/Kali/Parrot) ------------------------------------------
    "whois": Recipe(APT, "whois"),
    "dig": Recipe(APT, "dnsutils"),
    "host": Recipe(APT, "dnsutils"),
    "nslookup": Recipe(APT, "dnsutils"),
    "dnsrecon": Recipe(APT, "dnsrecon"),
    "sslscan": Recipe(APT, "sslscan"),
    "wafw00f": Recipe(APT, "wafw00f"),
    "whatweb": Recipe(APT, "whatweb"),
    "exiftool": Recipe(APT, "exiftool"),
    "binwalk": Recipe(APT, "binwalk"),
    "foremost": Recipe(APT, "foremost"),
    "masscan": Recipe(APT, "masscan"),
    "nmap": Recipe(APT, "nmap"),
    "nikto": Recipe(APT, "nikto"),
    "sqlmap": Recipe(APT, "sqlmap"),
    "hydra": Recipe(APT, "hydra"),
    "dirb": Recipe(APT, "dirb"),
    "wfuzz": Recipe(APT, "wfuzz"),
    "ffuf": Recipe(APT, "ffuf"),
    "feroxbuster": Recipe(APT, "feroxbuster"),
    "john": Recipe(APT, "john"),
    "hashcat": Recipe(APT, "hashcat"),
    "tshark": Recipe(APT, "tshark"),
    "tcpdump": Recipe(APT, "tcpdump"),
    "testssl.sh": Recipe(APT, "testssl.sh"),
    "wpscan": Recipe(APT, "wpscan"),
    # --- go (ProjectDiscovery + tomnomnom recon suite) ---------------------
    "subfinder": Recipe(GO, "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "httpx": Recipe(GO, "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "dnsx": Recipe(GO, "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "naabu": Recipe(GO, "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "katana": Recipe(GO, "github.com/projectdiscovery/katana/cmd/katana@latest"),
    "nuclei": Recipe(GO, "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "gobuster": Recipe(GO, "github.com/OJ/gobuster/v3@latest"),
    "assetfinder": Recipe(GO, "github.com/tomnomnom/assetfinder@latest"),
    "waybackurls": Recipe(GO, "github.com/tomnomnom/waybackurls@latest"),
    "gau": Recipe(GO, "github.com/lc/gau/v2/cmd/gau@latest"),
    "dalfox": Recipe(GO, "github.com/hahwul/dalfox/v2@latest"),
    "amass": Recipe(GO, "github.com/owasp-amass/amass/v4/...@master"),
    # --- pipx (read-only static / dependency analysis, cloud CLI) ----------
    "bandit": Recipe(PIPX, "bandit"),
    "semgrep": Recipe(PIPX, "semgrep"),
    "checkov": Recipe(PIPX, "checkov"),
    "pip-audit": Recipe(PIPX, "pip-audit"),
    "aws": Recipe(PIPX, "awscli"),
    "arjun": Recipe(PIPX, "arjun"),
    "paramspider": Recipe(PIPX, "paramspider"),
    "dirsearch": Recipe(PIPX, "dirsearch"),
}


def recipe_for(binary: str) -> Recipe | None:
    return INSTALL_RECIPES.get(binary)


def command_for(recipe: Recipe) -> list[str]:
    """Build the argv for a recipe. Fixed shapes, table-driven target only."""
    if recipe.method == APT:
        return ["sudo", "apt-get", "install", "-y", recipe.target]
    if recipe.method == GO:
        return ["go", "install", "-v", recipe.target]
    if recipe.method == PIPX:
        return ["pipx", "install", recipe.target]
    raise ValueError(f"unknown install method: {recipe.method}")


def command_str(recipe: Recipe) -> str:
    return " ".join(command_for(recipe))


# The executable that must be on PATH for each method's install to run.
_METHOD_BINARY = {APT: "apt-get", GO: "go", PIPX: "pipx"}


def method_available(method: str) -> bool:
    return shutil.which(_METHOD_BINARY.get(method, method)) is not None
