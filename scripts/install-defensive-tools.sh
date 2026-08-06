#!/usr/bin/env bash
#
# install-defensive-tools.sh - optional installer for the DEFENSIVE tools in the
# NexHunter registry that are commonly missing on a fresh box.
#
# Scope, on purpose:
#   * Passive/active reconnaissance, enumeration, TLS review, and read-only
#     static/dependency analysis -- the tools an authorized assessment starts
#     with and the ones NexHunter's recon/osint/code profiles surface.
#   * NOT included: intrusive scanners (sqlmap, ffuf, nikto, gobuster, hydra,
#     ...), exploitation frameworks, C2, payload/evasion generators, or anything
#     offensive. Install those yourself, deliberately, only where authorized.
#
# NexHunter itself never installs binaries. This is a convenience script you run
# by hand, after reading it. It needs: apt (Debian/Kali/Parrot), Go, and pipx.
#
# Usage:
#   ./scripts/install-defensive-tools.sh          # install everything below
#   ./scripts/install-defensive-tools.sh --dry-run
#
set -euo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

run() {
  echo "  \$ $*"
  [[ $DRY_RUN -eq 1 ]] || "$@"
}

have() { command -v "$1" >/dev/null 2>&1; }

echo "== NexHunter defensive-tool installer =="
[[ $DRY_RUN -eq 1 ]] && echo "(dry run: nothing will be installed)"

# --- apt: recon, DNS, TLS, OSINT, forensics helpers -------------------------
APT_PKGS=(
  whois dnsutils         # whois_lookup, dns_lookup, dig_axfr
  dnsrecon               # DNS enumeration
  sslscan                # sslscan
  wafw00f                # WAF fingerprint
  whatweb                # web tech id
  exiftool               # metadata
  binwalk foremost       # forensics carving
  masscan                # fast port sweep (passive-ish, no service probing)
)
if have apt-get; then
  echo "-- apt packages --"
  run sudo apt-get update
  for pkg in "${APT_PKGS[@]}"; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
      echo "  [have] $pkg"
    else
      run sudo apt-get install -y "$pkg"
    fi
  done
else
  echo "-- apt not found, skipping system packages --"
fi

# --- Go: ProjectDiscovery + tomnomnom recon suite ---------------------------
# These are the tools NexHunter's recon profile leans on and that this repo's
# newly-matured specs (subfinder, httpx, naabu, dnsx, katana, gau, waybackurls)
# parse. All are passive/active recon, no exploitation.
GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
)
if have go; then
  echo "-- go tools (installed to \$(go env GOPATH)/bin) --"
  for mod in "${GO_TOOLS[@]}"; do
    run go install -v "$mod"
  done
  echo "  note: ensure \$(go env GOPATH)/bin is on your PATH"
else
  echo "-- go not found, skipping Go recon suite (install Go, then re-run) --"
fi

# --- pipx: read-only static / dependency analysis ---------------------------
PIPX_TOOLS=(bandit semgrep checkov pip-audit)
if have pipx; then
  echo "-- pipx static-analysis tools --"
  for tool in "${PIPX_TOOLS[@]}"; do
    if have "$tool"; then echo "  [have] $tool"; else run pipx install "$tool"; fi
  done
else
  echo "-- pipx not found, skipping SAST tools (python -m pip install pipx) --"
fi

echo
echo "Done. Verify with:  python -m nexhunter.cli.client doctor"
