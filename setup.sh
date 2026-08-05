#!/usr/bin/env bash
# nexhunter one-command setup (Linux/macOS/WSL).
# Creates a venv, installs the package with MCP + browser extras, runs the
# doctor check, and prints the next steps.
set -euo pipefail

cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
VENV=".venv"

echo "[1/4] creating venv at $VENV"
"$PY" -m venv "$VENV"

if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    PY_VENV="$VENV/Scripts/python"
else
    PY_VENV="$VENV/bin/python"
fi

echo "[2/4] installing nexhunter with mcp + browser extras"
"$PY_VENV" -m pip install --upgrade pip
"$PY_VENV" -m pip install -e ".[mcp,browser]"

echo "[3/4] verifying the installation"
"$PY_VENV" -m nexhunter.cli.client doctor || true

echo "[4/4] done"
cat <<'EOF'

Start the server:
    .venv/bin/python -m nexhunter.api.server --port 8888

Then the MCP bridge (pick a profile):
    .venv/bin/python -m nexhunter.api.mcp --profile nexhunter-recon

Or on Windows (pwsh):
    setup.ps1
EOF
