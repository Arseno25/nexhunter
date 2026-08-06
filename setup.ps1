# nexhunter one-command setup (Windows PowerShell).
# Creates a venv, installs the package with MCP + browser extras, runs the
# doctor check, and prints the next steps.
$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

$Python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
$Venv = ".venv"

Write-Host "[1/4] creating venv at $Venv"
& $Python -m venv $Venv
if ($LASTEXITCODE -ne 0) { Write-Error "venv creation failed"; exit 1 }

$PyVenv = Join-Path $Venv "Scripts\python.exe"

Write-Host "[2/4] installing nexhunter with api + mcp + browser extras"
& $PyVenv -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { Write-Error "pip upgrade failed"; exit 1 }
& $PyVenv -m pip install -e ".[api,mcp,browser]"
if ($LASTEXITCODE -ne 0) { Write-Error "package install failed"; exit 1 }

Write-Host "[3/4] verifying the installation"
& $PyVenv -m nexhunter.cli.client doctor
if ($LASTEXITCODE -ne 0) { Write-Error "doctor check failed"; exit 1 }

Write-Host "[4/4] done"
@"

Start the server:
    .venv\Scripts\python.exe -m nexhunter.api.server --port 8888

Then the MCP bridge (pick a profile):
    .venv\Scripts\python.exe -m nexhunter.api.mcp --profile nexhunter-recon

"@
