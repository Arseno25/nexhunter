# NexHunter

> Advanced AI-Driven Security Assessment Platform

![Version](https://img.shields.io/badge/version-3.1.0-blue) ![Python](https://img.shields.io/badge/python-3.8+-green) ![Tools](https://img.shields.io/badge/tools-164-blue) ![Tests](https://img.shields.io/badge/tests-100%25-green)

---

## ⚡ Quick Start

```bash
# Install
git clone https://github.com/Arseno25/nexhunter.git
cd nexhunter
pip install -r requirements.txt

# Run server
python -m nexhunter.api.server --port 8888

# Test
python nexhunter.py assess https://example.com
```

---

## 🎯 Features

| Feature | Details |
|---------|---------|
| **AI Agents** | 18 total (13 core + 5 enhanced) |
| **Security Tools** | 164 integrated tools |
| **Workflows** | 9 assessment types (73 phases) |
| **API** | 30+ REST endpoints |
| **MCP** | 184 tools for any AI model |
| **Testing** | 12/12 tests (100% coverage) |

---

## 📋 Usage

### CLI

```bash
python nexhunter.py assess https://example.com           # Full assessment
python nexhunter.py probe https://example.com            # Quick probe
python nexhunter.py osint example.com                    # Reconnaissance
python nexhunter.py analyze-vulns example.com            # Analysis
python nexhunter.py bugbounty-pro example.com            # Bug bounty workflow
python nexhunter.py dashboard                            # View results
```

### REST API

```bash
# Start server
python -m nexhunter.api.server --port 8888

# Full assessment
curl -X POST http://localhost:8888/api/assess \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# Get results
curl http://localhost:8888/api/findings
curl http://localhost:8888/api/visual/dashboard
```

### MCP - Universal (Claude, Grok, Gemini, etc)

**Step 1:** Start Server
```bash
python -m nexhunter.api.server --port 8888
```

**Step 2:** Start MCP Bridge
```bash
python -m nexhunter.api.mcp --server http://127.0.0.1:8888
```

**Step 3:** Integrate with AI Model

**Claude Desktop** - Edit `~/.claude/config.json`
```json
{
  "mcpServers": {
    "nexhunter": {
      "command": "python",
      "args": ["-m", "nexhunter.api.mcp", "--server", "http://127.0.0.1:8888"],
      "timeout": 300
    }
  }
}
```

**Grok/Other AI Models** - Use stdin/stdout protocol
```bash
# Start MCP server
python -m nexhunter.api.mcp --server http://127.0.0.1:8888

# MCP responds with available tools
# AI model parses and uses tools via JSON-RPC
```

**Generic MCP Client**
```python
import subprocess
import json

# Start MCP bridge
proc = subprocess.Popen(
    ["python", "-m", "nexhunter.api.mcp", "--server", "http://127.0.0.1:8888"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    text=True
)

# Send tool request
request = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {"name": "assess", "arguments": {"target": "example.com"}},
    "id": 1
}

proc.stdin.write(json.dumps(request) + "\n")
response = proc.stdout.readline()
print(json.loads(response))
```

---

## 🛠️ Available Tools (164)

| Category | Count | Tools |
|----------|-------|-------|
| **Reconnaissance** | 11 | nmap, masscan, rustscan, subfinder, amass, shodan, dns, whois |
| **Web Scanning** | 13 | nuclei, ffuf, gobuster, sqlmap, nikto, dalfox, burp, zap |
| **Network** | 15 | aircrack, tcpdump, tshark, enum4linux, smbmap, ldapsearch |
| **Cryptography** | 5 | hashid, john, hashcat, openssl, testssl |
| **Forensics** | 8 | volatility, sleuthkit, autopsy, binwalk, exiftool |
| **Binary Analysis** | 10 | ghidra, radare2, objdump, readelf, checksec |
| **Cloud/DevOps** | 11 | kube-bench, trivy, docker, kubectl, aws-cli, gcloud |
| **Code Analysis** | 5 | semgrep, bandit, pylint, sonarqube, checkmarx |
| **Exploitation** | 6 | metasploit, empire, cobalt-strike, havoc, sliver |
| **Other** | 80+ | mobile, IDS/IPS, secrets, compliance, evasion, etc |

---

## 🔄 Workflows (9 Types)

```
Bug Bounty (10)      → Reconnaissance → Subdomain → Port Scan → Service Detect → Web Scan
Pentest (8)          → Scoping → Reconnaissance → Scanning → Exploitation → Reporting
API Security (10)    → Discovery → Auth → Input Validation → Rate Limiting → Headers
Cloud Security (8)   → Inventory → IAM → Network → Encryption → Compliance
Red Team (6) • Security Audit (7) • Mobile (8) • Supply Chain (7) • DevSecOps (8)
```

---

## 🔌 API Endpoints

**Assessment:** `/api/assess`, `/api/probe`, `/api/portscan`, `/api/webscan`, `/api/recon`

**Workflows:** `/api/flow/bugbounty-pro`, `/api/flow/ctf`, `/api/intelligence/osint`, `/api/intelligence/vulnerability-analysis`

**Results:** `/api/findings`, `/api/report`, `/api/visual/dashboard`, `/api/visual/vulnerabilities`

**System:** `/api/health`, `/api/telemetry`, `/api/cache/stats`, `/api/processes/list`

---

## ⚙️ Configuration

**File:** `core/config.py`

```python
CACHE_MAX = 128                     # LRU cache size
MAX_PARALLEL_WORKERS = 4            # Concurrent tools
RATE_LIMIT_ENABLED = True           # Request throttling
FINDING_DEDUP_ENABLED = True        # Duplicate prevention

TOOL_TIMEOUTS = {
    "nmap_scan": 300,
    "nuclei_scan": 600,
}
```

---

## 🔐 Security

✓ Authorization-first  
✓ XXE protection  
✓ Safe command execution  
✓ Input validation  
✓ Rate limiting  
✓ No hardcoded secrets  

---

## 📊 Stats

| Metric | Value |
|--------|-------|
| AI Agents | 18 |
| Security Tools | 164 |
| Workflows | 9 |
| Phases | 73 |
| API Endpoints | 30+ |
| MCP Tools | 184 |
| Test Coverage | 100% |

---

## 📦 Requirements

Python 3.8+, requests >= 2.28.0, urllib3 >= 1.26.0

---

<div align="center">

**NexHunter v3.1.0** — Security Assessment Platform

GitHub: https://github.com/Arseno25/nexhunter

</div>
