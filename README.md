# NexHunter

> Advanced AI-Driven Security Assessment Platform

![Version](https://img.shields.io/badge/version-3.1.0-blue) ![Python](https://img.shields.io/badge/python-3.8+-green) ![Tools](https://img.shields.io/badge/tools-164-blue) ![Tests](https://img.shields.io/badge/tests-100%25-green)

---

## ⚡ Quick Start

```bash
git clone https://github.com/Arseno25/nexhunter.git
cd nexhunter
pip install -r requirements.txt
python -m nexhunter.api.server --port 8888
```

---

## 🎯 Features

- **18 AI Agents** (13 core + 5 enhanced)
- **164 Security Tools** (reconnaissance, web, network, cloud, forensics, exploitation)
- **9 Assessment Workflows** (bug bounty, pentest, API, cloud, mobile, DevSecOps)
- **30+ REST API Endpoints**
- **Universal MCP Support** (Claude, Grok, Gemini, GPT-4, Llama, Mistral)
- **100% Test Coverage** (12/12 tests passing)

---

## 📋 Usage

### Option 1: Command Line

```bash
python nexhunter.py assess https://example.com           # Full assessment
python nexhunter.py probe https://example.com            # Quick probe
python nexhunter.py osint example.com                    # Reconnaissance
python nexhunter.py analyze-vulns example.com            # Vulnerability analysis
python nexhunter.py bugbounty-pro example.com            # Bug bounty workflow
python nexhunter.py dashboard                            # View results
```

### Option 2: REST API

```bash
# Start server
python -m nexhunter.api.server --port 8888

# Run assessment
curl -X POST http://localhost:8888/api/assess \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com"}'

# Get results
curl http://localhost:8888/api/findings
curl http://localhost:8888/api/visual/dashboard
```

### Option 3: MCP Integration

#### Setup Instructions

**Step 1:** Start NexHunter Server
```bash
python -m nexhunter.api.server --port 8888
```

**Step 2:** Start MCP Bridge
```bash
python -m nexhunter.api.mcp --server http://127.0.0.1:8888
```

**Step 3:** Configure AI Model

**Claude Desktop**
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
Edit `~/.claude/config.json` and restart Claude Desktop.

**Other Models** (Grok, Gemini, GPT-4, Llama, Mistral)

See [MCP Universal Guide](docs/MCP_UNIVERSAL.md) for detailed integration examples.

**Generic MCP Client**
```python
import subprocess
import json

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

**Step 4:** Use in AI Model
```
"Scan example.com with nexhunter"
→ AI model automatically uses available tools
```

---

## 🛠️ Security Tools (164)

**Categories:**
- **Reconnaissance** (11): nmap, masscan, rustscan, subfinder, amass, shodan, dns, whois
- **Web Scanning** (13): nuclei, ffuf, gobuster, nikto, sqlmap, dalfox, burpsuite, zap
- **Network** (15): aircrack, tcpdump, tshark, enum4linux, smbmap, ldapsearch
- **Cryptography** (5): hashid, john, hashcat, openssl, testssl
- **Forensics** (8): volatility, sleuthkit, autopsy, binwalk, exiftool
- **Binary Analysis** (10): ghidra, radare2, objdump, readelf, checksec
- **Cloud/DevOps** (11): kube-bench, trivy, docker, kubectl, aws-cli, gcloud
- **Code Analysis** (5): semgrep, bandit, pylint, sonarqube, checkmarx
- **Exploitation** (6): metasploit, empire, cobalt-strike, havoc, sliver
- **Other** (80+): mobile security, IDS/IPS, secrets detection, social engineering

---

## 🔄 Workflows (9 Types)

| Workflow | Phases | Target |
|----------|--------|--------|
| Bug Bounty | 10 | Web applications |
| Penetration Testing | 8 | Corporate networks |
| API Security | 10 | REST/GraphQL APIs |
| Cloud Security | 8 | AWS/Azure/GCP |
| Red Team | 6 | Adversarial simulation |
| Security Audit | 7 | Compliance & governance |
| Mobile Security | 8 | iOS/Android apps |
| Supply Chain | 7 | Dependencies |
| DevSecOps | 8 | CI/CD pipelines |

**Total Phases:** 73

---

## 🔐 Security

✓ Authorization-first design  
✓ XXE protection (defusedxml)  
✓ Safe command execution (no shell=True)  
✓ Input validation (ToolSpec)  
✓ Rate limiting  
✓ No hardcoded secrets  

---

## 📊 Stats

| Metric | Count |
|--------|-------|
| AI Agents | 18 |
| Security Tools | 164 |
| Workflows | 9 |
| Assessment Phases | 73 |
| API Endpoints | 30+ |
| CLI Commands | 15+ |
| MCP Tools | 184 |
| Test Coverage | 100% |

---

## 📚 Documentation

- **[Complete Guide](docs/README.md)** — Full reference
- **[Tools Reference](docs/TOOLS.md)** — All 164 tools
- **[Workflows](WORKFLOWS.md)** — Workflow specifications
- **[MCP Universal](docs/MCP_UNIVERSAL.md)** — Integration with all AI models
- **[Advanced Features](docs/ADVANCED_FEATURES.md)** — Caching, process management, intelligence
- **[Production Ready](docs/PRODUCTION_READINESS.md)** — Deployment guide

---

## 📦 Requirements

- Python 3.8+
- requests >= 2.28.0
- urllib3 >= 1.26.0

Optional security tools: nmap, nuclei, ffuf, gobuster, sqlmap, nikto

---

<div align="center">

**NexHunter v3.1.0** — Security Assessment Platform

[GitHub](https://github.com/Arseno25/nexhunter) • [Docs](docs/README.md)

</div>
