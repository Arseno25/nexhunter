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
python -m nexhunter.api.mcp --server http://127.0.0.1:8888
```

---

## 🎯 Features

- **18 AI Agents** (13 core + 5 enhanced)
- **164 Security Tools** (reconnaissance, web, network, cloud, forensics, exploitation)
- **9 Assessment Workflows** (bug bounty, pentest, API, cloud, mobile, DevSecOps)
- **184 MCP Tools** for AI integration
- **Universal MCP Support** (Claude, Grok, Gemini, GPT-4, Llama, Mistral, custom)
- **100% Test Coverage** (12/12 tests passing)

---

## 🔗 MCP Integration

### Setup

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
Edit `~/.claude/config.json` and restart Claude.

**Other AI Models** (Grok, Gemini, GPT-4, Llama, Mistral)

See [MCP Universal Guide](docs/MCP_UNIVERSAL.md) for setup instructions.

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

### Usage

**In Claude:**
```
"Scan example.com with nexhunter"
→ Claude uses available tools automatically
```

**In Other AI Models:**
Same pattern - AI automatically discovers and uses tools via MCP.

---

## 🛠️ Available Tools (164)

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
- **Other** (80+): mobile, IDS/IPS, secrets, social engineering

---

## 🔄 Workflows (9)

| Workflow | Phases | Target |
|----------|--------|--------|
| Bug Bounty | 10 | Web applications |
| Penetration Testing | 8 | Corporate networks |
| API Security | 10 | REST/GraphQL APIs |
| Cloud Security | 8 | AWS/Azure/GCP |
| Red Team | 6 | Adversarial simulation |
| Security Audit | 7 | Compliance |
| Mobile Security | 8 | iOS/Android |
| Supply Chain | 7 | Dependencies |
| DevSecOps | 8 | CI/CD pipelines |

---

## 🔐 Security

✓ Authorization-first design  
✓ XXE protection  
✓ Safe command execution  
✓ Input validation  
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
| MCP Tools | 184 |
| CLI Commands | 15+ |
| Test Coverage | 100% |

---

## 📚 Documentation

- **[Complete Guide](docs/README.md)** — Full reference
- **[MCP Universal](docs/MCP_UNIVERSAL.md)** — Integration with all AI models
- **[Tools Reference](docs/TOOLS.md)** — All 164 tools
- **[Advanced Features](docs/ADVANCED_FEATURES.md)** — Caching, intelligence
- **[Production Ready](docs/PRODUCTION_READINESS.md)** — Deployment

---

## 📦 Requirements

Python 3.8+, requests >= 2.28.0, urllib3 >= 1.26.0

---

<div align="center">

**NexHunter v3.1.0** — AI-Integrated Security Assessment

[GitHub](https://github.com/Arseno25/nexhunter)

</div>
