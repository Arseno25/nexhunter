# NexHunter

<div align="center">
  <img src="assets/nexhunter.png" alt="NexHunter" width="300">
</div>

<div align="center">
> Advanced AI-Driven Security Assessment Platform

![Version](https://img.shields.io/badge/version-3.1.0-blue) ![Python](https://img.shields.io/badge/python-3.8+-green) ![Tools](https://img.shields.io/badge/tools-164-blue) ![Tests](https://img.shields.io/badge/tests-100%25-green)
</div>

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

## 🔗 MCP Setup

Add to your AI provider's config file (e.g., `~/.claude/config.json`):

```json
{
  "mcp": {
    "nexhunter": {
      "type": "local",
      "command": [
        "/path/to/python",
        "-m",
        "nexhunter.api.mcp",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "environment": {
        "PYTHONPATH": "/path/to/nexhunter"
      },
      "enabled": true
    }
  }
}
```

**Configure for your system:**

| Parameter | Example | Notes |
|-----------|---------|-------|
| `/path/to/python` | `/usr/bin/python3` or `C:\Python\python.exe` or `.venv/Scripts/python.exe` | Path to Python interpreter |
| `/path/to/nexhunter` | `/home/user/nexhunter` or `C:\Users\user\nexhunter` | Path to NexHunter repo |
| `http://127.0.0.1:8888` | Change port if needed | NexHunter server address |

**Linux/macOS Example:**
```json
{
  "mcp": {
    "nexhunter": {
      "type": "local",
      "command": [
        "/usr/bin/python3",
        "-m",
        "nexhunter.api.mcp",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "environment": {
        "PYTHONPATH": "/home/user/nexhunter"
      },
      "enabled": true
    }
  }
}
```

**Windows Example:**
```json
{
  "mcp": {
    "nexhunter": {
      "type": "local",
      "command": [
        "C:\\Users\\user\\nexhunter\\.venv\\Scripts\\python.exe",
        "-m",
        "nexhunter.api.mcp",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "environment": {
        "PYTHONPATH": "C:\\Users\\user\\nexhunter"
      },
      "enabled": true
    }
  }
}
```

**Usage:**
```
"Scan example.com with nexhunter"
→ AI model automatically discovers and uses tools
```

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
| Test Coverage | 100% |

---

<div align="center">

**NexHunter v3.1.0** — AI-Integrated Security Assessment

[GitHub](https://github.com/Arseno25/nexhunter)

</div>
