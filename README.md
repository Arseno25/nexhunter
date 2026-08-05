# NexHunter

<div align="center">
  <img src="assets/nexhunter.png" alt="NexHunter" width="300">
</div>

<div align="center">
    <strong>
        Advanced AI-Driven Security Assessment Platform
    </strong>

![Version](https://img.shields.io/badge/version-1.0.0-blue) ![Python](https://img.shields.io/badge/python-3.8+-green) ![Tools](https://img.shields.io/badge/tools-164-blue) ![Tests](https://img.shields.io/badge/tests-77%20passing-green)
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
- **77 tests passing** across auth, authorization, engagement scope, policy, redaction, audit, enforcement, and MCP registration

---

## 🔗 MCP Setup

Add to your AI provider's config file (e.g., `~/.claude/config.json`):

```json
{
  "mcpServers": {
    "nexhunter": {
      "command": "python3",
      "args": [
        "-m",
        "nexhunter.api.mcp",
        "--server",
        "http://127.0.0.1:8888"
      ],
      "timeout": 300,
      "alwaysAllow": []
    }
  }
}
```

Replace `python3` with full path to Python interpreter and `127.0.0.1:8888` with your server address.

**Examples:**
- Linux/macOS: `python3` or `/usr/bin/python3`
- Windows: `C:\Python\python.exe` or `.venv\Scripts\python.exe`

**Usage:**
```
"Scan example.com with nexhunter"
→ AI model automatically discovers and uses 164 tools
```

---

## 📖 About NexHunter

**NexHunter** is an AI-driven security assessment platform that orchestrates 164 specialized security tools through an intelligent agent system. It automates complex security workflows by:

- **Intelligent Tool Selection**: AI agents analyze targets and automatically select optimal tools
- **Workflow Automation**: Executes comprehensive assessment workflows (bug bounty, pentest, API security, cloud security, red team, audit, mobile, supply chain, DevSecOps)
- **Result Correlation**: Correlates findings across multiple tools to identify attack paths and vulnerabilities
- **Smart Caching**: LRU cache with MD5-based deduplication reduces redundant scans
- **Real-time Monitoring**: Process management tracks execution with streaming output
- **Universal AI Integration**: Works with Claude, Grok, Gemini, GPT-4, Llama, Mistral via MCP protocol

**Use Cases:**
- Automated security assessments for targets
- Continuous vulnerability scanning
- Red team operations
- Security compliance audits
- Bug bounty automation
- API security testing
- Cloud infrastructure assessment

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
| Tests Passing | 77 |

---

<div align="center">

**NexHunter v1.0.0** — AI-Integrated Security Assessment

[GitHub](https://github.com/Arseno25/nexhunter)

</div>
