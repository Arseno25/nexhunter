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

**Any Other Model** - See `docs/MCP_UNIVERSAL.md` for Grok, Gemini, GPT-4, Llama, Mistral, and generic clients.

---

## 🛠️ Security Tools (164)

**Reconnaissance** (11): nmap, masscan, rustscan, subfinder, amass, shodan, dns, whois, host, assetfinder, censys

**Web Scanning** (13): nuclei, ffuf, gobuster, nikto, sqlmap, dalfox, xsstrike, commix, burpsuite, zap, w3af, wpscan, joomscan

**Network** (15): aircrack, aireplay, airodump, tcpdump, tshark, arp-scan, nping, netstat, ss, enum4linux, smbmap, cme, rpcclient, smbclient, ldapsearch

**Cryptography** (5): hashid, john, hashcat, openssl, testssl

**Forensics** (8): strings, exiftool, binwalk, foremost, volatility, sleuthkit, autopsy, regripper

**Binary Analysis** (10): ghidra, ida, radare2, cutter, angr, objdump, readelf, nm, ldd, strace

**Cloud/DevOps** (11): kube-bench, kube-hunter, trivy, grype, docker, kubectl, aws-cli, gcloud, az, tfsec, checkov

**Code Analysis** (5): semgrep, bandit, pylint, sonarqube, checkmarx

**Exploitation** (6): metasploit, empire, cobalt-strike, havoc, sliver, msfvenom

**Other** (80+): mobile security, IDS/IPS, secrets detection, password testing, evasion, social engineering

---

## 🔄 Workflows (9)

| Workflow | Phases | Focus |
|----------|--------|-------|
| **Bug Bounty** | 10 | Web applications |
| **Penetration Testing** | 8 | Corporate networks |
| **API Security** | 10 | REST/GraphQL APIs |
| **Cloud Security** | 8 | AWS/Azure/GCP |
| **Red Team** | 6 | Adversarial simulation |
| **Security Audit** | 7 | Compliance |
| **Mobile Security** | 8 | iOS/Android |
| **Supply Chain** | 7 | Dependencies |
| **DevSecOps** | 8 | CI/CD pipelines |

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
| Assessment Phases | 73 |
| MCP Tools | 184 |
| API Endpoints | 30+ |
| CLI Commands | 15+ |
| Test Coverage | 100% |

---

## 📦 Requirements

Python 3.8+, requests >= 2.28.0, urllib3 >= 1.26.0

---

<div align="center">

**NexHunter v3.1.0** — Security Assessment Platform

GitHub: https://github.com/Arseno25/nexhunter

</div>
