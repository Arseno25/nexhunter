# MCP Universal Integration Guide

Use NexHunter with **any AI model** via MCP (Model Context Protocol).

---

## Supported AI Models

| Model | Integration | Status |
|-------|-------------|--------|
| **Claude** | Official | ✓ Production |
| **Grok** | MCP Bridge | ✓ Compatible |
| **Gemini** | MCP Bridge | ✓ Compatible |
| **GPT-4** | MCP Bridge | ✓ Compatible |
| **Llama** | MCP Bridge | ✓ Compatible |
| **Mistral** | MCP Bridge | ✓ Compatible |
| **Any MCP Client** | Generic | ✓ Compatible |

---

## Architecture

```
NexHunter Server (8888)
    ↑
    ├── MCP Bridge (stdio/HTTP)
    ↑
    ├── Claude Desktop
    ├── Grok API Client
    ├── Gemini API Client
    ├── Generic MCP Client
    └── Custom Integration
```

---

## Setup for Each Model

### 1. Claude Desktop (Native)

**File:** `~/.claude/config.json`

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

**Restart:** Claude Desktop

**Usage:** 
```
"Scan example.com with nexhunter"
→ Claude automatically uses MCP tools
```

---

### 2. Grok (X AI)

**Prerequisites:**
- Grok API key
- MCP bridge running

**Step 1:** Start NexHunter server
```bash
python -m nexhunter.api.server --port 8888
```

**Step 2:** Start MCP bridge
```bash
python -m nexhunter.api.mcp --server http://127.0.0.1:8888
```

**Step 3:** Python integration
```python
import requests
import json

GROK_API = "https://api.x.ai/v1"
GROK_KEY = "your-grok-key"
MCP_BRIDGE = "http://127.0.0.1:9000"  # MCP bridge endpoint

# Get available tools from NexHunter
tools_response = requests.post(f"{MCP_BRIDGE}/tools")
tools = tools_response.json()

# Use with Grok
response = requests.post(
    f"{GROK_API}/messages",
    headers={"Authorization": f"Bearer {GROK_KEY}"},
    json={
        "model": "grok-2",
        "messages": [{"role": "user", "content": "Scan example.com"}],
        "tools": tools  # NexHunter tools
    }
)

print(response.json())
```

---

### 3. Gemini (Google)

**Prerequisites:**
- Gemini API key
- MCP bridge running

**Python Integration:**
```python
import google.generativeai as genai
import requests

# Configure Gemini
genai.configure(api_key="your-gemini-key")

# Get NexHunter tools
mcp_response = requests.post("http://127.0.0.1:9000/tools")
nexhunter_tools = mcp_response.json()

# Convert to Gemini format
gemini_tools = [{
    "name": tool["name"],
    "description": tool["description"],
    "function_declarations": [{
        "name": tool["name"],
        "parameters": {
            "type": "OBJECT",
            "properties": {
                k: {"type": "STRING"} for k in tool.get("params", {})
            }
        }
    }]
} for tool in nexhunter_tools]

# Use with Gemini
model = genai.GenerativeModel("gemini-2.0-flash", tools=gemini_tools)
response = model.generate_content("Scan example.com with nexhunter")
print(response.text)
```

---

### 4. GPT-4 (OpenAI)

**Prerequisites:**
- OpenAI API key
- MCP bridge running

**Python Integration:**
```python
import openai
import requests

openai.api_key = "your-openai-key"

# Get NexHunter tools
mcp_response = requests.post("http://127.0.0.1:9000/tools")
nexhunter_tools = mcp_response.json()

# Convert to OpenAI format
openai_tools = [{
    "type": "function",
    "function": {
        "name": tool["name"],
        "description": tool["description"],
        "parameters": {
            "type": "object",
            "properties": {
                k: {"type": "string"} for k in tool.get("params", {})
            }
        }
    }
} for tool in nexhunter_tools]

# Use with GPT-4
response = openai.ChatCompletion.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Scan example.com"}],
    tools=openai_tools,
    tool_choice="auto"
)

print(response.choices[0].message)
```

---

### 5. Llama (Meta)

**Prerequisites:**
- Llama model running locally or via API
- MCP bridge running

**Using Ollama:**
```bash
# Install Ollama & run Llama
ollama run llama2

# In Python:
import requests
import subprocess
import json

# Start NexHunter
subprocess.Popen(["python", "-m", "nexhunter.api.server", "--port", "8888"])

# Get tools
tools_response = requests.post("http://127.0.0.1:9000/tools")
tools = tools_response.json()

# Query Llama with tools
response = requests.post(
    "http://localhost:11434/api/chat",
    json={
        "model": "llama2",
        "messages": [{
            "role": "user",
            "content": "Scan example.com. Available tools: " + str(tools)
        }]
    }
)

print(response.json())
```

---

### 6. Mistral (Mistral AI)

**Prerequisites:**
- Mistral API key
- MCP bridge running

**Python Integration:**
```python
from mistralai.client import MistralClient
from mistralai.models.chat_message import ChatMessage
import requests

# Configure Mistral
client = MistralClient(api_key="your-mistral-key")

# Get NexHunter tools
mcp_response = requests.post("http://127.0.0.1:9000/tools")
nexhunter_tools = mcp_response.json()

# Convert to Mistral format
mistral_tools = [{
    "type": "function",
    "function": {
        "name": tool["name"],
        "description": tool["description"],
        "parameters": {
            "type": "object",
            "properties": {
                k: {"type": "string"} for k in tool.get("params", {})
            }
        }
    }
} for tool in nexhunter_tools]

# Use with Mistral
response = client.chat(
    model="mistral-large-latest",
    messages=[ChatMessage(role="user", content="Scan example.com")],
    tools=mistral_tools
)

print(response.choices[0].message.content)
```

---

## Generic MCP Client

### Using stdio (Recommended)

```python
import subprocess
import json
import sys

class NexHunterMCP:
    def __init__(self, server_url="http://127.0.0.1:8888"):
        self.server_url = server_url
        self.process = subprocess.Popen(
            ["python", "-m", "nexhunter.api.mcp", "--server", server_url],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
    
    def call_tool(self, tool_name, **kwargs):
        """Call a NexHunter tool via MCP"""
        request = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": kwargs
            },
            "id": 1
        }
        
        # Send request
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        
        # Read response
        response_line = self.process.stdout.readline()
        return json.loads(response_line)
    
    def list_tools(self):
        """Get all available tools"""
        request = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        }
        
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        
        response_line = self.process.stdout.readline()
        return json.loads(response_line)
    
    def close(self):
        """Close MCP connection"""
        self.process.terminate()
        self.process.wait()

# Usage
mcp = NexHunterMCP()

# List tools
tools = mcp.list_tools()
print(f"Available tools: {len(tools)}")

# Call assess tool
result = mcp.call_tool("assess", target="https://example.com")
print(result)

mcp.close()
```

### Using HTTP (Alternative)

```python
import requests
import json

class NexHunterHTTP:
    def __init__(self, server_url="http://127.0.0.1:8888"):
        self.server_url = server_url
    
    def assess(self, target):
        """Run full assessment"""
        return requests.post(
            f"{self.server_url}/api/assess",
            json={"target": target}
        ).json()
    
    def probe(self, target):
        """Quick HTTP probe"""
        return requests.post(
            f"{self.server_url}/api/probe",
            json={"target": target}
        ).json()
    
    def osint(self, target):
        """OSINT intelligence"""
        return requests.post(
            f"{self.server_url}/api/intelligence/osint",
            json={"target": target}
        ).json()
    
    def run_tool(self, tool_name, **params):
        """Run specific tool"""
        return requests.post(
            f"{self.server_url}/api/command",
            json={"tool": tool_name, "params": params}
        ).json()

# Usage
nxh = NexHunterHTTP()
result = nxh.assess("https://example.com")
print(json.dumps(result, indent=2))
```

---

## Universal Integration Pattern

**For any AI model:**

```
1. Start NexHunter Server
   └─ python -m nexhunter.api.server --port 8888

2. Start MCP Bridge
   └─ python -m nexhunter.api.mcp --server http://127.0.0.1:8888

3. AI Model Connects
   └─ Claude: config.json
   └─ Grok: API call with tools
   └─ Gemini: genai.GenerativeModel(tools=...)
   └─ GPT-4: openai.ChatCompletion(...tools=...)
   └─ Custom: stdio/HTTP protocol

4. Use in AI
   └─ "Scan example.com with nexhunter"
   └─ AI model automatically calls tools
```

---

## Tool Availability

**184 Tools Available via MCP:**

**Static Functions (20):**
- assess(), probe(), osint(), analyze_target()
- select_tools(), optimize_parameters()
- run_flow(), run_agent()
- findings(), report()
- telemetry(), cache_stats()
- processes(), process_status()
- And more...

**Dynamic Tools (164):**
- All 164 security tools from core/tools.py
- Automatically registered
- Full parameter support

---

## Configuration

### MCP Bridge Settings

```bash
# Custom server address
python -m nexhunter.api.mcp --server http://192.168.1.100:8888

# Custom MCP port
python -m nexhunter.api.mcp --server http://127.0.0.1:8888 --port 9000

# Debug mode
python -m nexhunter.api.mcp --server http://127.0.0.1:8888 --debug
```

### Tool Configuration

Edit `core/config.py`:
```python
CACHE_MAX = 128
MAX_PARALLEL_WORKERS = 4
RATE_LIMIT_ENABLED = True
TOOL_TIMEOUTS = {...}
```

---

## Troubleshooting

### MCP Bridge Not Responding
```bash
# Check if server running
curl http://127.0.0.1:8888/api/health

# Check if MCP bridge running
ps aux | grep nexhunter.api.mcp

# Restart
pkill -f nexhunter.api.mcp
python -m nexhunter.api.mcp --server http://127.0.0.1:8888
```

### Tool Execution Error
```bash
# Check tool availability
curl http://127.0.0.1:8888/api/health

# List processes
curl http://127.0.0.1:8888/api/processes/list

# Check telemetry
curl http://127.0.0.1:8888/api/telemetry
```

### Timeout Issues
```python
# Increase timeout in config
TOOL_TIMEOUTS = {
    "nuclei_scan": 900,  # 15 minutes
    "nmap_scan": 600     # 10 minutes
}
```

---

## Performance Tips

1. **Enable Caching** - Reuse results for same targets
2. **Parallel Execution** - Multiple tools simultaneously
3. **Async Operations** - Fire-and-forget long-running tasks
4. **Monitor Telemetry** - Track cache hits, response times
5. **Rate Limiting** - Respect target rate limits

---

## Security Best Practices

✓ Only scan authorized targets  
✓ Use local MCP bridge (127.0.0.1)  
✓ Enable authentication for network access  
✓ Review tool output before sharing  
✓ Respect privacy and compliance  

---

## API Protocol

### MCP JSON-RPC Format

**Tool List Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "id": 1
}
```

**Tool Call Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "assess",
    "arguments": {
      "target": "https://example.com"
    }
  },
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "ok": true,
    "data": {...},
    "meta": {...}
  },
  "id": 1
}
```

---

## Summary

NexHunter MCP works with **any AI model**:
- ✓ Claude Desktop (native)
- ✓ Grok, Gemini, GPT-4, Llama, Mistral (via bridge)
- ✓ Any MCP client (stdio/HTTP)
- ✓ 184 tools available
- ✓ Full security assessment capabilities

**Start Using:**
```bash
# Terminal 1
python -m nexhunter.api.server --port 8888

# Terminal 2
python -m nexhunter.api.mcp --server http://127.0.0.1:8888

# Then: Integrate with your AI model
```

---

**Version**: 3.1.0  
**Status**: Production Ready  
**Compatibility**: Universal MCP Standard
