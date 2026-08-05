"""nexhunter.config - centralized configuration."""

# Cache settings
CACHE_MAX = 128
CACHE_CLEANUP_THRESHOLD = 0.8

# Tool execution
DEFAULT_TOOL_TIMEOUT = 300
TOOL_TIMEOUTS = {
    "nmap_scan": 600,
    "nuclei_scan": 600,
    "ffuf_scan": 600,
    "gobuster_dir": 600,
    "sqlmap_scan": 900,
    "nikto_scan": 600,
    "httpx_probe": 120,
    "subfinder_enum": 300,
    "amass_enum": 600,
    "wpscan_scan": 900,
    "dns_lookup": 60,
    "whois_lookup": 60,
    "curl_headers": 60,
    "dalfox_xss": 600,
    "hashid": 60,
    "john": 900,
    "hashcat": 900,
    "strings": 120,
    "exiftool": 120,
    "binwalk": 300,
    "foremost": 300,
    "checksec": 60,
    "objdump": 300,
    "gdb": 120,
}

# Rate limiting
RATE_LIMIT_ENABLED = True
RATE_LIMIT_PER_HOST = 5  # max requests per minute per host

# Finding deduplication
FINDING_DEDUP_ENABLED = True

# Agent settings
MAX_PARALLEL_WORKERS = 4
MAX_PROCESS_OUTPUT_LINES = 200
MAX_TOOL_OUTPUT_PREVIEW = 2000

# Server settings
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888
REQUEST_TIMEOUT = 600

# Flow settings
WORKFLOW_TIMEOUT = 3600  # 1 hour per workflow
