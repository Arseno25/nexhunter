"""nexhunter.config - centralized configuration."""

import os

# Cache settings (legacy Engine LRU, used by /api/probe, /api/portscan, ...)
CACHE_MAX = 128
CACHE_CLEANUP_THRESHOLD = 0.8

# Result cache for the single execution path (ExecutionService). Only
# deterministic terminal results (completed/failed) are stored; a timeout or a
# termination says nothing durable about the target and is never cached.
# Overridable per-process via NEXHUNTER_CACHE_ENABLED / _TTL / _MAX.
RESULT_CACHE_ENABLED = True
RESULT_CACHE_TTL = 300  # seconds; 0 disables expiry
RESULT_CACHE_MAX = 256  # entries

# Tool execution
DEFAULT_TOOL_TIMEOUT = 300
TOOL_TIMEOUTS = {
    "nmap_scan": 600,
    "nuclei_scan": 600,
    "ffuf_scan": 600,
    "gobuster_dir": 600,
    "dirsearch": 600,   # default 300s always timed out; 600s gives a single wordlist pass
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
    "feroxbuster": 900,
    "wfuzz": 900,
    "tplmap": 900,
    "nosqlmap": 900,
    "subjack": 900,
    "impacket_psexec": 900,
    "evil_winrm": 900,
    "prowler": 1800,
    "scoutsuite": 1800,
    "kiterunner": 900,
    "bulk_extractor": 900,
    "theharvester": 600,
    "sslyze": 600,
    "sslscan": 300,
    "naabu": 600,
    "browser_crawl": 300,
    "bandit": 600,
    "tcpdump_capture": 300,
    "tshark_capture": 300,
}

# Rate limiting
RATE_LIMIT_ENABLED = True
RATE_LIMIT_PER_HOST = 5  # max requests per minute per host

# Finding deduplication
FINDING_DEDUP_ENABLED = True

# Agent settings
# Parallel tool fan-out. The batch worker count adapts to host load between
# MIN_PARALLEL_WORKERS and PARALLEL_WORKERS_CEILING (see core/scaling.py) --
# the same auto-scaling idea as HexStrike's process pool, bounded to this
# machine. MAX_PARALLEL_WORKERS is the baseline used when load is unknown
# (psutil not installed), so behaviour is unchanged without the optional dep.
MIN_PARALLEL_WORKERS = int(os.environ.get("NEXHUNTER_MIN_WORKERS", "2"))
MAX_PARALLEL_WORKERS = int(os.environ.get("NEXHUNTER_MAX_WORKERS", "4"))
PARALLEL_WORKERS_CEILING = int(
    os.environ.get("NEXHUNTER_WORKERS_CEILING", str(min(32, max(4, (os.cpu_count() or 4) * 2))))
)
# Load thresholds (percent): at/above HI shrink toward MIN, below LO grow
# toward the ceiling, in between hold the baseline.
WORKER_CPU_HI = float(os.environ.get("NEXHUNTER_WORKER_CPU_HI", "85"))
WORKER_CPU_LO = float(os.environ.get("NEXHUNTER_WORKER_CPU_LO", "50"))
WORKER_MEM_HI = float(os.environ.get("NEXHUNTER_WORKER_MEM_HI", "90"))
MAX_PROCESS_OUTPUT_LINES = 200
MAX_TOOL_OUTPUT_PREVIEW = 2000

# Server bind host/port live in the top-level, validated config.py
# (bind_host/bind_port). Duplicating them here caused two sources of truth, so
# they were removed. REQUEST_TIMEOUT was dead and is gone too.

# Flow settings
WORKFLOW_TIMEOUT = 3600  # 1 hour per workflow
