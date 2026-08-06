"""Shared multi-flag command builders used by more than one ToolSpec."""


def _build_nmap_advanced(p: dict) -> list:
    """Build an nmap argv from advanced scan knobs."""
    argv = ["nmap"]
    if p.get("aggressive"):
        argv += ["-A"]
    else:
        if p.get("os_detection"):
            argv += ["-O"]
        if p.get("version_detection", True):
            argv += ["-sV"]
    if p.get("stealth"):
        argv += ["-sS", "-T1", "-n", "-Pn"]
    else:
        argv += [f"-T{p.get('timing', '4')}"]
    if p.get("nse_scripts"):
        argv += ["--script", p["nse_scripts"]]
    if p.get("ports"):
        argv += ["-p", p["ports"]]
    argv += ["-oX", "-"]
    argv += [p["target"]]
    return argv


def _build_masscan_advanced(p: dict) -> list:
    """Build a masscan argv with rate and thread control."""
    argv = ["masscan", p["target"], "-p", p["ports"], "-oG", "-", "--rate", str(p["rate"])]
    if p.get("threads"):
        argv += ["--threads", str(p["threads"])]
    return argv


def _build_ffuf_advanced(p: dict) -> list:
    """Build an ffuf argv with one wordlist per comma-separated entry.

    The target URL keeps its FUZZ-style markers; each wordlist is paired with
    the keyword at the same position, or plain FUZZ when no markers exist.
    """
    argv = ["ffuf", "-u", p["target"], "-t", str(p["threads"]), "-s"]
    wordlists = [w.strip() for w in str(p["wordlists"]).split(",") if w.strip()]
    for wordlist in wordlists:
        argv += ["-w", wordlist]
    if p.get("method"):
        argv += ["-X", str(p["method"])]
    if p.get("filter_status"):
        argv += ["-fs", str(p["filter_status"])]
    if p.get("matcher_status"):
        argv += ["-mc", str(p["matcher_status"])]
    return argv
