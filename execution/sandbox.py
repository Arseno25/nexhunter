"""File management and isolated Python execution for the lab.

Two narrow, useful primitives the lab frequently wants:

  * file ops  - read/list anything the server can see; write only inside an
    explicit allow root (writes elsewhere are refused, no silent fallback).
  * python_run- execute a short snippet with the project's python inside a
    scratch cwd. Output capped, timeout enforced. A test harness, not a shell.

These are helpers the HTTP/MCP layer can call; they are intentionally not
registered as tools, so the single execution path stays the only path that
runs anything from the tool registry.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path

MAX_READ_BYTES = 200_000
MAX_LIST_ENTRIES = 500
PYTHON_MAX_OUTPUT = 128_000
PYTHON_TIMEOUT = 120

# Writes are confined to this directory (created on demand). Read-only ops are
# free to touch anywhere readable.
DEFAULT_ALLOW_ROOT = Path.home() / ".nexhunter" / "lab"


def _allow_root() -> Path:
    root = Path(DEFAULT_ALLOW_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _resolve(root: Path, rel: str) -> Path | None:
    """Join `rel` into root and guarantee it stays inside root."""
    rel = (rel or "").lstrip("/\\")
    if not rel:
        return root
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def list_dir(path: str = "", limit: int = MAX_LIST_ENTRIES) -> dict:
    """List a readable directory. Empty path falls back to the allow root."""
    root = _resolve(_allow_root(), path) if path else _allow_root()
    if root is None:
        return {"ok": False, "error": "path must be a plain relative path"}
    if not root.is_dir():
        return {"ok": False, "error": f"not a directory: {path or root}"}
    entries = []
    try:
        for child in sorted(root.iterdir())[: max(1, int(limit))]:
            entries.append({
                "name": child.name,
                "is_dir": child.is_dir(),
                "size": child.stat().st_size if child.is_file() else None,
            })
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "path": str(root), "entries": entries,
            "count": len(entries)}


def read_file(path: str, max_bytes: int = MAX_READ_BYTES) -> dict:
    p = Path(path)
    if not p.is_file():
        return {"ok": False, "error": f"not a file: {path}"}
    try:
        size = p.stat().st_size
        data = p.read_bytes()[: max(1, int(max_bytes))]
        return {
            "ok": True, "path": str(p), "bytes": size,
            "content": data.decode("utf-8", errors="replace"),
            "truncated": size > int(max_bytes),
        }
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


def write_file(path: str, content: str) -> dict:
    """Write a file, but only under the allow root."""
    target = _resolve(_allow_root(), path)
    if target is None:
        return {"ok": False, "error": "path must stay inside the allow root",
                "allow_root": str(_allow_root())}
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((content or "").encode("utf-8"))
        return {"ok": True, "path": str(target),
                "bytes": len((content or "").encode("utf-8"))}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}


def python_run(code: str, timeout: int = PYTHON_TIMEOUT,
               max_output: int = PYTHON_MAX_OUTPUT) -> dict:
    """Run a short Python snippet in a scratch dir with output caps."""
    if not code or not code.strip():
        return {"ok": False, "error": "code is required"}
    timeout = max(30, min(600, int(timeout or 30)))
    max_output = max(1_000, int(max_output))
    t0 = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="nexhunter-py-") as scratch:
            proc = subprocess.run(
                [sys.executable, "-c", code],
                capture_output=True, text=True, cwd=scratch,
                timeout=timeout,
            )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timed out after {timeout}s",
                "code": "TIMEOUT"}
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    return {
        "ok": proc.returncode == 0,
        "exit": proc.returncode,
        "stdout": proc.stdout[:max_output],
        "stderr": proc.stderr[:max_output],
        "duration_s": round(time.monotonic() - t0, 3),
        "truncated": len(proc.stdout) > max_output,
    }
