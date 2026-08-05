"""LRU + TTL cache for tool execution results.

The single execution path runs the same tool with the same parameters more
often than it looks: an autonomous loop re-probes a host, an operator re-runs a
scan, two profiles converge on the same recon step. Caching the terminal result
of a deterministic run turns those repeats into a lookup instead of another
process against the target.

What is cached is deliberately narrow:

  * Only terminal, deterministic outcomes -- a completed or failed run. A
    timeout or a termination says nothing durable about the target, so it is
    never stored.
  * The key is a hash of the tool name and its *normalized* parameters (the
    post-validation values), so parameter order and defaulting do not split the
    cache, and no raw parameter value -- secret or otherwise -- is retained in
    the key.

The cache never reaches the operating system and never changes what may run: it
only short-circuits a repeat of a call that already went through the full
validate -> build -> run path once.
"""

import hashlib
import json
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from nexhunter.core.config import (
    RESULT_CACHE_ENABLED,
    RESULT_CACHE_MAX,
    RESULT_CACHE_TTL,
)

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


@dataclass
class CachedResult:
    """One stored result, with the id of the execution that produced it."""

    result: dict[str, Any]
    stored_at: float
    execution_id: str


class ResultCache:
    """Thread-safe LRU cache with per-entry TTL, keyed by tool + params."""

    def __init__(
        self,
        max_entries: int = RESULT_CACHE_MAX,
        ttl_seconds: float = RESULT_CACHE_TTL,
        enabled: bool = RESULT_CACHE_ENABLED,
    ):
        self.max_entries = max(1, int(max_entries))
        self.ttl_seconds = max(0.0, float(ttl_seconds))
        self.enabled = bool(enabled)
        self._entries: OrderedDict[str, CachedResult] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.expirations = 0

    @classmethod
    def from_env(cls) -> "ResultCache":
        """Build a cache, letting NEXHUNTER_CACHE_* override config defaults."""
        # NEXHUNTER_CACHE_MAX is accepted as an alias for _MAX_ENTRIES.
        max_entries = _env_int(
            "NEXHUNTER_CACHE_MAX_ENTRIES",
            _env_int("NEXHUNTER_CACHE_MAX", RESULT_CACHE_MAX),
        )
        return cls(
            max_entries=max_entries,
            ttl_seconds=_env_float("NEXHUNTER_CACHE_TTL", float(RESULT_CACHE_TTL)),
            enabled=_env_flag("NEXHUNTER_CACHE_ENABLED", RESULT_CACHE_ENABLED),
        )

    @staticmethod
    def key_for(tool_name: str, normalized_params: dict[str, Any]) -> str:
        """A stable hash of the tool and its normalized parameters.

        Values are hashed, never stored, so a secret parameter cannot be read
        back out of the cache key.
        """
        blob = json.dumps(
            {"tool": tool_name, "params": normalized_params},
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def get(self, key: str) -> CachedResult | None:
        """Return a live entry and count the hit, or None (counting the miss)."""
        if not self.enabled:
            return None
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self.misses += 1
                return None
            if self._expired(entry):
                self._entries.pop(key, None)
                self.expirations += 1
                self.misses += 1
                return None
            self._entries.move_to_end(key)
            self.hits += 1
            return entry

    def put(self, key: str, result: dict[str, Any], execution_id: str) -> None:
        """Store a terminal result, evicting the least-recently-used if full."""
        if not self.enabled:
            return
        with self._lock:
            self._entries[key] = CachedResult(
                result=result, stored_at=time.monotonic(), execution_id=execution_id
            )
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
                self.evictions += 1

    def clear(self) -> int:
        """Drop every entry. Returns how many were removed."""
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            return count

    def _expired(self, entry: CachedResult) -> bool:
        return self.ttl_seconds > 0 and (time.monotonic() - entry.stored_at) > self.ttl_seconds

    def stats(self) -> dict[str, Any]:
        """Cache telemetry for /api/cache/stats."""
        with self._lock:
            total = self.hits + self.misses
            return {
                "enabled": self.enabled,
                "entries": len(self._entries),
                "max_entries": self.max_entries,
                "ttl_seconds": self.ttl_seconds,
                "hits": self.hits,
                "misses": self.misses,
                "evictions": self.evictions,
                "expirations": self.expirations,
                "hit_rate": round(self.hits / total, 3) if total else 0.0,
            }


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in _TRUE:
        return True
    if raw in _FALSE:
        return False
    return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    try:
        return float(raw) if raw else default
    except ValueError:
        return default
