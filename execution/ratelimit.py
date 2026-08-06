"""Per-host request rate limiting.

Parallel tool fan-out (see workflows/orchestrator batch execution) can point
several scanners at the same host at once. A sliding-window limiter paces those
so NexHunter does not self-DoS a target. Bare hosts, ``host:port`` and full
URLs all collapse to the same hostname key, so ``example.com`` and
``https://example.com/x`` share one budget.

Slow tools rarely reach the per-minute cap on their own; the limiter mainly
smooths bursts of quick tools. Callers block in ``acquire`` until a slot frees.
"""

import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

from nexhunter.core.config import RATE_LIMIT_ENABLED, RATE_LIMIT_PER_HOST


def host_of(target: str) -> str:
    """Hostname key for a bare host, ``host:port``, or full URL. '' if none."""
    if not target:
        return ""
    t = target.strip()
    if "://" not in t:
        t = "//" + t  # let urlparse treat a bare host as a netloc
    return (urlparse(t).hostname or "").lower()


class HostRateLimiter:
    """Sliding-window limiter: at most ``per_minute`` acquires per host/minute."""

    def __init__(self, per_minute: int = RATE_LIMIT_PER_HOST, enabled: bool = RATE_LIMIT_ENABLED):
        self.per_minute = int(per_minute)
        self.enabled = bool(enabled)
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls) -> "HostRateLimiter":
        return cls()

    def acquire(self, target: str) -> None:
        """Block until a request slot is free for ``target``'s host."""
        if not self.enabled or self.per_minute <= 0:
            return
        host = host_of(target)
        if not host:
            return
        while True:
            with self._lock:
                dq = self._hits[host]
                now = time.monotonic()
                while dq and now - dq[0] >= 60.0:
                    dq.popleft()
                if len(dq) < self.per_minute:
                    dq.append(now)
                    return
                wait = 60.0 - (now - dq[0])
            time.sleep(min(max(wait, 0.01), 60.0))  # released lock before sleeping


def _selfcheck() -> None:
    assert host_of("wibidigital.com") == "wibidigital.com"
    assert host_of("https://wibidigital.com/home") == "wibidigital.com"
    assert host_of("http://wibidigital.com:8080") == "wibidigital.com"
    assert host_of("") == ""

    rl = HostRateLimiter(per_minute=3, enabled=True)
    t0 = time.monotonic()
    for _ in range(3):
        rl.acquire("example.com")  # 3 slots, no wait
    assert time.monotonic() - t0 < 0.5, "first 3 should not block"

    # A disabled limiter never blocks.
    off = HostRateLimiter(per_minute=1, enabled=False)
    off.acquire("example.com")
    off.acquire("example.com")

    # Different hosts have independent budgets.
    rl.acquire("other.com")
    print("ratelimit OK")


if __name__ == "__main__":
    _selfcheck()
