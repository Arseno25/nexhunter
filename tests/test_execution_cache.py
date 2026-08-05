"""Result caching on the single execution path."""

import os
import sys
import time
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.core import tools as T
from nexhunter.execution.cache import ResultCache
from nexhunter.execution.service import ExecutionService


def _service(tmp: Path, cache: ResultCache) -> ExecutionService:
    os.environ["NEXHUNTER_DATA_DIR"] = str(tmp)
    return ExecutionService(cache=cache)


def _register(name: str, argv, cacheable: bool = True) -> None:
    T.TOOLS[name] = T.ToolSpec(
        name=name,
        binary=sys.executable,
        description="test-only",
        params={"target": None},
        timeout=30,
        risk_level="passive",
        cacheable=cacheable,
        builder=lambda p: [sys.executable, "-c", argv],
    )


# ---------------------------------------------------------------- unit: cache

def test_cache_lru_eviction():
    """The least-recently-used entry is dropped once over capacity."""
    print("[TEST] LRU eviction...")
    cache = ResultCache(max_entries=2, ttl_seconds=0)
    cache.put("a", {"v": 1}, "e1")
    cache.put("b", {"v": 2}, "e2")
    cache.get("a")                 # touch a -> b is now least-recent
    cache.put("c", {"v": 3}, "e3")  # evicts b

    assert cache.get("b") is None
    assert cache.get("a") is not None
    assert cache.get("c") is not None
    assert cache.evictions == 1
    print("  [OK] LRU evicts the least-recently-used entry")


def test_cache_ttl_expiry():
    """An entry past its TTL is a miss and is counted as an expiration."""
    print("[TEST] TTL expiry...")
    cache = ResultCache(max_entries=8, ttl_seconds=0.05)
    cache.put("k", {"v": 1}, "e1")
    assert cache.get("k") is not None
    time.sleep(0.08)
    assert cache.get("k") is None
    assert cache.expirations == 1
    print("  [OK] Expired entry is dropped")


def test_cache_disabled_stores_nothing():
    """A disabled cache is inert."""
    print("[TEST] Disabled cache...")
    cache = ResultCache(enabled=False)
    cache.put("k", {"v": 1}, "e1")
    assert cache.get("k") is None
    assert cache.stats()["entries"] == 0
    print("  [OK] Disabled cache never stores")


def test_cache_key_ignores_param_order():
    """Key depends on values, not dict order."""
    print("[TEST] Key stability...")
    k1 = ResultCache.key_for("t", {"a": 1, "b": 2})
    k2 = ResultCache.key_for("t", {"b": 2, "a": 1})
    assert k1 == k2
    assert ResultCache.key_for("t", {"a": 1}) != ResultCache.key_for("t", {"a": 2})
    print("  [OK] Key is order-independent and value-sensitive")


# ------------------------------------------------------- integration: service

def test_hit_returns_cached_without_new_record(tmp: Path):
    """A repeat call is served from cache and mints no second record."""
    print("[TEST] Cache hit reuses the original execution...")
    cache = ResultCache(max_entries=8, ttl_seconds=0)
    service = _service(tmp, cache)
    _register("echo_cache", "print('hello')")
    try:
        first = service.execute("echo_cache", {"target": "example.com"})
        second = service.execute("echo_cache", {"target": "example.com"})

        assert first["cached"] is False
        assert second["cached"] is True
        assert second["execution_id"] == first["execution_id"], "hit reuses the original id"
        assert len(service.registry) == 1, "a hit must not create a new record"
        assert cache.hits == 1 and cache.misses == 1
    finally:
        T.TOOLS.pop("echo_cache", None)
    print("  [OK] Hit served from cache, no new record")


def test_no_cache_bypasses(tmp: Path):
    """no_cache forces a fresh run and a new record."""
    print("[TEST] no_cache bypass...")
    cache = ResultCache(max_entries=8, ttl_seconds=0)
    service = _service(tmp, cache)
    _register("echo_nocache", "print('hi')")
    try:
        service.execute("echo_nocache", {"target": "a"})
        again = service.execute("echo_nocache", {"target": "a"}, no_cache=True)

        assert again["cached"] is False
        assert len(service.registry) == 2, "bypass runs a second time"
    finally:
        T.TOOLS.pop("echo_nocache", None)
    print("  [OK] no_cache runs fresh")


def test_non_cacheable_tool_never_cached(tmp: Path):
    """A cacheable=False tool is run every time."""
    print("[TEST] Non-cacheable tool...")
    cache = ResultCache(max_entries=8, ttl_seconds=0)
    service = _service(tmp, cache)
    _register("live_capture", "print('live')", cacheable=False)
    try:
        one = service.execute("live_capture", {"target": "a"})
        two = service.execute("live_capture", {"target": "a"})

        assert one["cached"] is False and two["cached"] is False
        assert len(service.registry) == 2
        assert cache.hits == 0 and cache.stats()["entries"] == 0
    finally:
        T.TOOLS.pop("live_capture", None)
    print("  [OK] Live tool bypasses the cache")


def test_failed_run_is_cached(tmp: Path):
    """A deterministic non-zero exit is a cacheable terminal result."""
    print("[TEST] Failed run cached...")
    cache = ResultCache(max_entries=8, ttl_seconds=0)
    service = _service(tmp, cache)
    _register("echo_fail", "import sys; sys.exit(3)")
    try:
        first = service.execute("echo_fail", {"target": "a"})
        second = service.execute("echo_fail", {"target": "a"})

        assert first["status"] == "failed"
        assert second["cached"] is True
        assert len(service.registry) == 1
    finally:
        T.TOOLS.pop("echo_fail", None)
    print("  [OK] Failed run served from cache on repeat")


if __name__ == "__main__":
    print("\n=== Execution Cache Tests ===\n")
    previous = os.environ.get("NEXHUNTER_DATA_DIR")
    try:
        test_cache_lru_eviction()
        test_cache_ttl_expiry()
        test_cache_disabled_stores_nothing()
        test_cache_key_ignores_param_order()
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            test_hit_returns_cached_without_new_record(tmp)
            test_no_cache_bypasses(tmp)
            test_non_cacheable_tool_never_cached(tmp)
            test_failed_run_is_cached(tmp)
    finally:
        if previous is None:
            os.environ.pop("NEXHUNTER_DATA_DIR", None)
        else:
            os.environ["NEXHUNTER_DATA_DIR"] = previous
    print("\n=== All Execution Cache Tests Passed ===\n")
