"""Adaptive parallelism: size a tool batch to current host load.

nexhunter fans independent tool steps out across a thread pool. A flat worker
cap wastes a large idle host and can overcommit a small busy one, so the batch
size adapts between ``MIN_PARALLEL_WORKERS`` and ``PARALLEL_WORKERS_CEILING``
based on CPU/memory load -- the same auto-scaling idea as HexStrike's process
pool, bounded to this machine.

Load is read via psutil when installed (optional ``perf`` extra). Without it
the count falls back to the static baseline ``MAX_PARALLEL_WORKERS``, so
behaviour is unchanged rather than guessed.
"""

from __future__ import annotations

from nexhunter.core import config

try:  # optional; presence enables load-aware scaling
    import psutil

    # Prime the CPU-percent delta so the first real read is meaningful rather
    # than the 0.0 psutil returns on its very first non-blocking call.
    psutil.cpu_percent(interval=None)
except Exception:  # pragma: no cover - psutil absent or unusable
    psutil = None  # type: ignore[assignment]


def load_available() -> bool:
    """True when host load can be sensed (psutil importable)."""
    return psutil is not None


def _load() -> tuple[float, float] | None:
    """Current (cpu%, mem%), or None when psutil is unavailable."""
    if psutil is None:
        return None
    try:
        return psutil.cpu_percent(interval=None), psutil.virtual_memory().percent
    except Exception:  # pragma: no cover - defensive
        return None


def adaptive_worker_count(job_count: int) -> int:
    """Workers to use for a batch of ``job_count`` independent jobs.

    A single job runs inline (1 worker). Otherwise the cap adapts to load: a
    busy host shrinks toward ``MIN_PARALLEL_WORKERS``, an idle one grows toward
    ``PARALLEL_WORKERS_CEILING``, and an unknown load (no psutil) holds the
    baseline ``MAX_PARALLEL_WORKERS``. The result is always clamped to the job
    count, so a 2-job batch never spins up more than 2 workers.
    """
    if job_count <= 1:
        return 1

    lo = max(1, config.MIN_PARALLEL_WORKERS)
    base = config.MAX_PARALLEL_WORKERS
    hi = max(lo, config.PARALLEL_WORKERS_CEILING)

    load = _load()
    if load is None:
        target = base
    else:
        cpu, mem = load
        if cpu >= config.WORKER_CPU_HI or mem >= config.WORKER_MEM_HI:
            target = lo
        elif cpu < config.WORKER_CPU_LO and mem < config.WORKER_MEM_HI:
            target = hi
        else:
            target = base

    target = max(lo, min(target, hi))
    return max(1, min(job_count, target))
