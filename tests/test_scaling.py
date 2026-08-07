"""Adaptive parallel-worker scaling (core/scaling.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nexhunter.core import config as C
from nexhunter.core import scaling


def test_single_job_runs_inline():
    assert scaling.adaptive_worker_count(0) == 1
    assert scaling.adaptive_worker_count(1) == 1


def test_fallback_holds_baseline_without_load(monkeypatch):
    """No load signal (psutil absent/unusable) => baseline, clamped to jobs."""
    monkeypatch.setattr(scaling, "_load", lambda: None)
    assert scaling.adaptive_worker_count(10) == C.MAX_PARALLEL_WORKERS
    assert scaling.adaptive_worker_count(3) == 3  # clamped to job count


def test_idle_host_scales_up_to_ceiling(monkeypatch):
    monkeypatch.setattr(scaling, "_load", lambda: (5.0, 20.0))
    assert scaling.adaptive_worker_count(1000) == C.PARALLEL_WORKERS_CEILING


def test_busy_cpu_scales_down_to_min(monkeypatch):
    monkeypatch.setattr(scaling, "_load", lambda: (C.WORKER_CPU_HI + 1, 10.0))
    assert scaling.adaptive_worker_count(1000) == C.MIN_PARALLEL_WORKERS


def test_busy_memory_scales_down_to_min(monkeypatch):
    monkeypatch.setattr(scaling, "_load", lambda: (10.0, C.WORKER_MEM_HI + 1))
    assert scaling.adaptive_worker_count(1000) == C.MIN_PARALLEL_WORKERS


def test_middling_load_holds_baseline(monkeypatch):
    mid_cpu = (C.WORKER_CPU_LO + C.WORKER_CPU_HI) / 2
    monkeypatch.setattr(scaling, "_load", lambda: (mid_cpu, 60.0))
    assert scaling.adaptive_worker_count(1000) == C.MAX_PARALLEL_WORKERS


def test_result_never_exceeds_job_count(monkeypatch):
    monkeypatch.setattr(scaling, "_load", lambda: (5.0, 5.0))  # idle -> ceiling
    assert scaling.adaptive_worker_count(2) == 2
