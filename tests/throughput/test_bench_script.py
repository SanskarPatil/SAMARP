"""Smoke test for scripts/bench_throughput.py (1 s step; not a KPI measurement)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from scenarios.canonical_campaign import generate_canonical_campaign_events

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "bench_throughput.py"


def _load():
    spec = importlib.util.spec_from_file_location("bench_throughput", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_bench_step_reports_every_required_metric():
    bench = _load()
    step = bench.run_step(rate=500, duration_s=1.0, capacity=10_000, db_mode="memory", base_events=generate_canonical_campaign_events())
    for key in ("sustained_processed_eps", "worst_1s_processed_eps", "dropped_events", "dropped_pct", "cpu_pct_of_one_core",
                "peak_rss_mb_process", "event_to_alert_latency_ms", "event_to_processed_latency_ms", "backlog_at_end_events"):
        assert key in step
    assert step["offered_events"] > 0
    assert step["processed_events"] + step["dropped_events"] == step["offered_events"]
    assert step["event_to_processed_latency_ms"]["p50"] is not None


def test_overflow_is_dropped_not_back_pressured():
    bench = _load()
    step = bench.run_step(rate=5_000, duration_s=1.0, capacity=100, db_mode="memory", base_events=generate_canonical_campaign_events())
    assert step["processed_events"] + step["dropped_events"] == step["offered_events"]
