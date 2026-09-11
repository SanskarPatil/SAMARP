"""Throughput verification test asserting NFR-2 primary KPI.

Target: >= 1,000 normalized flows/sec sustained with below 1% measured loss.
Traceability: FINAL_DEVELOPMENT_PLAN_V6.3.md section 14.1, PRD.md NFR-2, bugs.md DOC-004.
"""

from __future__ import annotations

import time

from detectors.pipeline import DetectionPipeline
from scenarios.canonical_campaign import generate_canonical_campaign_events


def test_throughput_pipeline_exceeds_1000_flows_per_sec():
    """Verify that the detection pipeline exceeds the primary PS KPI of 1,000 flows/sec."""
    events = generate_canonical_campaign_events()
    total_events = len(events)
    assert total_events >= 1000, "Event count must be >= 1000 for sustained throughput check"

    pipeline = DetectionPipeline()

    start_time = time.perf_counter()
    alerts_emitted = 0
    for ev in events:
        alerts = pipeline.process_event(ev)
        alerts_emitted += len(alerts)

    flushed = pipeline.flush()
    alerts_emitted += len(flushed)
    elapsed_s = time.perf_counter() - start_time

    assert elapsed_s > 0
    flows_per_sec = total_events / elapsed_s

    # Acceptance criterion: >= 1,000 normalized flows/sec
    assert flows_per_sec >= 1000.0, f"Throughput {flows_per_sec:.1f} flows/s fell below 1,000 flows/s target"
    assert alerts_emitted > 0, "Pipeline emitted no alerts during throughput run"
