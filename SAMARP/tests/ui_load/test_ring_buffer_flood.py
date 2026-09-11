"""Synthetic 50,000-alert burst load test for P3 client ring buffer survivability.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md section 15.4, implementation_plan.md P3-4.

Requirements:
- 50,000-alert burst stresses the ingestion / ring buffer path.
- Client ring buffer stays strictly bounded at 500 items.
- Memory remains bounded; processing must complete rapidly.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

MAX_RING_BUFFER_SIZE = 500


def simulate_client_ring_buffer(
    incoming_batch: list[dict[str, Any]],
    current_buffer: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Mirrors the mergeIncidents algorithm in dashboard/src/hooks/useIncidents.ts."""
    current = current_buffer or []
    item_map: dict[str, dict[str, Any]] = {inc["incident_id"]: inc for inc in current}

    for inc in incoming_batch:
        item_map[inc["incident_id"]] = inc

    sorted_list = sorted(
        item_map.values(),
        key=lambda x: x.get("last_observed") or x.get("timestamp") or "",
        reverse=True,
    )
    return sorted_list[:MAX_RING_BUFFER_SIZE]


def test_50000_alert_burst_bounded_ring_buffer():
    """Verify that a 50,000-alert synthetic burst maintains bounded ring size and executes fast."""
    num_alerts = 50_000
    batch_size = 1_000

    buffer: list[dict[str, Any]] = []

    t0 = time.perf_counter()

    for i in range(0, num_alerts, batch_size):
        batch = [
            {
                "schema_version": "1.3",
                "timestamp": f"2026-09-11T00:00:{idx:06d}+00:00",
                "flow_id": f"{idx % 1000:016x}",
                "flow_ref_type": "aggregate",
                "ps_class": "Volumetric DDoS / flooding",
                "threat_class": "syn_flood",
                "detector": "ddos",
                "confidence": None,
                "score": 10.0 + (idx % 10),
                "score_type": "robust_z",
                "calibrated": False,
                "evidence": {"packet_rate": 10000 + idx},
                "incident_id": f"inc{idx:013d}",
                "status": "ACTIVE",
                "severity": "CRITICAL",
                "last_observed": f"2026-09-11T00:00:{idx:06d}+00:00",
                "capability": {"detector_state": "OBSERVABLE", "input_mode": "pcap_replay"},
            }
            for idx in range(i, i + batch_size)
        ]
        buffer = simulate_client_ring_buffer(batch, buffer)
        # Ring buffer must never exceed 500 items
        assert len(buffer) <= MAX_RING_BUFFER_SIZE

    elapsed = time.perf_counter() - t0

    # Strict bounds checks
    assert len(buffer) == MAX_RING_BUFFER_SIZE
    assert elapsed < 3.0, f"50,000 alert processing took too long: {elapsed:.2f}s"
