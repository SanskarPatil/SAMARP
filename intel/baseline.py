"""Deterministic baseline-snapshot generation owned by P2."""

from __future__ import annotations

from statistics import median
from typing import Iterable, Mapping

from features.stateless import median_absolute_deviation


def generate_baseline_snapshot(events: Iterable[Mapping[str, float]]) -> dict[str, object]:
    events = list(events)
    metrics: dict[str, dict[str, float]] = {}
    for metric in ("packets_per_second", "outbound_byte_ratio", "unique_destination_ports"):
        values = [float(event[metric]) for event in events if metric in event]
        metrics[metric] = {"median": float(median(values)) if values else 0.0, "mad": median_absolute_deviation(values)}
    return {"version": "0.1.0", "generated_from": "deterministic-synthetic-benign-corpus", "adaptive_updates": False, "metrics": metrics}
