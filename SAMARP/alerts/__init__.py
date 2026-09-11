"""Alerts package: deduplication, scoring, and lifecycle management."""

from __future__ import annotations

from alerts.deduplicator import Deduplicator, extract_dedup_key
from alerts.scorer import (
    AlertScorer,
    aggregate_scores,
    escalate_severity,
    evaluate_severity,
)

__all__ = [
    "Deduplicator",
    "AlertScorer",
    "extract_dedup_key",
    "evaluate_severity",
    "escalate_severity",
    "aggregate_scores",
]
