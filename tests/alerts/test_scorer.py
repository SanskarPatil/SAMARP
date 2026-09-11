"""Tests for Alert Scorer, severity evaluation, and calibration enforcement.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md section 17, design.md section 14.
"""

from __future__ import annotations

import pytest

from alerts.scorer import (
    AlertScorer,
    aggregate_scores,
    escalate_severity,
    evaluate_severity,
)


def test_severity_evaluation_robust_z() -> None:
    assert evaluate_severity(1.5, "robust_z") == "INFO"
    assert evaluate_severity(3.5, "robust_z") == "LOW"
    assert evaluate_severity(6.0, "robust_z") == "MEDIUM"
    assert evaluate_severity(9.5, "robust_z") == "HIGH"
    assert evaluate_severity(14.0, "robust_z") == "CRITICAL"


def test_severity_evaluation_normalized_score() -> None:
    assert evaluate_severity(0.10, "anomaly_score") == "INFO"
    assert evaluate_severity(0.35, "anomaly_score") == "LOW"
    assert evaluate_severity(0.60, "anomaly_score") == "MEDIUM"
    assert evaluate_severity(0.80, "anomaly_score") == "HIGH"
    assert evaluate_severity(0.95, "anomaly_score") == "CRITICAL"


def test_severity_escalation() -> None:
    assert escalate_severity("LOW", "HIGH") == "HIGH"
    assert escalate_severity("CRITICAL", "MEDIUM") == "CRITICAL"
    assert escalate_severity("INFO", "LOW") == "LOW"
    assert escalate_severity("HIGH", "INFO") == "HIGH"


def test_aggregate_scores() -> None:
    assert aggregate_scores(0.6, 0.85, "anomaly_score") == 0.85
    assert aggregate_scores(10.0, 5.0, "robust_z") == 10.0
    assert aggregate_scores(None, 0.75, "anomaly_score") == 0.75
    assert aggregate_scores(0.5, None, "anomaly_score") == 0.5


def test_scorer_enforces_calibrated_false_for_non_model() -> None:
    scorer = AlertScorer()

    # robust_z claiming calibrated=True must be overridden to False
    alert_z = {
        "score": 6.5,
        "score_type": "robust_z",
        "calibrated": True,
        "confidence": 0.95,
    }
    scored_z = scorer.score_alert(alert_z)
    assert scored_z["calibrated"] is False

    # anomaly_score must have calibrated=False
    alert_ano = {
        "score": 0.8,
        "score_type": "anomaly_score",
        "calibrated": True,
    }
    scored_ano = scorer.score_alert(alert_ano)
    assert scored_ano["calibrated"] is False


def test_scorer_preserves_valid_confidence() -> None:
    scorer = AlertScorer()

    # Valid confidence in [0, 1]
    alert = {
        "score": 0.88,
        "score_type": "model_probability",
        "confidence": 0.88,
        "calibrated": True,
    }
    scored = scorer.score_alert(alert)
    assert scored["confidence"] == 0.88
    assert scored["severity"] == "HIGH"

    # Out of bounds confidence converted to None
    alert_bad = {
        "score": 0.88,
        "score_type": "model_probability",
        "confidence": 2.5,
    }
    scored_bad = scorer.score_alert(alert_bad)
    assert scored_bad["confidence"] is None
