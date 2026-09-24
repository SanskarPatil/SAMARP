"""Confidence assignment for every emitted alert (PS constraint e).

PS26145 requires a *confidence score* on every alert.  Detectors produce raw
scores of different kinds (``robust_z`` is unbounded, ``anomaly_score`` and
``rule_score`` are already in [0, 1], ``model_probability`` is a model output).
This module turns each raw score into a confidence in [0, 1] and records HOW
that number was obtained in ``calibrated_on``:

  "platt_dga"        - Platt-calibrated LightGBM DGA probability (models/dga_model.py)
  "synthetic_replay" - per-detector logistic calibration fitted on the labelled
                       synthetic replay (config/confidence_calibration.json,
                       produced by scripts/calibrate_confidence.py)
  "uncalibrated"     - documented monotone mapping of the raw score; bounded,
                       comparable within one detector, NOT a probability

``calibrated`` is True only for the first two.  The UI shows a percent sign
only when ``calibrated`` is True.  The raw ``score`` is never modified.
"""

from __future__ import annotations

import json
import math
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

CALIBRATED_ON_VALUES = ("synthetic_replay", "platt_dga", "uncalibrated")
CALIBRATION_FILE = Path(__file__).resolve().parents[1] / "config" / "confidence_calibration.json"

# Reference z used to scale robust_z scores: the detector's own alerting
# threshold from config/thresholds.yaml (a z exactly at threshold maps to
# 1 - e^-1 = 0.632 in the uncalibrated mapping).
_DEFAULT_Z_REF = 5.0


def _z_reference(detector: str) -> float:
    try:
        from detectors.common import thresholds

        section = thresholds().get(detector) or {}
        value = float(section.get("robust_z", _DEFAULT_Z_REF))
        return value if value > 0 else _DEFAULT_Z_REF
    except Exception:  # pragma: no cover - thresholds file missing
        return _DEFAULT_Z_REF


def normalized_score(detector: str, score: float | None, score_type: str) -> float:
    """Map a raw score onto a non-negative evidence scale (x >= 0)."""
    if score is None or not math.isfinite(float(score)):
        return 0.0
    value = float(score)
    if score_type == "robust_z":
        return max(0.0, value) / _z_reference(detector)
    return min(1.0, max(0.0, value))


def _uncalibrated(x: float, score_type: str) -> float:
    if score_type == "robust_z":
        return 1.0 - math.exp(-x)          # saturating, 0.632 at the alert threshold
    return min(1.0, max(0.0, x))


@lru_cache(maxsize=1)
def calibration_table(path: str | None = None) -> dict[str, dict[str, float]]:
    """Per-detector logistic parameters {"a": .., "b": ..}; empty when not fitted yet."""
    source = Path(path) if path else CALIBRATION_FILE
    if not source.exists():
        return {}
    data = json.loads(source.read_text(encoding="utf-8"))
    return {name: {"a": float(p["a"]), "b": float(p["b"])} for name, p in (data.get("detectors") or {}).items()}


def confidence_for(detector: str, score: float | None, score_type: str, table: Mapping[str, Mapping[str, float]] | None = None) -> tuple[float, str]:
    """Return (confidence in [0,1], calibrated_on)."""
    if score_type == "model_probability" and score is not None:
        return round(min(1.0, max(0.0, float(score))), 4), "platt_dga"
    x = normalized_score(detector, score, score_type)
    params = (table if table is not None else calibration_table()).get(detector)
    if params:
        logit = max(min(params["a"] * x + params["b"], 60.0), -60.0)
        return round(1.0 / (1.0 + math.exp(-logit)), 4), "synthetic_replay"
    return round(_uncalibrated(x, score_type), 4), "uncalibrated"


def apply_confidence(alert: dict[str, Any], table: Mapping[str, Mapping[str, float]] | None = None) -> dict[str, Any]:
    """Fill ``confidence``, ``calibrated_on`` and ``calibrated`` in place; returns the alert."""
    confidence, calibrated_on = confidence_for(str(alert.get("detector")), alert.get("score"), str(alert.get("score_type", "anomaly_score")), table)
    alert["confidence"] = confidence
    alert["calibrated_on"] = calibrated_on
    alert["calibrated"] = calibrated_on != "uncalibrated"
    return alert
