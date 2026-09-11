"""Alert Scorer and Severity Evaluation Engine.

Source: FINAL_DEVELOPMENT_PLAN_V6.3.md sections 6.3, 17, design.md sections 9.4, 14.
Schema: schemas/alert.schema.json (v1.3).

Responsibilities:
1. Normalizes and validates detector scores against frozen score_type semantics:
   - robust_z: NEVER a probability; calibrated MUST be False.
   - rule_score: NEVER a probability; calibrated MUST be False.
   - anomaly_score: NEVER a probability; calibrated MUST be False.
   - model_probability: Only type where calibrated may be True.
2. Evaluates and maps scores to discrete severity levels:
   INFO, LOW, MEDIUM, HIGH, CRITICAL.
3. Implements monotonic severity escalation (CRITICAL > HIGH > MEDIUM > LOW > INFO).
4. Aggregates scores across repeated observations during deduplication.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

SEVERITY_LEVELS: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

VALID_SCORE_TYPES = {"robust_z", "anomaly_score", "model_probability", "rule_score"}
VALID_SEVERITIES = set(SEVERITY_LEVELS.keys())


def evaluate_severity(score: float | None, score_type: str = "anomaly_score") -> str:
    """Evaluate severity level based on score magnitude and score_type.

    Returns one of: INFO, LOW, MEDIUM, HIGH, CRITICAL.
    """
    if score is None:
        return "MEDIUM"

    if score_type == "robust_z":
        # Robust z-score thresholds (median/MAD units)
        if score >= 12.0:
            return "CRITICAL"
        if score >= 8.0:
            return "HIGH"
        if score >= 5.0:
            return "MEDIUM"
        if score >= 3.0:
            return "LOW"
        return "INFO"

    # Normalized scores in [0.0, 1.0] (anomaly_score, rule_score, model_probability)
    if score >= 0.90:
        return "CRITICAL"
    if score >= 0.75:
        return "HIGH"
    if score >= 0.50:
        return "MEDIUM"
    if score >= 0.25:
        return "LOW"
    return "INFO"


def escalate_severity(current_severity: str, new_severity: str) -> str:
    """Return the higher severity level between current and incoming."""
    curr_rank = SEVERITY_LEVELS.get(current_severity, 0)
    new_rank = SEVERITY_LEVELS.get(new_severity, 0)
    return new_severity if new_rank > curr_rank else current_severity


def aggregate_scores(
    existing_score: float | None,
    new_score: float | None,
    score_type: str = "anomaly_score",
) -> float | None:
    """Aggregate existing and incoming scores, preserving peak risk."""
    if existing_score is None:
        return new_score
    if new_score is None:
        return existing_score
    return max(existing_score, new_score)


class AlertScorer:
    """Evaluates, standardizes, and validates detector scores and severity."""

    def score_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Validate and score an incoming alert according to frozen contract rules."""
        scored = deepcopy(alert)

        score_val = scored.get("score")
        score_type = scored.get("score_type", "anomaly_score")

        if score_type not in VALID_SCORE_TYPES:
            score_type = "anomaly_score"
            scored["score_type"] = score_type

        # Contract Rule: robust_z and rule_score are NEVER probabilities.
        # Only model_probability may be calibrated.
        if score_type in ("robust_z", "rule_score", "anomaly_score"):
            scored["calibrated"] = False

        # Validate confidence field semantics
        confidence = scored.get("confidence")
        if confidence is not None:
            if not isinstance(confidence, (int, float)) or not (0.0 <= confidence <= 1.0):
                scored["confidence"] = None

        # Severity evaluation: use explicit severity if provided and valid, otherwise evaluate
        current_sev = scored.get("severity")
        if not current_sev or current_sev not in VALID_SEVERITIES:
            scored["severity"] = evaluate_severity(score_val, score_type)

        return scored
