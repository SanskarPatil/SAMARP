"""Shared P2 detector output helpers; no persistence or transport logic."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Mapping

import yaml

PS_CLASSES = {"ddos": "Volumetric DDoS / flooding", "reflection": "Volumetric DDoS / flooding", "scan": "Port scanning / reconnaissance", "c2": "Botnet C2 beaconing", "dga": "DGA / DNS tunnelling", "dns": "DGA / DNS tunnelling", "tls_quic": "Malware in encrypted sessions", "exfil": "Data exfiltration"}

def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)

def stable_id(value: object) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()[:16]

@lru_cache(maxsize=1)
def thresholds() -> dict[str, Any]:
    with (Path(__file__).resolve().parents[1] / "config" / "thresholds.yaml").open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)

@dataclass(frozen=True)
class DetectionOutcome:
    alert: dict[str, Any] | None
    capability_state: str
    missing_evidence: tuple[str, ...] = ()

def unavailable(input_mode: str, *missing: str) -> DetectionOutcome:
    return DetectionOutcome(None, "NOT_OBSERVABLE", tuple(missing))

def _timestamp(value: str | None) -> str:
    return value or datetime.now().astimezone().isoformat()

def make_alert(*, detector: str, threat_class: str, observed_time: str | None, input_mode: str, dedup_components: Mapping[str, object], evidence: Mapping[str, Any], flow_ref_type: str, score: float, score_type: str = "rule_score", confidence: float | None = None, calibrated: bool = False, severity: str = "HIGH", capability_state: str = "OBSERVABLE", missing_evidence: tuple[str, ...] = (), baseline: Mapping[str, Any] | None = None, threshold: Mapping[str, Any] | None = None, model_version: str | None = None, intel_version: str = "0.1.0") -> DetectionOutcome:
    if detector not in PS_CLASSES:
        raise ValueError(f"unknown detector {detector}")
    dedup_key = canonical({"ps_class": PS_CLASSES[detector], **dict(dedup_components)})
    identity = stable_id(dedup_key)
    return DetectionOutcome({"schema_version": "1.3", "timestamp": _timestamp(observed_time), "flow_id": identity, "flow_ref_type": flow_ref_type, "ps_class": PS_CLASSES[detector], "threat_class": threat_class, "detector": detector, "confidence": confidence, "score": score, "score_type": score_type, "calibrated": calibrated, "evidence": dict(evidence), "baseline": dict(baseline) if baseline else None, "threshold": dict(threshold) if threshold else None, "incident_id": identity, "dedup_key": dedup_key, "status": "NEW", "severity": severity, "capability": {"detector_state": capability_state, "input_mode": input_mode, "missing_evidence": list(missing_evidence)}, "model_version": model_version, "intel_version": intel_version}, capability_state, missing_evidence)
