"""Passive C2 beacon detection using repeated timing and destination context."""
from __future__ import annotations
from typing import Any, Mapping
from features.stateless import coefficient_of_variation, median_absolute_deviation, quantile
from .common import DetectionOutcome, make_alert, thresholds, unavailable
def detect(window: Mapping[str, Any]) -> DetectionOutcome:
    required = ("src_ip", "dst_ip", "dst_port", "timestamps")
    missing = tuple(name for name in required if window.get(name) is None)
    if missing: return unavailable(window.get("input_mode", "pcap_replay"), *missing)
    config, times = thresholds()["c2"], sorted(float(value) for value in window["timestamps"])
    if len(times) < config["min_events"]: return unavailable(window.get("input_mode", "pcap_replay"), "repeated_flow_observations")
    intervals = [right - left for left, right in zip(times, times[1:])]
    cv, iat_median, iat_p95 = coefficient_of_variation(intervals), quantile(intervals, .5), quantile(intervals, .95)
    mad = median_absolute_deviation(intervals)
    if not (cv <= config["cv_max"] and iat_median > 0): return DetectionOutcome(None, "OBSERVABLE")
    return make_alert(detector="c2", threat_class="Periodic C2 beaconing", observed_time=window.get("observed_time"), input_mode=window.get("input_mode", "pcap_replay"), flow_ref_type="entity", dedup_components={"src_ip": window["src_ip"], "dst_ip": window["dst_ip"], "dst_port": window["dst_port"]}, score=max(0.0, 1.0 - cv), score_type="anomaly_score", evidence={"interpretation": "Repeated communication has low inter-arrival variation to one destination; this is behavioural suspicion, not payload attribution.", "event_count": len(times), "destination_consistency": 1.0, "iat_median": iat_median, "iat_p95": iat_p95, "iat_cv": cv, "iat_mad": mad, "destination_novelty": bool(window.get("destination_novel", False))}, threshold={"cv_max": config["cv_max"], "min_events": config["min_events"], "window_s": config["window_s"]})
