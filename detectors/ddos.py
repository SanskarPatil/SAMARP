"""Passive flood and low-rate Slowloris detection; no active probing."""

from __future__ import annotations
from typing import Any, Mapping
from features.stateless import robust_z_score, shannon_entropy
from .common import DetectionOutcome, make_alert, thresholds, unavailable

def detect(window: Mapping[str, Any]) -> DetectionOutcome:
    required = ("packets_per_second", "dst_ip", "dst_port", "sources", "syn_rate", "syn_ack_rate")
    missing = tuple(name for name in required if window.get(name) is None)
    if missing: return unavailable(window.get("input_mode", "pcap_replay"), *missing)
    config, pps = thresholds()["ddos"], float(window["packets_per_second"])
    z_score = robust_z_score(pps, window.get("baseline_pps", ()))
    syn_ack_ratio = float(window["syn_rate"]) / max(float(window["syn_ack_rate"]), 1.0)
    sources = list(window["sources"])
    if not (pps >= config["min_pps"] and (z_score >= config["robust_z"] or not window.get("baseline_pps")) and syn_ack_ratio >= 3.0): return DetectionOutcome(None, "OBSERVABLE")
    return make_alert(detector="ddos", threat_class="SYN flood", observed_time=window.get("observed_time"), input_mode=window.get("input_mode", "pcap_replay"), flow_ref_type="aggregate", dedup_components={"dst_ip": window["dst_ip"], "dst_port": window["dst_port"]}, score=z_score, score_type="robust_z", threshold={"min_pps": config["min_pps"], "robust_z": config["robust_z"], "syn_ack_ratio_min": 3.0}, baseline={"packets_per_second": list(window.get("baseline_pps", ()))}, evidence={"interpretation": "SYN rate and packet rate exceed configured flood gates.", "packets_per_second": pps, "byte_rate": float(window.get("bytes_per_second", 0.0)), "syn_rate": float(window["syn_rate"]), "syn_ack_rate": float(window["syn_ack_rate"]), "syn_ack_ratio": syn_ack_ratio, "unique_source_count": len(set(sources)), "source_entropy": shannon_entropy(sources), "robust_z": z_score})

def detect_slowloris(window: Mapping[str, Any]) -> DetectionOutcome:
    required = ("dst_ip", "dst_port", "half_open_concurrency", "connection_duration_p95", "bytes_per_connection", "packets_per_second")
    missing = tuple(name for name in required if window.get(name) is None)
    if missing: return unavailable(window.get("input_mode", "pcap_replay"), *missing)
    concurrent, duration = int(window["half_open_concurrency"]), float(window["connection_duration_p95"])
    low_rate = float(window["packets_per_second"]) <= float(window.get("slowloris_low_pps_max", 20.0))
    if not (concurrent >= int(window.get("slowloris_concurrency_min", 20)) and duration >= float(window.get("slowloris_duration_min_s", 60.0)) and low_rate): return DetectionOutcome(None, "OBSERVABLE")
    return make_alert(detector="ddos", threat_class="Slowloris low-rate connection exhaustion", observed_time=window.get("observed_time"), input_mode=window.get("input_mode", "pcap_replay"), flow_ref_type="aggregate", dedup_components={"dst_ip": window["dst_ip"], "dst_port": window["dst_port"]}, score=float(concurrent), evidence={"interpretation": "Concurrent long-lived half-open connections meet duration and low-rate gates.", "half_open_concurrency": concurrent, "connection_duration_p95": duration, "bytes_per_connection": float(window["bytes_per_connection"]), "packets_per_second": float(window["packets_per_second"]), "destination_service": str(window["dst_port"])}, threshold={"concurrency_min": int(window.get("slowloris_concurrency_min", 20)), "duration_min_s": float(window.get("slowloris_duration_min_s", 60.0)), "low_pps_max": float(window.get("slowloris_low_pps_max", 20.0))})
