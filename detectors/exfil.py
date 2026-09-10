"""Passive behavioural exfiltration detection; it never infers data content."""
from __future__ import annotations
from typing import Any, Mapping
from features.stateless import robust_z_score
from .common import DetectionOutcome, make_alert, thresholds, unavailable
def detect(window: Mapping[str, Any]) -> DetectionOutcome:
    required = ("src_ip", "dst_ip", "outbound_bytes", "inbound_bytes", "duration_s")
    missing = tuple(name for name in required if window.get(name) is None)
    if missing: return unavailable(window.get("input_mode", "pcap_replay"), *missing)
    config = thresholds()["exfil"]
    outbound, inbound = float(window["outbound_bytes"]), float(window["inbound_bytes"])
    ratio = outbound / max(inbound, 1.0)
    z_score = robust_z_score(outbound, window.get("baseline_outbound_bytes", ()))
    if not (ratio >= config["outbound_ratio_min"] and (z_score >= config["robust_z"] or not window.get("baseline_outbound_bytes"))): return DetectionOutcome(None, "OBSERVABLE")
    return make_alert(detector="exfil", threat_class="Suspicious outbound data transfer", observed_time=window.get("observed_time"), input_mode=window.get("input_mode", "pcap_replay"), flow_ref_type="entity", dedup_components={"src_ip": window["src_ip"], "dst_ip": window["dst_ip"]}, score=z_score, score_type="robust_z", evidence={"interpretation": "Outbound byte volume is unusually asymmetric and sustained; the system does not infer data content.", "outbound_bytes": outbound, "inbound_bytes": inbound, "outbound_byte_ratio": ratio, "duration_s": float(window["duration_s"]), "bytes_per_packet": float(window.get("bytes_per_packet", 0.0)), "destination_concentration": float(window.get("destination_concentration", 0.0)), "robust_z": z_score}, baseline={"outbound_bytes": list(window.get("baseline_outbound_bytes", ()))}, threshold=dict(config))
