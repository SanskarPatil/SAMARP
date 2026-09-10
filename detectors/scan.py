"""Passive reconnaissance detection from bounded source-window metadata."""
from __future__ import annotations
from typing import Any, Mapping
from .common import DetectionOutcome, make_alert, thresholds, unavailable
def detect(window: Mapping[str, Any]) -> DetectionOutcome:
    required = ("src_ip", "destination_ports", "destinations")
    missing = tuple(name for name in required if window.get(name) is None)
    if missing: return unavailable(window.get("input_mode", "pcap_replay"), *missing)
    config, ports, destinations = thresholds()["scan"], set(window["destination_ports"]), set(window["destinations"])
    if not (len(ports) >= config["unique_port_min"] or len(destinations) >= config["unique_dst_min"]): return DetectionOutcome(None, "OBSERVABLE")
    return make_alert(detector="scan", threat_class="Passive port scanning / reconnaissance", observed_time=window.get("observed_time"), input_mode=window.get("input_mode", "pcap_replay"), flow_ref_type="entity", dedup_components={"src_ip": window["src_ip"]}, score=float(max(len(ports), len(destinations))), evidence={"interpretation": "Destination and/or port fan-out exceeds the passive reconnaissance threshold.", "unique_destination_ports": len(ports), "unique_destinations": len(destinations), "connection_attempts": int(window.get("connection_attempts", 0)), "window_s": config["window_s"]}, threshold={"unique_port_min": config["unique_port_min"], "unique_dst_min": config["unique_dst_min"], "window_s": config["window_s"]})
