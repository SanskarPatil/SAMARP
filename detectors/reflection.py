"""UDP reflection/amplification and spoofed-source flood evidence."""
from __future__ import annotations
from typing import Any, Mapping
from features.stateless import shannon_entropy
from .common import DetectionOutcome, make_alert, unavailable
AMPLIFIER_PORTS = {53, 123, 389, 1900, 11211}
def detect(window: Mapping[str, Any]) -> DetectionOutcome:
    required = ("dst_ip", "amplifier_port", "packets_per_second", "sources")
    missing = tuple(name for name in required if window.get(name) is None)
    if missing: return unavailable(window.get("input_mode", "pcap_replay"), *missing)
    port, sources, pps = int(window["amplifier_port"]), list(window["sources"]), float(window["packets_per_second"])
    fan_in = len(set(sources))
    if not (port in AMPLIFIER_PORTS and fan_in >= 10 and pps >= 5000): return DetectionOutcome(None, "OBSERVABLE")
    return make_alert(detector="reflection", threat_class="UDP reflection/amplification", observed_time=window.get("observed_time"), input_mode=window.get("input_mode", "pcap_replay"), flow_ref_type="aggregate", dedup_components={"dst_ip": window["dst_ip"], "amplifier_port": port}, score=float(fan_in), evidence={"interpretation": "High-rate UDP fan-in from an amplification service is observable; reserved-source share excludes declared lab prefixes.", "packets_per_second": pps, "amplifier_port": port, "fan_in": fan_in, "source_entropy": shannon_entropy(sources), "reserved_source_share": float(window.get("reserved_source_share_external", 0.0))}, threshold={"fan_in_min": 10, "min_pps": 5000, "amplifier_ports": sorted(AMPLIFIER_PORTS)})
