"""Encrypted-session metadata suspicion detector; payloads are never parsed."""
from __future__ import annotations
from typing import Any, Mapping
from features.extractor import shape_features
from .common import DetectionOutcome, make_alert, thresholds, unavailable
def detect(event: Mapping[str, Any]) -> DetectionOutcome:
    capability = event.get("capability") or {}
    if capability.get("tls_handshake") == "NOT_OBSERVABLE" and capability.get("quic_metadata") == "NOT_OBSERVABLE": return unavailable(event.get("input_mode", "pcap_replay"), "tls_or_quic_metadata")
    if not event.get("src_ip") or not event.get("dst_ip"): return unavailable(event.get("input_mode", "pcap_replay"), "flow_endpoints")
    tls, quic, shape = event.get("tls") or {}, event.get("quic") or {}, shape_features(event)
    ja3, ja3s, ja4 = tls.get("ja3") or quic.get("ja3"), tls.get("ja3s"), tls.get("ja4") or quic.get("ja4")
    novelty = bool(event.get("destination_novel", False))
    suspicious_fingerprint = bool(event.get("intel_match", False))
    unusual_shape = shape["iat_cv"] > float(event.get("shape_iat_cv_min", 1.5)) or shape["packet_size_p95"] > float(event.get("shape_packet_size_p95_min", 1200))
    if not ((novelty and unusual_shape) or suspicious_fingerprint): return DetectionOutcome(None, "DEGRADED" if not (ja3 and ja3s and ja4) else "OBSERVABLE")
    state = "OBSERVABLE" if ja3 and ja3s and ja4 else "DEGRADED"
    missing = tuple(name for name, value in (("ja3", ja3), ("ja3s", ja3s), ("ja4", ja4)) if not value)
    return make_alert(detector="tls_quic", threat_class="Suspicious encrypted session metadata", observed_time=event.get("observed_time"), input_mode=event.get("input_mode", "pcap_replay"), flow_ref_type="flow_5tuple", dedup_components={"src_ip": event["src_ip"], "ja3": ja3 or "NOT_OBSERVABLE", "dst_ip": event["dst_ip"]}, score=float(novelty) + float(unusual_shape) + float(suspicious_fingerprint), score_type="anomaly_score", capability_state=state, missing_evidence=missing, evidence={"interpretation": "Suspicious encrypted-session metadata and traffic shape; no payload was decrypted or identified.", "ja3": ja3, "ja3s": ja3s, "ja4": ja4, "destination_novelty": novelty, "packet_size_first_n": shape["packet_size_first_n"], "direction_first_n": shape["direction_first_n"], "iat_median": shape["iat_median"], "iat_p95": shape["iat_p95"], "iat_cv": shape["iat_cv"], "upstream_packet_ratio": shape["upstream_packet_ratio"], "downstream_packet_ratio": shape["downstream_packet_ratio"]}, threshold=dict(thresholds()["tls_quic"]))
