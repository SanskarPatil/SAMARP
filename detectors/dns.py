"""Rule-based passive DNS tunnelling detector with visible qtype evidence."""
from __future__ import annotations
from typing import Any, Mapping
from features.extractor import dns_window_features, domain_features
from .common import DetectionOutcome, make_alert, thresholds, unavailable
def detect(window: Mapping[str, Any]) -> DetectionOutcome:
    events = list(window.get("events") or [])
    if not events: return unavailable(window.get("input_mode", "pcap_replay"), "dns_names")
    if not window.get("src_ip"): return unavailable(window.get("input_mode", "pcap_replay"), "src_ip")
    config, dns_features = thresholds()["dns_tunnel"], dns_window_features(events)
    lexical = [domain_features((event.get("dns") or {}).get("qname")) for event in events]
    max_length, max_entropy = max(item["length"] for item in lexical), max(item["entropy"] for item in lexical)
    qps = float(window.get("queries_per_second", len(events)))
    encoded = sum(bool(set(((event.get("dns") or {}).get("qname") or "").lower()) & set("0123456789-_")) for event in events)
    if not (max_length >= config["qname_len_min"] and max_entropy >= config["entropy_min"] and qps >= config["qps_per_domain_min"]): return DetectionOutcome(None, "OBSERVABLE")
    registered_domain = window.get("registered_domain")
    if not registered_domain: return unavailable(window.get("input_mode", "pcap_replay"), "registered_domain")
    return make_alert(detector="dns", threat_class="DNS tunnelling", observed_time=window.get("observed_time"), input_mode=window.get("input_mode", "pcap_replay"), flow_ref_type="entity", dedup_components={"src_ip": window["src_ip"], "registered_domain": registered_domain}, score=max_entropy, score_type="rule_score", evidence={"interpretation": "Long, high-entropy DNS labels recur at a high query rate; qtype shares are shown for review.", "query_length_max": max_length, "query_entropy_max": max_entropy, "encoded_name_count": encoded, "query_frequency": qps, "qtype_distribution": dns_features["qtype_distribution"], "qtype_entropy": dns_features["qtype_entropy"], "qtype_txt_ratio": dns_features["qtype_txt_ratio"], "qtype_null_ratio": dns_features["qtype_null_ratio"], "qtype_cname_ratio": dns_features["qtype_cname_ratio"], "response_seen": all((event.get("dns") or {}).get("response_seen") is True for event in events)}, threshold=dict(config))
