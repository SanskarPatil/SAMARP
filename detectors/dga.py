"""DGA detection using the one calibrated LightGBM model or explicit fallback."""
from __future__ import annotations
from pathlib import Path
from typing import Any, Mapping
from features.extractor import domain_features
from models.dga_model import CalibratedDGAModel
from .common import DetectionOutcome, make_alert, thresholds, unavailable

def _fallback_score(qname: str, nxdomain_rate: float) -> float:
    feature = domain_features(qname, nxdomain_rate=nxdomain_rate)
    return min(1.0, feature["entropy"] / 5.0 * .6 + min(feature["length"] / 30.0, 1.0) * .2 + nxdomain_rate * .2)

def detect(event: Mapping[str, Any], model: CalibratedDGAModel | None = None) -> DetectionOutcome:
    dns, capability = event.get("dns") or {}, event.get("capability") or {}
    qname = dns.get("qname")
    if capability.get("dns_names") == "NOT_OBSERVABLE" or not qname: return unavailable(event.get("input_mode", "pcap_replay"), "dns_names")
    if not event.get("src_ip"): return unavailable(event.get("input_mode", "pcap_replay"), "src_ip")
    query_count, nxdomain_rate = int(event.get("query_count", 1)), float(event.get("nxdomain_rate", float(bool(dns.get("nxdomain")))) )
    config = thresholds()["dga"]
    if query_count < config["min_queries"]: return DetectionOutcome(None, "OBSERVABLE")
    feature = domain_features(qname, nxdomain_rate=nxdomain_rate, language_model=model.language_model if model else None)
    if model:
        score, calibrated, version, score_type = model.predict_probability(qname, nxdomain_rate), True, model.version, "model_probability"
    else:
        score, calibrated, version, score_type = _fallback_score(qname, nxdomain_rate), False, "rules-fallback", "rule_score"
    if not (score >= config["score_threshold"] and nxdomain_rate >= config["nxdomain_rate_min"]): return DetectionOutcome(None, "OBSERVABLE")
    return make_alert(detector="dga", threat_class="DGA domain burst", observed_time=event.get("observed_time"), input_mode=event.get("input_mode", "pcap_replay"), flow_ref_type="entity", dedup_components={"src_ip": event["src_ip"]}, score=score, score_type=score_type, confidence=score if calibrated else None, calibrated=calibrated, model_version=version, evidence={"interpretation": "DGA lexical features and observed NXDOMAIN context exceeded the configured threshold.", **feature, "query_count": query_count, "calibrated": calibrated, "model_version": version}, threshold=dict(config))
